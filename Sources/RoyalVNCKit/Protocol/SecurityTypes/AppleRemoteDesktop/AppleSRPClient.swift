#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

/// Pure (Foundation-only, no socket) SRP-6a math for Apple Remote Desktop auth type 33.
///
/// Implements the non-standard Apple SRP-6a variant exactly as documented in
/// `docs/HP-STREAMING-DOSSIER.md` §3.2 (SHA-512 throughout, empty-username identity,
/// PBKDF2-pre-hashed password, `PAD()` = left-zero-pad to 512 bytes). Byte-orderings are taken
/// verbatim from the dossier / reference `auth.py` and are NOT independently re-derived (NFR-2);
/// they are oracle-verified downstream at O4a/O4b/O6 (HP-SPECS §8).
///
/// The 4096-bit modular exponentiation for `A` and `S` uses the vendored CryptoSwift
/// `BigUInteger` — the exact big-integer type `Encryption/BigNum.swift` already wraps. No new
/// third-party dependency is introduced (NFR-4). `BigNum` itself is not reused here because it
/// exposes only `modExp`/`rand`, not the modular subtract/multiply/add that `S` requires.
///
/// Security (NFR-6 / `sensitive-data`): this type never logs `password`, `P'`, `x`, `S`, `K`,
/// `M1`, `M2`, or any wrap/content key. All randomness (`a`) is injected by the caller so the
/// type is deterministic for tests (NFR-3).
enum AppleSRPClient {
    /// Width, in bytes, that `PAD()` left-zero-pads big integers to (4096-bit MODP group = 512B).
    static let padWidth = 512

    /// Left-zero-pad `data` to `width` bytes. Values are never wider than `width` for a 4096-bit
    /// group (a residue mod N is < N ≤ 2^4096), so this only ever prepends zero bytes.
    static func pad(_ data: Data, to width: Int = padWidth) -> Data {
        guard data.count < width else { return data }

        return Data(repeating: 0, count: width - data.count) + data
    }

    // MARK: - Digests

    private static func sha512(_ data: Data) -> Data {
        Data(SHA2(variant: .sha512).calculate(for: Array(data)))
    }

    private static func sha256(_ data: Data) -> Data {
        Data(SHA2(variant: .sha256).calculate(for: Array(data)))
    }

    // MARK: - Derivation

    /// Run the full SRP-6a client derivation.
    ///
    /// - Parameters:
    ///   - password: The user password bytes (UTF-8). Never logged.
    ///   - salt: Server salt `s` (32 bytes on the wire).
    ///   - iterations: PBKDF2 iteration count. READ from the wire — never hardcoded (see the
    ///     non-hardcode unit test which drives two distinct values through the same code).
    ///   - N: The group modulus `N` (RFC5054 4096-bit MODP, 512 bytes big-endian).
    ///   - g: The generator `g` (Apple uses `5`).
    ///   - B: The server public value `B` (512 bytes big-endian).
    ///   - a: The client private exponent `a`, injected for determinism (>= 256 bits in production).
    /// - Returns: `A` (client public value, PAD-ed to 512B — the value hashed and, per the dossier,
    ///   sent on the wire), `M1` (client proof, 64B), `K` (session key, 64B), `S` (shared secret,
    ///   minimal big-endian), `x` (private key, 64B) and `u` (scrambling parameter, 64B). `S`/`x`/`u`
    ///   are surfaced for O4a self-consistency assertions only.
    static func derive(password: Data,
                       salt: Data,
                       iterations: Int,
                       N: Data,
                       g: Data,
                       B: Data,
                       a: Data) throws -> (A: Data, M1: Data, K: Data, S: Data, x: Data, u: Data) {
        // P' = PBKDF2-HMAC-SHA512(password, salt, iterations, dkLen=128)
        let pPrime: [UInt8]
        do {
            pPrime = try PKCS5.PBKDF2(password: Array(password),
                                      salt: Array(salt),
                                      iterations: iterations,
                                      keyLength: 128,
                                      variant: .sha2(.sha512)).calculate()
        } catch {
            throw VNCError.authentication(.ardAuthenticationFailed)
        }

        // x = SHA512(salt || SHA512(0x3a || P'))  — ':' separator, empty username.
        let xInner = sha512(Data([0x3a]) + Data(pPrime))
        let xData = sha512(salt + xInner)

        // k = SHA512(N || PAD(g))
        let kData = sha512(N + pad(g))

        // Big-integer domain.
        let nBig = BigUInteger(N)
        let gBig = BigUInteger(g)
        let aBig = BigUInteger(a)
        let xBig = BigUInteger(xData)
        let kBig = BigUInteger(kData)
        let bBig = BigUInteger(B)

        // A = g^a mod N  (PAD-ed to 512B for hashing and the wire).
        let aPub = gBig.power(aBig, modulus: nBig)
        let aData = pad(aPub.serialize())

        // u = SHA512(PAD(A) || PAD(B))
        let uData = sha512(aData + pad(B))
        let uBig = BigUInteger(uData)

        // S = (B - k * g^x)^(a + u * x) mod N
        let gx = gBig.power(xBig, modulus: nBig)      // g^x mod N
        let kgx = (kBig * gx) % nBig                   // (k * g^x) mod N
        // (B - k*g^x) mod N — (B − k·g^x) can be negative in the field, so adding N before the
        // modular reduction keeps the unsigned BigUInteger representation valid.
        let base = (bBig + nBig - kgx) % nBig
        let exponent = aBig + (uBig * xBig)
        let sBig = base.power(exponent, modulus: nBig)
        let sData = sBig.serialize()

        // K = SHA512(PAD(S))
        let kSession = sha512(pad(sData))

        // M1 = SHA512((SHA512(N) XOR SHA512(PAD(g))) || SHA512('') || salt || PAD(A) || PAD(B) || K)
        let hN = sha512(N)
        let hg = sha512(pad(g))
        let xorNg = Data(zip(hN, hg).map { $0 ^ $1 })
        let hEmpty = sha512(Data())
        var m1Input = Data()
        m1Input.append(xorNg)
        m1Input.append(hEmpty)
        m1Input.append(salt)
        m1Input.append(aData)
        m1Input.append(pad(B))
        m1Input.append(kSession)
        let m1 = sha512(m1Input)

        return (A: aData, M1: m1, K: kSession, S: sData, x: xData, u: uData)
    }

    // MARK: - Server proof (M2)

    /// The expected server proof `M2 = SHA512(PAD(A) || M1 || K)` (dossier §3.2 step 4 / §13.2).
    static func computeM2(A: Data, M1: Data, K: Data) -> Data {
        sha512(pad(A) + M1 + K)
    }

    /// Verify the server proof `M2` in constant time (no early-exit `==`).
    ///
    /// A production client MUST verify `M2` (the reference `auth.py` skips it) to resist server
    /// impersonation (dossier §13.2). Returns `true` only on an exact match.
    static func verifyM2(_ received: Data, A: Data, M1: Data, K: Data) -> Bool {
        let expected = computeM2(A: A, M1: M1, K: K)

        return constantTimeEquals(received, expected)
    }

    /// Constant-time byte-equality. The length pre-check is not secret (both proofs are 64B).
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }

        let a = Array(lhs)
        let b = Array(rhs)
        var diff: UInt8 = 0

        for i in 0..<a.count {
            diff |= a[i] ^ b[i]
        }

        return diff == 0
    }

    // MARK: - Wrap key

    /// `wrap_key = SHA-256(K)[0:16]` — seeds the AES-128-CBC record layer (dossier §3.2, `auth.py:356`).
    static func wrapKey(K: Data) -> Data {
        Data(sha256(K).prefix(16))
    }
}
