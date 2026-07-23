#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Security)
import Security
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

extension VNCProtocol {
    /// Coordinator for Apple Remote Desktop authentication type 33 (RSA-SRP) — HP-SPECS §5.2,
    /// dossier §3.2. Owns the multi-roundtrip wire exchange over a `NetworkConnection`:
    ///
    ///   RSA1 init → recv server SPKI → build + send `c2s1` → recv `s2c1` challenge
    ///   → solve SRP (`AppleSRPClient`) → build + send `c2s2` → recv `M2` + `SecurityResult`
    ///   → **verify `M2` first** (HP-SPECS §5.2 step 4) → require `SecurityResult == 0`.
    ///
    /// It is a thin I/O adapter: all SRP math (`AppleSRPClient`) and envelope framing
    /// (`AppleRSA1Envelope`) live in the pure, unit-tested 5b seams. The one crypto operation the
    /// coordinator owns itself is the RSA-PKCS#1 v1.5 encryption of the identity block (the seams take
    /// a pre-encrypted 256-byte block), done with the vendored CryptoSwift `RSA` — no new dependency
    /// (NFR-4). Production randomness (`a`, `client_random`) is `SecRandomCopyBytes`; injectable for
    /// determinism (NFR-3, A3).
    ///
    /// Security (NFR-6): never logs `password`, `P'`, `x`, `S`, `K`, `M1`, `M2`, or any wrap/content
    /// key. The `M2`-verification-failure *event* is logged with no proof bytes.
    ///
    /// WIRE FRAMING — ORACLE-GATED. The byte layout of every server message read and client message
    /// written here is confirmed byte-for-byte at the live O-checkpoints O3–O6 (HP-SPECS §8) against
    /// the reference `auth.py -v` tap; it is NOT offline-verifiable and is implemented to the dossier's
    /// stated layout. Each such point is marked `ORACLE(On)` inline. Do not treat these reads/writes
    /// as pinned until the live checkpoint passes.
    struct ARDRSASRPAuthentication {
        /// Result of a successful exchange: the 16-byte record-layer wrap key (`SHA-256(K)[0:16]`).
        /// Never logged.
        struct Success {
            let wrapKey: Data
        }

        /// Injectable randomness (NFR-3). Defaults to `SecRandomCopyBytes` in production (A3).
        let randomBytes: (Int) throws -> Data

        init(randomBytes: @escaping (Int) throws -> Data = ARDRSASRPAuthentication.secureRandomBytes) {
            self.randomBytes = randomBytes
        }

        /// Run the full type-33 exchange. `0x21` (security-type select) has already been sent by the
        /// caller (`sendAuthenticationData`); this begins at the RSA1 init body.
        func authenticate(connection: any NetworkConnection,
                          credential: VNCUsernamePasswordCredential,
                          logger: VNCLogger) async throws -> Success {
            // Step 0 — RSA1 init (c→s). u32 length(10, big-endian) || 10-byte RSA1 init body.
            // ORACLE(O3): the u32 length prefix around the init body.
            var initMessage = Self.bigEndian32(UInt32(AppleRSA1Envelope.rsa1Init().count))
            initMessage.append(AppleRSA1Envelope.rsa1Init())
            try await connection.write(data: initMessage)

            // Step 0 — recv server public key: u32 len || u16 || u32 keyLen || DER SubjectPublicKeyInfo.
            // ORACLE(O3): what `len`/`u16` count and whether the DER length is exactly `keyLen`.
            _ = try await connection.readUInt32()               // len (bytes following) — unused
            _ = try await connection.readUInt16()               // reserved / type — unused
            let keyLength = try await connection.readUInt32()
            let spki = try await connection.readBuffered(length: Int(keyLength))

            let publicKey = try AppleRSA1Envelope.parseSPKI(spki)

            // Step 1 — c2s1 (650B). identity is RSA-PKCS#1 v1.5-encrypted under the server key.
            // ORACLE(O3): empty username in the identity blob (dossier §3.2 — empty-username identity).
            let identity = AppleRSA1Envelope.identity(username: "")
            let rsaEncrypted = try Self.rsaEncryptPKCS1(identity,
                                                        modulus: publicKey.n,
                                                        exponent: publicKey.e)
            let c2s1 = try AppleRSA1Envelope.c2s1(rsaEncrypted: rsaEncrypted)
            // ORACLE(O3): whether c2s1 is sent bare (as here) or with its own length prefix.
            try await connection.write(data: c2s1)

            // Step 2 — recv s2c1 challenge.
            // ORACLE(O4/O5/R9): the s2c1 framing (leading total length; g width; the u64 `iterations`
            // endianness — assumed big-endian per RFB convention; the trailing `options` extent).
            let challenge = try await Self.readChallenge(connection: connection)

            // Step 3 — solve SRP. `a` is a fresh ≥256-bit private exponent (A3).
            let a = try randomBytes(32)
            let srp = try AppleSRPClient.derive(password: Data(credential.password.utf8),
                                                salt: challenge.salt,
                                                iterations: challenge.iterations,
                                                N: challenge.N,
                                                g: challenge.g,
                                                B: challenge.B,
                                                a: a)

            let clientRandom = try randomBytes(16)
            // ORACLE(O5): the `opts` echoed in c2s2 (here: the server's s2c1 options verbatim).
            let c2s2 = try AppleRSA1Envelope.c2s2(A: srp.A,
                                                  M1: srp.M1,
                                                  opts: challenge.options,
                                                  clientRandom: clientRandom)
            try await connection.write(data: c2s2)

            // Step 4 — recv M2 + SecurityResult. Verify M2 FIRST (server-impersonation guard, §13.2).
            // ORACLE(O6): the exact bytes between M2[64] and the u32 SecurityResult.
            let serverM2 = try await connection.readBuffered(length: 64)

            guard AppleSRPClient.verifyM2(serverM2, A: srp.A, M1: srp.M1, K: srp.K) else {
                // NFR-6: log the event only — never the proof/key bytes.
                logger.logError("M2 verification failed")

                throw VNCError.authentication(.ardAuthenticationFailed)
            }

            let securityResult = try await connection.readUInt32()

            guard securityResult == 0 else {
                throw VNCError.authentication(.ardAuthenticationFailed)
            }

            return Success(wrapKey: AppleSRPClient.wrapKey(K: srp.K))
        }
    }
}

// MARK: - Challenge parsing (s2c1)
private extension VNCProtocol.ARDRSASRPAuthentication {
    /// The parsed s2c1 challenge. All SRP field byte-orders are taken verbatim from the dossier /
    /// reference and confirmed at O4/O5 — not independently re-derived (NFR-2).
    struct Challenge {
        let N: Data          // 4096-bit MODP modulus (512 bytes)
        let g: Data          // generator (Apple: 5)
        let salt: Data       // 32 bytes
        let B: Data          // server public value (512 bytes)
        let iterations: Int  // PBKDF2 iteration count — READ from wire (never hardcoded)
        let options: Data    // capability string, echoed in c2s2
    }

    /// Read + slice the s2c1 challenge.
    ///
    /// ORACLE(O4/O5): the whole layout below is the dossier's stated field order behind an assumed
    /// leading total-length prefix (the only self-consistent way to bound the trailing variable-length
    /// `options`). `iterations` is read big-endian (R9). Confirmed byte-for-byte at the live checkpoint.
    static func readChallenge(connection: any NetworkConnection) async throws -> Challenge {
        let totalLength = try await connection.readUInt32()

        guard totalLength >= 512 + 1 + 32 + 512 + 8 else {
            throw VNCError.protocol(.invalidData)
        }

        let body = try await connection.readBuffered(length: Int(totalLength))
        let bytes = Array(body)

        var offset = 0
        func take(_ count: Int) throws -> Data {
            guard offset + count <= bytes.count else {
                throw VNCError.protocol(.invalidData)
            }
            let slice = Data(bytes[offset..<(offset + count)])
            offset += count
            return slice
        }

        let N = try take(512)
        let g = try take(1)          // ORACLE(O4): generator wire width (assumed 1 byte = 0x05)
        let salt = try take(32)
        let B = try take(512)
        let iterationsData = try take(8)

        // iterations: u64 big-endian (R9). Fits in Int on 64-bit; guard against a pathological value.
        var iterations: UInt64 = 0
        for byte in iterationsData {
            iterations = (iterations << 8) | UInt64(byte)
        }
        guard iterations > 0, iterations <= UInt64(Int.max) else {
            throw VNCError.protocol(.invalidData)
        }

        let options = Data(bytes[offset..<bytes.count])   // remainder

        return Challenge(N: N,
                         g: g,
                         salt: salt,
                         B: B,
                         iterations: Int(iterations),
                         options: options)
    }
}

// MARK: - RSA-PKCS#1 v1.5 encryption (coordinator-owned)
private extension VNCProtocol.ARDRSASRPAuthentication {
    /// RSA-PKCS#1 v1.5-encrypt `plaintext` under the server public key `(modulus, exponent)`, producing
    /// exactly a 256-byte block (RSA-2048, dossier §3.2 step 1). Uses the vendored CryptoSwift `RSA`
    /// (default `.pksc1v15`, secure random padding) — no new dependency (NFR-4).
    ///
    /// ORACLE(O3): assumes a 2048-bit server key (256-byte block). The output is left-zero-padded to
    /// 256 bytes defensively (a well-formed 2048-bit modulus already yields 256).
    static func rsaEncryptPKCS1(_ plaintext: Data,
                                modulus: Data,
                                exponent: Data) throws -> Data {
        let rsa = RSA(n: Array(modulus), e: Array(exponent))

        let encrypted: [UInt8]
        do {
            encrypted = try rsa.encrypt(Array(plaintext), variant: .pksc1v15)
        } catch {
            throw VNCError.authentication(.ardAuthenticationFailed)
        }

        var block = Data(encrypted)
        guard block.count <= 256 else {
            throw VNCError.authentication(.ardAuthenticationFailed)
        }
        if block.count < 256 {
            block = Data(repeating: 0, count: 256 - block.count) + block
        }

        return block
    }
}

// MARK: - Randomness
extension VNCProtocol.ARDRSASRPAuthentication {
    /// Cryptographically-secure random bytes (A3). `SecRandomCopyBytes` on Apple platforms, matching
    /// the type-30 path (`ARDAuthenticationImpl.swift`); a system-RNG fallback elsewhere.
    static func secureRandomBytes(_ count: Int) throws -> Data {
        guard count > 0 else { return Data() }

#if canImport(Security)
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { pointer -> Int32 in
            guard let baseAddress = pointer.baseAddress else { return errSecParam }

            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }

        guard status == errSecSuccess else {
            throw VNCError.authentication(.ardAuthenticationFailed)
        }

        return bytes
#else
        return Data((0..<count).map { _ in UInt8.random(in: 0...255) })
#endif
    }
}

// MARK: - Big-endian helper
private extension VNCProtocol.ARDRSASRPAuthentication {
    static func bigEndian32(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ])
    }
}
