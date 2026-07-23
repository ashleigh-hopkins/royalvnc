import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleSRPClient` — the pure SRP-6a math for Apple auth type 33 (HP-SPECS §7).
///
/// Validation strategy (per the Q2 prerequisite result): the reference `auth.py` does not expose
/// the client private `a`, so these tests do NOT assert equality against a reference-`a`-derived
/// dump. Instead they use:
///   1. Known-answer vectors from an INDEPENDENT re-implementation of the documented dossier §3.2
///      formula (Python `hashlib`/`pow`), embedded below — this cross-checks the CryptoSwift
///      implementation against a second implementation of the same spec.
///   2. O4a self-consistency (field widths, determinism, S != 0).
///   3. The iterations-non-hardcode property (two distinct iteration counts flow through the same
///      code and produce distinct proofs, each matching its own oracle vector).
///
/// The fixed inputs are a deterministic consistency oracle, NOT the live Apple group / credentials.
/// A SMALL 256-bit modulus and light PBKDF2 counts are used purely so the pure-Swift modular
/// exponentiation and key derivation are fast in the debug test build; `PAD()` still pads to the
/// full 512-byte width (a formula constant), so `A` is exercised at its real 512-byte wire size.
/// Byte-for-byte agreement with the live Apple 4096-bit group / credentials and the real iteration
/// count is gated downstream at O4b/O5/O6 (HP-SPECS §8).
final class AppleSRPClientTests: XCTestCase {
    // MARK: - Fixed oracle inputs (see scratchpad srp_oracle3.py)

    private let nHex = "edbca290a9eab7061f00bca0042db9232c61275c9e6b6cf8950e87d7f5606615"
    private let gHex = "05"
    private let saltHex = "304cc4f278686ca2bc54a5d4ee29fec3e96ca26feb4ead1958c61d5727d93f6d"
    private let password = "hunter2-correct-horse"
    private let aHex = "33176469aa6ef6308860a84722025e0511dc6f3fcb57d5d8"
    private let bHex = "2de288f12fcb9940da10faaa6fc24b837a2f11088d29b146607507ebc5b864d7"

    private func makeInputs() -> (password: Data, salt: Data, N: Data, g: Data, B: Data, a: Data) {
        (Data(password.utf8), Hex.data(saltHex), Hex.data(nHex), Hex.data(gHex), Hex.data(bHex), Hex.data(aHex))
    }

    // Expected outputs for iterations=211 (independent Python oracle). `A` is PAD-ed to 512 bytes.
    private let expected211 = (
        A: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bc0cf38a1f2b338bbc809e1a9e1b2aad27aa6007da41d51ec59b7dacf889a6f6",
        M1: "4e5191915a819b18b474d6cfb7a5e626bdc23f6f93e4e2b41fad4c609ac04379669f8eac42003903809a006b1b5bea89a464813190e37904965367b921d7f5bd",
        K: "354e550b6b728cd90d59154547207b420eb47a012be511a7b6b0bb83a2474ad82f0676a2cefc4cdd09a0d9356d5307b0f796176e23bf36626613d3122c5c9b37",
        x: "fd0a149fca1514c0261362c7b9f1f6aeeaced98d77a963eb753b7f83ce2896fa65a272f242bffcd344fe8688423deaee6bea247354bb8cb95d83ce693abbc093",
        u: "6549c0586fca3835a7c60ebb3540790fb0282b9924441929011d7d4a9762448cf2aae7dbc9ea9db415b5189e328fe10df9c040624a7caf8626119f2b9b8af698",
        M2: "01ed5757fb3d59632b05468e7078865990b50647874f1cfc959811e524967d5d962220dcd5e3c5b3d1a6ab579369296c22d11c52924dd31888d29f69150c231a",
        wrap: "63c2536f68e0808396749e9cbe74db99"
    )

    // MARK: - Known-answer cross-check against the independent oracle

    func testDeriveMatchesIndependentOracle() throws {
        let i = makeInputs()
        let result = try AppleSRPClient.derive(password: i.password, salt: i.salt, iterations: 211,
                                               N: i.N, g: i.g, B: i.B, a: i.a)

        XCTAssertEqual(Hex.string(result.A), expected211.A, "A (client public) must match the oracle")
        XCTAssertEqual(Hex.string(result.M1), expected211.M1, "M1 (client proof) must match the oracle")
        XCTAssertEqual(Hex.string(result.K), expected211.K, "K (session key) must match the oracle")
        XCTAssertEqual(Hex.string(result.x), expected211.x, "x (private key) must match the oracle")
        XCTAssertEqual(Hex.string(result.u), expected211.u, "u (scrambler) must match the oracle")

        let m2 = AppleSRPClient.computeM2(A: result.A, M1: result.M1, K: result.K)
        XCTAssertEqual(Hex.string(m2), expected211.M2, "M2 (server proof) must match the oracle")

        let wrap = AppleSRPClient.wrapKey(K: result.K)
        XCTAssertEqual(Hex.string(wrap), expected211.wrap, "wrap_key = SHA-256(K)[0:16] must match the oracle")
    }

    // MARK: - Iterations are not hardcoded (spec §7)

    func testIterationsNotHardcoded() throws {
        let i = makeInputs()
        let r211 = try AppleSRPClient.derive(password: i.password, salt: i.salt, iterations: 211,
                                             N: i.N, g: i.g, B: i.B, a: i.a)
        let r307 = try AppleSRPClient.derive(password: i.password, salt: i.salt, iterations: 307,
                                             N: i.N, g: i.g, B: i.B, a: i.a)

        // Both must independently match the oracle for their own iteration count -> the count is
        // genuinely consumed by PBKDF2, not replaced by a baked-in constant.
        XCTAssertEqual(Hex.string(r211.M1), expected211.M1)
        XCTAssertEqual(Hex.string(r307.M1), "2d5ed5edf22042e322c3da071f2a0408c98614aab982e8cc0b1e95e1d4b007923c23e76f67b978925ec20426cba16fe9c65bd2fb2959ca720c3c1d27ccae416f")
        XCTAssertEqual(Hex.string(AppleSRPClient.wrapKey(K: r307.K)), "89ea8a0a0151e3e321792cfcc81a663c")

        // Iteration-dependent values differ; iteration-independent values (A, u) stay equal.
        XCTAssertNotEqual(r211.M1, r307.M1, "M1 must change with the iteration count")
        XCTAssertNotEqual(r211.K, r307.K, "K must change with the iteration count")
        XCTAssertNotEqual(r211.x, r307.x, "x must change with the iteration count")
        XCTAssertNotEqual(r211.S, r307.S, "S must change with the iteration count")
        XCTAssertEqual(r211.A, r307.A, "A = g^a mod N is independent of the iteration count")
        XCTAssertEqual(r211.u, r307.u, "u = SHA512(PAD(A)||PAD(B)) is independent of the iteration count")
    }

    // MARK: - O4a self-consistency

    func testSelfConsistencyFieldWidthsAndDeterminism() throws {
        let i = makeInputs()
        let a = try AppleSRPClient.derive(password: i.password, salt: i.salt, iterations: 211,
                                          N: i.N, g: i.g, B: i.B, a: i.a)
        let b = try AppleSRPClient.derive(password: i.password, salt: i.salt, iterations: 211,
                                          N: i.N, g: i.g, B: i.B, a: i.a)

        // Deterministic given the same injected inputs (NFR-3).
        XCTAssertEqual(a.A, b.A)
        XCTAssertEqual(a.M1, b.M1)
        XCTAssertEqual(a.K, b.K)

        // PAD-ed / digest widths.
        XCTAssertEqual(a.A.count, 512, "A is PAD-ed to the 512-byte group width")
        XCTAssertEqual(a.M1.count, 64, "M1 is a SHA-512 digest")
        XCTAssertEqual(a.K.count, 64, "K is a SHA-512 digest")
        XCTAssertEqual(a.x.count, 64, "x is a SHA-512 digest")
        XCTAssertEqual(a.u.count, 64, "u is a SHA-512 digest")

        // S must be a non-zero shared secret.
        XCTAssertFalse(a.S.isEmpty, "S must not be empty")
        XCTAssertTrue(a.S.contains { $0 != 0 }, "S must be non-zero")
    }

    // MARK: - M2 verification (constant-time)

    func testVerifyM2AcceptsValidRejectsTampered() throws {
        let i = makeInputs()
        let r = try AppleSRPClient.derive(password: i.password, salt: i.salt, iterations: 211,
                                          N: i.N, g: i.g, B: i.B, a: i.a)

        let validM2 = AppleSRPClient.computeM2(A: r.A, M1: r.M1, K: r.K)
        XCTAssertTrue(AppleSRPClient.verifyM2(validM2, A: r.A, M1: r.M1, K: r.K),
                      "a correctly-constructed M2 must verify")

        // Flip one byte -> must be rejected.
        var tampered = validM2
        tampered[0] ^= 0x01
        XCTAssertFalse(AppleSRPClient.verifyM2(tampered, A: r.A, M1: r.M1, K: r.K),
                       "a tampered M2 must be rejected")

        // Wrong length -> rejected.
        XCTAssertFalse(AppleSRPClient.verifyM2(Data(validM2.dropLast()), A: r.A, M1: r.M1, K: r.K),
                       "a truncated M2 must be rejected")
    }

    func testConstantTimeEquals() {
        XCTAssertTrue(AppleSRPClient.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 3])))
        XCTAssertFalse(AppleSRPClient.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 4])))
        XCTAssertFalse(AppleSRPClient.constantTimeEquals(Data([1, 2, 3]), Data([1, 2])))
        XCTAssertTrue(AppleSRPClient.constantTimeEquals(Data(), Data()))
    }

    // MARK: - PAD

    func testPadLeftZeroPads() {
        let short = Data([0xAB, 0xCD])
        let padded = AppleSRPClient.pad(short, to: 8)
        XCTAssertEqual(Hex.string(padded), "000000000000abcd", "PAD left-zero-pads to the target width")

        let exact = Data(repeating: 0xFF, count: 8)
        XCTAssertEqual(AppleSRPClient.pad(exact, to: 8), exact, "PAD leaves already-wide data unchanged")
    }

    // MARK: - Full-width 4096-bit group test (MINOR-4)

    func testSRPWithRFC5054_4096BitGroup() throws {
        // RFC-5054 4096-bit MODP group 8192 (the real Apple HP group).
        let n4096Hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"
        let g4096Hex = "05"

        // Small iteration count and fixed injected 'a' for speed (this is a self-consistency test,
        // not a known-answer oracle — we're validating that 4096-bit modexp completes without overflow).
        let saltHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        let password = "test-password-4096"
        let aHex = "fedcba9876543210fedcba9876543210fedcba9876543210"
        let bHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        let iterations = 10  // Keep it fast for unit tests.

        let result = try AppleSRPClient.derive(password: Data(password.utf8),
                                               salt: Hex.data(saltHex),
                                               iterations: iterations,
                                               N: Hex.data(n4096Hex),
                                               g: Hex.data(g4096Hex),
                                               B: Hex.data(bHex),
                                               a: Hex.data(aHex))

        // O4a self-consistency: A must be 512 bytes (PAD-ed), derived values must be present.
        XCTAssertEqual(result.A.count, 512, "A must be PAD-ed to 512 bytes at 4096-bit width")
        XCTAssertEqual(result.M1.count, 64, "M1 must be SHA-512 (64 bytes)")
        XCTAssertEqual(result.K.count, 64, "K must be SHA-512 (64 bytes)")
        XCTAssertFalse(result.S.isEmpty, "S must not be empty")
        XCTAssertTrue(result.S.contains { $0 != 0 }, "S must be non-zero")

        // Recompute A from the same 'a' — must match (determinism).
        let result2 = try AppleSRPClient.derive(password: Data(password.utf8),
                                                salt: Hex.data(saltHex),
                                                iterations: iterations,
                                                N: Hex.data(n4096Hex),
                                                g: Hex.data(g4096Hex),
                                                B: Hex.data(bHex),
                                                a: Hex.data(aHex))
        XCTAssertEqual(result.A, result2.A, "A = g^a mod N must recompute consistently (4096-bit)")

        // Purpose: prove 4096-bit BigUInteger modexp path works without overflow/crash (de-risks R8).
    }
}
