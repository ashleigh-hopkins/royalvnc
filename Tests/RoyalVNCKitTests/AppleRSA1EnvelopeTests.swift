import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleRSA1Envelope` — RSA1 init, SPKI parsing, identity, and the c2s1/c2s2
/// envelope framing (HP-SPECS §7).
final class AppleRSA1EnvelopeTests: XCTestCase {
    // MARK: - RSA1 init

    func testRSA1InitBytes() {
        let blob = AppleRSA1Envelope.rsa1Init()

        XCTAssertEqual(blob.count, 10, "RSA1 init body is 10 bytes")
        XCTAssertEqual(Hex.string(blob), "0100" + "52534131" + "00000000",
                       "01 00 || 'RSA1' || 00 00 00 00")
    }

    // MARK: - Identity

    func testIdentityEmptyUsername() {
        let identity = AppleRSA1Envelope.identity(username: "")

        // u32 payload_len(=7) || u32 username_len(=0) || u16 0 || u8 0
        XCTAssertEqual(identity.count, 11)
        XCTAssertEqual(Hex.string(identity), "00000007" + "00000000" + "0000" + "00")
    }

    func testIdentityWithUsername() {
        let identity = AppleRSA1Envelope.identity(username: "bob")

        // payload_len = 4 + 3 + 2 + 1 = 10 ; username_len = 3 ; username = "bob" (62 6f 62)
        XCTAssertEqual(identity.count, 14)
        XCTAssertEqual(Hex.string(identity), "0000000a" + "00000003" + "626f62" + "0000" + "00")
    }

    // MARK: - c2s1 (650-byte envelope)

    func testC2S1FramingAndOffsets() throws {
        let rsaBlock = Data((0..<256).map { UInt8($0 & 0xFF) })
        let envelope = try AppleRSA1Envelope.c2s1(rsaEncrypted: rsaBlock)

        XCTAssertEqual(envelope.count, 650, "c2s1 is exactly 650 bytes")
        let bytes = Array(envelope)
        XCTAssertEqual(Array(bytes[0..<2]), [0x01, 0x00], "version 01 00")
        XCTAssertEqual(Array(bytes[2..<6]), [0x52, 0x53, 0x41, 0x31], "'RSA1'")
        XCTAssertEqual(Array(bytes[6..<8]), [0x00, 0x02], "authtype 00 02")
        XCTAssertEqual(Array(bytes[8..<10]), [0x01, 0x00], "inner_len 01 00 = 256")
        XCTAssertEqual(Data(bytes[10..<266]), rsaBlock, "256-byte RSA block at offset 0x00A")
        XCTAssertEqual(Array(bytes[266..<650]), Array(repeating: 0, count: 384), "384 trailing zero bytes")
    }

    func testC2S1RejectsWrongLength() {
        XCTAssertThrowsError(try AppleRSA1Envelope.c2s1(rsaEncrypted: Data(repeating: 0, count: 255)))
        XCTAssertThrowsError(try AppleRSA1Envelope.c2s1(rsaEncrypted: Data(repeating: 0, count: 257)))
    }

    // MARK: - c2s2 (1076-byte envelope)

    func testC2S2FramingAndOffsets() throws {
        let a = Data(repeating: 0xA1, count: 512)
        let m1 = Data(repeating: 0xB2, count: 64)
        let opts = Data("SRP-6a,SHA-512,PBKDF2".utf8)
        let clientRandom = Data((0..<16).map { UInt8($0) })

        let envelope = try AppleRSA1Envelope.c2s2(A: a, M1: m1, opts: opts, clientRandom: clientRandom)

        XCTAssertEqual(envelope.count, 1076, "c2s2 is framed to 1076 bytes")
        let bytes = Array(envelope)

        // u16 A_len
        XCTAssertEqual(Array(bytes[0..<2]), [0x02, 0x00], "A_len = 512 big-endian")
        XCTAssertEqual(Data(bytes[2..<514]), a, "A at offset 2")

        var offset = 514
        XCTAssertEqual(bytes[offset], 0x40, "u8 64 marker before M1"); offset += 1
        XCTAssertEqual(Data(bytes[offset..<(offset + 64)]), m1, "M1[64]"); offset += 64

        let optsLen = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        XCTAssertEqual(optsLen, opts.count, "opts_len big-endian"); offset += 2
        XCTAssertEqual(Data(bytes[offset..<(offset + opts.count)]), opts, "opts payload"); offset += opts.count

        XCTAssertEqual(bytes[offset], 0x10, "u8 16 marker before client_random"); offset += 1
        XCTAssertEqual(Data(bytes[offset..<(offset + 16)]), clientRandom, "client_random[16]"); offset += 16

        // Remainder is zero padding to 1076.
        XCTAssertEqual(Array(bytes[offset..<1076]), Array(repeating: 0, count: 1076 - offset),
                       "trailing zero pad to 1076")
    }

    func testC2S2RejectsBadInputs() {
        let a = Data(repeating: 0xA1, count: 512)
        let m1 = Data(repeating: 0xB2, count: 64)
        let clientRandom = Data(repeating: 0xC3, count: 16)

        // Wrong M1 length.
        XCTAssertThrowsError(try AppleRSA1Envelope.c2s2(A: a, M1: Data(repeating: 0, count: 63),
                                                        opts: Data(), clientRandom: clientRandom))
        // Wrong client_random length.
        XCTAssertThrowsError(try AppleRSA1Envelope.c2s2(A: a, M1: m1, opts: Data(),
                                                        clientRandom: Data(repeating: 0, count: 15)))
        // Fields overflow 1076.
        XCTAssertThrowsError(try AppleRSA1Envelope.c2s2(A: a, M1: m1,
                                                        opts: Data(repeating: 0, count: 600),
                                                        clientRandom: clientRandom))
    }

    // MARK: - parseSPKI

    /// A minimal but structurally-valid DER SubjectPublicKeyInfo, hand-built so `(n, e)` are known:
    /// n magnitude = 0xC711, e = 0x010001 (65537).
    private let validSPKI = "301e" +                               // SEQUENCE (30 bytes)
        "300d" + "06092a864886f70d010101" + "0500" +               //   AlgorithmIdentifier: OID rsaEncryption + NULL
        "030d" + "00" +                                            //   BIT STRING (13 bytes), 0 unused bits
        "300a" + "020300c711" + "0203010001"                       //     RSAPublicKey SEQUENCE { INTEGER n, INTEGER e }

    func testParseSPKIExtractsModulusAndExponent() throws {
        let (n, e) = try AppleRSA1Envelope.parseSPKI(Hex.data(validSPKI))

        XCTAssertEqual(Hex.string(n), "c711", "modulus magnitude with the DER sign byte stripped")
        XCTAssertEqual(Hex.string(e), "010001", "public exponent 65537")
    }

    func testParseSPKIRejectsTruncatedData() {
        let full = Hex.data(validSPKI)
        let truncated = full.prefix(full.count - 4)
        XCTAssertThrowsError(try AppleRSA1Envelope.parseSPKI(Data(truncated)))
    }

    func testParseSPKIRejectsWrongOuterTag() {
        var bytes = Array(Hex.data(validSPKI))
        bytes[0] = 0x31 // SET instead of SEQUENCE
        XCTAssertThrowsError(try AppleRSA1Envelope.parseSPKI(Data(bytes)))
    }

    func testParseSPKIRejectsNonRSAOID() {
        // Flip a byte inside the algorithm OID so it is no longer rsaEncryption.
        let corrupted = validSPKI.replacingOccurrences(of: "06092a864886f70d010101",
                                                       with: "06092a864886f70d010102")
        XCTAssertThrowsError(try AppleRSA1Envelope.parseSPKI(Hex.data(corrupted)))
    }

    // MARK: - DER long-form length overflow guard (F1)

    func testParseSPKIRejectsDERLengthOverflow() {
        // DER long-form length with 8 bytes of 0xFF → UInt64.max, which overflows Int.
        // Structure: SEQUENCE tag (0x30), long-form length indicator (0x88 = 8 length bytes),
        // followed by eight 0xFF bytes (length = UInt64.max). This should be rejected.
        let overflowDER = Hex.data("3088" + "ffffffffffffffff")
        XCTAssertThrowsError(try AppleRSA1Envelope.parseSPKI(overflowDER),
                           "DER with an overflowing long-form length must be rejected")
    }

    // MARK: - Degenerate key rejection (MINOR-2)

    func testParseSPKIRejectsDegenerateKeys() {
        // A structurally-valid SPKI but with a 1-byte modulus (degenerate).
        // AlgorithmIdentifier + BIT STRING → RSAPublicKey with n=0x01, e=0x03.
        let degenerateN = "301b" +                                     // SEQUENCE (27 bytes)
            "300d" + "06092a864886f70d010101" + "0500" +               //   AlgorithmIdentifier
            "030a" + "00" +                                            //   BIT STRING (10 bytes), 0 unused
            "3007" + "020101" + "020103"                               //     RSAPublicKey: n=0x01, e=0x03

        XCTAssertThrowsError(try AppleRSA1Envelope.parseSPKI(Hex.data(degenerateN)),
                           "SPKI with a degenerate 1-byte modulus must be rejected")

        // Empty exponent: an INTEGER encoding 0x00 which stripLeadingZeros will make empty.
        // n is 0x0102 (2 bytes, valid), e is 0x00 (becomes empty after strip, invalid).
        let emptyE = "301c" +                                          // SEQUENCE (28 bytes)
            "300d" + "06092a864886f70d010101" + "0500" +               //   AlgorithmIdentifier
            "030b" + "00" +                                            //   BIT STRING (11 bytes)
            "3008" + "02030102" + "020100"                             //     RSAPublicKey: n=0x0102, e=0x00

        XCTAssertThrowsError(try AppleRSA1Envelope.parseSPKI(Hex.data(emptyE)),
                           "SPKI with an empty exponent (after strip) must be rejected")
    }
}
