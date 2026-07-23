import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleControlRecordCodec` — the AES-128-CBC control-record seal/open, filler
/// math, SHA-1 trailer, IV chaining and sequence accounting (HP-SPECS §7).
///
/// Seal KAT (see scratchpad): key `000102030405060708090a0b0c0d0e0f`, iv
/// `0f0e0d0c0b0a09080706050403020100`, seq 1, body "hello", filler `0102030405` →
/// ciphertext `f8abaec8dae06ad810dcded16bfb04aae2e41f69633806186354a2c752c0ab8c`.
final class AppleControlRecordCodecTests: XCTestCase {
    private let key = Hex.data("000102030405060708090a0b0c0d0e0f")
    private let iv0 = Hex.data("0f0e0d0c0b0a09080706050403020100")

    // MARK: - filler length (boundaries 0 / 14 / 15)

    func testFillerLenBoundaries() {
        // total = 2 + bodyLen + 20 ; filler = (16 - total % 16) % 16
        XCTAssertEqual(AppleControlRecordCodec.fillerLen(bodyLen: 10), 0, "total 32 → aligned, no filler")
        XCTAssertEqual(AppleControlRecordCodec.fillerLen(bodyLen: 12), 14, "total 34 → 14 filler")
        XCTAssertEqual(AppleControlRecordCodec.fillerLen(bodyLen: 11), 15, "total 33 → 15 filler")
        XCTAssertEqual(AppleControlRecordCodec.fillerLen(bodyLen: 5), 5, "total 27 → 5 filler")
        XCTAssertEqual(AppleControlRecordCodec.fillerLen(bodyLen: 0), 10, "total 22 → 10 filler")
    }

    // MARK: - SHA-1 trailer KAT

    func testTrailerKAT() {
        // SHA1( u32_be(7) || 00 03 'abc' AA BB )
        let pre = Hex.data("0003616263aabb")
        let trailer = AppleControlRecordCodec.trailer(seq: 7, plaintext: pre)

        XCTAssertEqual(Hex.string(trailer), "c965ee07189520845e72ebc373152af11233eec9")
        XCTAssertEqual(trailer.count, 20, "trailer is a 20-byte SHA-1 digest")
    }

    // MARK: - seal KAT

    func testSealKAT() throws {
        let body = Data("hello".utf8)
        let filler = Hex.data("0102030405")
        let (record, nextIV) = try AppleControlRecordCodec.seal(body: body, seq: 1, iv: iv0, key: key,
                                                                filler: filler)

        let expectedCiphertext = "f8abaec8dae06ad810dcded16bfb04aae2e41f69633806186354a2c752c0ab8c"
        XCTAssertEqual(Hex.string(record), "0020" + expectedCiphertext,
                       "u16 ciphertext_len(32) || ciphertext")
        XCTAssertEqual(Hex.string(nextIV), "e2e41f69633806186354a2c752c0ab8c",
                       "nextIV is the last ciphertext block")
    }

    // MARK: - roundtrip

    func testSealOpenRoundtrip() throws {
        let body = Data("SetDisplayConfiguration payload".utf8)
        let (record, sealNextIV) = try AppleControlRecordCodec.seal(body: body, seq: 0, iv: iv0, key: key)
        let (recovered, openNextIV) = try AppleControlRecordCodec.open(record: record, seq: 0, iv: iv0, key: key)

        XCTAssertEqual(recovered, body, "open recovers the sealed body")
        XCTAssertEqual(sealNextIV, openNextIV, "seal and open agree on the next chained IV")
    }

    func testEmptyBodyRoundtrip() throws {
        let (record, _) = try AppleControlRecordCodec.seal(body: Data(), seq: 0, iv: iv0, key: key)
        let (recovered, _) = try AppleControlRecordCodec.open(record: record, seq: 0, iv: iv0, key: key)

        XCTAssertEqual(recovered, Data(), "an empty body round-trips")
    }

    // MARK: - IV chaining across 3 records

    func testIVChainThreeRecords() throws {
        let bodies = [Data("SetDisplayConfiguration".utf8),
                      Data("SetEncodings".utf8),
                      Data("FramebufferUpdateRequest".utf8)]

        // Seal three records, threading each record's nextIV into the next seal (persistent CBC IV).
        var iv = iv0
        var records = [Data]()
        for (seq, body) in bodies.enumerated() {
            let (record, nextIV) = try AppleControlRecordCodec.seal(body: body, seq: UInt32(seq), iv: iv, key: key)
            records.append(record)
            iv = nextIV
        }

        // Open with the SAME chained IV progression; each body must be recovered.
        var openIV = iv0
        for (seq, record) in records.enumerated() {
            let (recovered, nextIV) = try AppleControlRecordCodec.open(record: record, seq: UInt32(seq),
                                                                       iv: openIV, key: key)
            XCTAssertEqual(recovered, bodies[seq], "record \(seq) body recovered under the chained IV")
            openIV = nextIV
        }

        // Opening record 1 with the INITIAL iv (i.e. not chaining) must fail its trailer check.
        XCTAssertThrowsError(try AppleControlRecordCodec.open(record: records[1], seq: 1, iv: iv0, key: key),
                             "using an unchained IV must break the record")
    }

    // MARK: - sequence accounting

    func testSequenceNumberFoldedIntoTrailer() throws {
        let body = Data("input".utf8)
        let (record0, _) = try AppleControlRecordCodec.seal(body: body, seq: 0, iv: iv0, key: key, filler: Data(repeating: 0, count: AppleControlRecordCodec.fillerLen(bodyLen: body.count)))
        let (record1, _) = try AppleControlRecordCodec.seal(body: body, seq: 1, iv: iv0, key: key, filler: Data(repeating: 0, count: AppleControlRecordCodec.fillerLen(bodyLen: body.count)))

        XCTAssertNotEqual(record0, record1, "identical inputs but different seq → different record (trailer)")

        // A record sealed at seq 0 must not verify when opened as seq 1.
        XCTAssertThrowsError(try AppleControlRecordCodec.open(record: record0, seq: 1, iv: iv0, key: key),
                             "a seq mismatch must fail the trailer check")
    }

    // MARK: - filler is not validated

    func testFillerValueNotValidatedOnOpen() throws {
        let body = Data("hello".utf8) // filler length 5
        let zeros = Data(repeating: 0x00, count: 5)
        let ones = Data(repeating: 0xFF, count: 5)

        let (recordZeros, _) = try AppleControlRecordCodec.seal(body: body, seq: 3, iv: iv0, key: key, filler: zeros)
        let (recordOnes, _) = try AppleControlRecordCodec.seal(body: body, seq: 3, iv: iv0, key: key, filler: ones)

        // Different filler → different ciphertext, but BOTH open to the same body (open must not
        // require any particular filler value — only the SHA-1 trailer is checked).
        XCTAssertNotEqual(recordZeros, recordOnes)
        let (bodyA, _) = try AppleControlRecordCodec.open(record: recordZeros, seq: 3, iv: iv0, key: key)
        let (bodyB, _) = try AppleControlRecordCodec.open(record: recordOnes, seq: 3, iv: iv0, key: key)
        XCTAssertEqual(bodyA, body)
        XCTAssertEqual(bodyB, body)
    }

    // MARK: - frame / integrity errors

    func testOpenRejectsBadCiphertextLengthFrame() {
        // ciphertext_len = 0.
        XCTAssertThrowsError(try AppleControlRecordCodec.open(record: Hex.data("0000"), seq: 0, iv: iv0, key: key))
        // ciphertext_len not a multiple of 16 (declared 8, 8 bytes follow).
        XCTAssertThrowsError(try AppleControlRecordCodec.open(record: Hex.data("0008") + Data(repeating: 0, count: 8),
                                                              seq: 0, iv: iv0, key: key))
        // declared length does not match the actual payload.
        XCTAssertThrowsError(try AppleControlRecordCodec.open(record: Hex.data("0020") + Data(repeating: 0, count: 16),
                                                              seq: 0, iv: iv0, key: key))
    }

    func testOpenRejectsTamperedCiphertext() throws {
        let body = Data("hello".utf8)
        let (record, _) = try AppleControlRecordCodec.seal(body: body, seq: 0, iv: iv0, key: key)

        var bytes = Array(record)
        bytes[bytes.count - 1] ^= 0x01 // flip a ciphertext byte
        XCTAssertThrowsError(try AppleControlRecordCodec.open(record: Data(bytes), seq: 0, iv: iv0, key: key),
                             "a tampered ciphertext must fail the SHA-1 trailer check")
    }

    // MARK: - seal input guards

    func testSealRejectsBadKeyIVAndFillerLengths() {
        let body = Data("hello".utf8)
        XCTAssertThrowsError(try AppleControlRecordCodec.seal(body: body, seq: 0, iv: iv0,
                                                              key: Data(repeating: 0, count: 15)))
        XCTAssertThrowsError(try AppleControlRecordCodec.seal(body: body, seq: 0,
                                                              iv: Data(repeating: 0, count: 15), key: key))
        XCTAssertThrowsError(try AppleControlRecordCodec.seal(body: body, seq: 0, iv: iv0, key: key,
                                                              filler: Data(repeating: 0, count: 4)))
    }
}
