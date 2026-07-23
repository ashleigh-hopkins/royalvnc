import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleRecordKeySchedule` — the `0x44f` rekey parse + independent AES-128-ECB
/// unwrap + wrap-key rotation (HP-SPECS §7).
///
/// KAT (see scratchpad): under wrap key `0f0e0d0c0b0a09080706050403020100`,
/// `enc_key = 65904177f55f924c5b42342726cd9757` unwraps to `101112131415161718191a1b1c1d1e1f`
/// and `enc_iv  = 1f2c64877ff635b61a835a1d52ed94f7` unwraps to `202122232425262728292a2b2c2d2e2f`
/// (AES-128-ECB, no padding).
final class AppleRecordKeyScheduleTests: XCTestCase {
    private let wrapKey = "0f0e0d0c0b0a09080706050403020100"
    private let keyWrapped = "65904177f55f924c5b42342726cd9757"
    private let ivWrapped = "1f2c64877ff635b61a835a1d52ed94f7"
    private let contentKeyPlain = "101112131415161718191a1b1c1d1e1f"
    private let ivPlain = "202122232425262728292a2b2c2d2e2f"

    // MARK: - parseRekey

    func testParseRekeyLayoutAndGeneration() throws {
        // generation = 0x00000102, then enc_key[16] || enc_iv[16].
        let rekey = Hex.data("00000102") + Hex.data(keyWrapped) + Hex.data(ivWrapped)
        XCTAssertEqual(rekey.count, 36)

        let parsed = try AppleRecordKeySchedule.parseRekey(rekey)
        XCTAssertEqual(parsed.gen, 0x0000_0102, "generation is big-endian u32")
        XCTAssertEqual(Hex.string(parsed.keyWrapped), keyWrapped)
        XCTAssertEqual(Hex.string(parsed.ivWrapped), ivWrapped)
    }

    func testParseRekeyRejectsWrongLength() {
        XCTAssertThrowsError(try AppleRecordKeySchedule.parseRekey(Data(repeating: 0, count: 35)))
        XCTAssertThrowsError(try AppleRecordKeySchedule.parseRekey(Data(repeating: 0, count: 37)))
    }

    // MARK: - unwrap (KAT + independence)

    func testUnwrapKAT() throws {
        let recovered = try AppleRecordKeySchedule.unwrap((Hex.data(keyWrapped), Hex.data(ivWrapped)),
                                                          wrapKey: Hex.data(wrapKey))

        XCTAssertEqual(Hex.string(recovered.key), contentKeyPlain, "content key unwrapped via AES-128-ECB")
        XCTAssertEqual(Hex.string(recovered.iv), ivPlain, "content iv unwrapped via AES-128-ECB")
    }

    /// The two 16-byte halves are unwrapped independently: swapping the wrapped halves swaps the
    /// recovered outputs, proving neither half depends on the other (no CBC chaining across them).
    func testUnwrapHalvesAreIndependent() throws {
        let swapped = try AppleRecordKeySchedule.unwrap((Hex.data(ivWrapped), Hex.data(keyWrapped)),
                                                        wrapKey: Hex.data(wrapKey))

        XCTAssertEqual(Hex.string(swapped.key), ivPlain, "swapped: 'key' slot yields the iv plaintext")
        XCTAssertEqual(Hex.string(swapped.iv), contentKeyPlain, "swapped: 'iv' slot yields the key plaintext")
    }

    func testUnwrapRejectsBadLengths() {
        // Bad wrap key length.
        XCTAssertThrowsError(try AppleRecordKeySchedule.unwrap((Hex.data(keyWrapped), Hex.data(ivWrapped)),
                                                               wrapKey: Data(repeating: 0, count: 15)))
        // Bad wrapped-half length.
        XCTAssertThrowsError(try AppleRecordKeySchedule.unwrap((Data(repeating: 0, count: 15), Hex.data(ivWrapped)),
                                                               wrapKey: Hex.data(wrapKey)))
    }

    // MARK: - nextWrapKey rotation

    func testNextWrapKeyIsRecoveredKey() throws {
        let recovered = try AppleRecordKeySchedule.unwrap((Hex.data(keyWrapped), Hex.data(ivWrapped)),
                                                          wrapKey: Hex.data(wrapKey))
        let next = try AppleRecordKeySchedule.nextWrapKey(recoveredKey: recovered.key)

        XCTAssertEqual(next, recovered.key, "the next wrap key is the recovered content key (forward rotation)")
    }

    func testNextWrapKeyRejectsBadLength() {
        XCTAssertThrowsError(try AppleRecordKeySchedule.nextWrapKey(recoveredKey: Data(repeating: 0, count: 15)))
    }
}
