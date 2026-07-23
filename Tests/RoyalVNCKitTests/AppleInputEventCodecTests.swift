import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleInputEventCodec` — the `0x10` encrypted input event (HP-SPECS §7).
///
/// ECB KAT (see scratchpad): content key `000102030405060708090a0b0c0d0e0f`, a 16-byte block of
/// `0x11` with `byte[10]` forced to `0xff` → AES-128-ECB `ba79f6bf6c438bff4a4396a91fd6b8cf`.
final class AppleInputEventCodecTests: XCTestCase {
    private let contentKey = Hex.data("000102030405060708090a0b0c0d0e0f")

    func testEncode0x10KAT() throws {
        let block = Data(repeating: 0x11, count: 16)
        let message = try AppleInputEventCodec.encode0x10(block: block, contentKey: contentKey)

        XCTAssertEqual(message.count, 18, "0x10 00 || 16-byte ECB block")
        XCTAssertEqual(Hex.string(message), "1000" + "ba79f6bf6c438bff4a4396a91fd6b8cf",
                       "0x10 00 prefix then AES-128-ECB(block with byte[10]=0xff)")
    }

    /// The codec forces `byte[10] = 0xff` regardless of the incoming value: two blocks differing
    /// ONLY at index 10 must produce identical output.
    func testSentinelForcedRegardlessOfInput() throws {
        var withZero = Array(repeating: UInt8(0x11), count: 16)
        withZero[10] = 0x00
        var withFF = Array(repeating: UInt8(0x11), count: 16)
        withFF[10] = 0xff

        let a = try AppleInputEventCodec.encode0x10(block: Data(withZero), contentKey: contentKey)
        let b = try AppleInputEventCodec.encode0x10(block: Data(withFF), contentKey: contentKey)

        XCTAssertEqual(a, b, "byte[10] is forced to the 0xff sentinel before encryption")
    }

    /// O9-neg control: the ECB block MUST be keyed on the content key, never the SRP wrap key.
    /// Encrypting the same block under a different key must yield a different message.
    func testKeySelectionMatters() throws {
        let wrapKey = Hex.data("ffffffffffffffffffffffffffffffff")
        let block = Data(repeating: 0x11, count: 16)

        let underContentKey = try AppleInputEventCodec.encode0x10(block: block, contentKey: contentKey)
        let underWrapKey = try AppleInputEventCodec.encode0x10(block: block, contentKey: wrapKey)

        XCTAssertNotEqual(underContentKey, underWrapKey,
                          "a 0x10 built under the wrong key must differ (would silently drop input on the wire)")
    }

    func testRejectsBadLengths() {
        XCTAssertThrowsError(try AppleInputEventCodec.encode0x10(block: Data(repeating: 0, count: 15),
                                                                 contentKey: contentKey))
        XCTAssertThrowsError(try AppleInputEventCodec.encode0x10(block: Data(repeating: 0, count: 16),
                                                                 contentKey: Data(repeating: 0, count: 15)))
    }
}
