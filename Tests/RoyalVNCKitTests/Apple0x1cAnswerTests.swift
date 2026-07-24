import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `Apple0x1cAnswer` — the `0x1c` answer parser (HP Phase 4, HP-PHASE4-SPECS §5.3 / crib §2a).
///
/// The answer vectors are produced by an INDEPENDENT oracle (Python `plistlib` FMT_BINARY + `zlib`,
/// i.e. host-equivalent, NOT the AGPL reference), which also exercises cross-implementation
/// compatibility: Python's binary plist is decoded by `PropertyListSerialization` and Python's
/// `zlib.compress` stream is inflated by the fork's vendored `ZlibStream`.
final class Apple0x1cAnswerTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }

    // 0x00 ‖ filler ‖ bplist{avcMediaStreamNegotiatorMediaBlob: zlib(F5 sub4=2560/5=1440/6=4/7=1)}
    private let answerReady = "00deadbeef62706c6973743030d101025f10216176634d6564696153747265616d4e65676f746961746f724d65646961426c6f624f1018789ce3601460d4e2526810d158c06dc062c10800109e0243080b2f000000000000010100000000000000030000000000000000000000000000004a"
    // 0x00 ‖ bplist{... zlib(F5 sub4=0/5=0/6=0)}  → encoder not ready
    private let answerZero = "0062706c6973743030d101025f10216176634d6564696153747265616d4e65676f746961746f724d65646961426c6f624f1012789ce360d4625360d06030600000039d00b2080b2f0000000000000101000000000000000300000000000000000000000000000044"
    // Python zlib.compress(0x00..0x2f) — the fork's ZlibStream must inflate this.
    private let known = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
    private let pyZlibKnown = "789c6360646266616563e7e0e4e2e6e1e5e3171014121611151397909492969195935750545256515553d7d0d4d2d6d1d5d3070048280469"

    func testParseReadyCanvas() {
        let c = Apple0x1cAnswer.parse(hex(answerReady))
        XCTAssertTrue(c.isReady)
        XCTAssertEqual(c.width, 2560)
        XCTAssertEqual(c.height, 1440)
        XCTAssertEqual(c.tileCount, 4)
        XCTAssertTrue(c.ltrpEnabled)
    }

    func testParseZeroCanvasNotReady() {
        // Encoder-not-ready (cw=ch=0): the scan yields no usable canvas ⇒ notReady (caller retries).
        let c = Apple0x1cAnswer.parse(hex(answerZero))
        XCTAssertFalse(c.isReady)
        XCTAssertEqual(c, .notReady)
    }

    func testWrongFirstByteReturnsNotReady() {
        // Same bytes but first byte != 0x00.
        var bytes = [UInt8](hex(answerReady))
        bytes[0] = 0x01
        XCTAssertEqual(Apple0x1cAnswer.parse(Data(bytes)), .notReady)
    }

    func testNoBplistReturnsNotReady() {
        XCTAssertEqual(Apple0x1cAnswer.parse(Data([0x00, 0xDE, 0xAD, 0xBE, 0xEF])), .notReady)
        XCTAssertEqual(Apple0x1cAnswer.parse(Data()), .notReady)
    }

    /// Cross-implementation zlib: the fork's ZlibStream inflates a Python `zlib.compress` stream.
    func testZlibInflatesPythonStream() throws {
        let out = try ZlibStream().decompressedData(compressedData: hex(pyZlibKnown))
        XCTAssertEqual(out, hex(known))
    }
}
