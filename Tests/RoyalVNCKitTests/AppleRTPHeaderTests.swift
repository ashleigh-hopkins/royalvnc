import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `AppleRTPHeader` — the BE RTP header parser (HP Phase 4, HP-PHASE4-SPECS §5.4 / crib §3f).
final class AppleRTPHeaderTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }

    /// Basic 12-byte fixed header: V=2, no CC/X/marker, PT=100, seq/ts/ssrc BE.
    func testBasicHeader() {
        // 80 64 | 1234 | AABBCCDD | 11223344  + 4-byte payload
        let h = AppleRTPHeader.parse(hex("80641234aabbccdd11223344deadbeef"))
        XCTAssertNotNil(h)
        XCTAssertEqual(h?.version, 2)
        XCTAssertEqual(h?.csrcCount, 0)
        XCTAssertEqual(h?.hasExtension, false)
        XCTAssertEqual(h?.marker, false)
        XCTAssertEqual(h?.payloadType, 100)
        XCTAssertEqual(h?.sequenceNumber, 0x1234)
        XCTAssertEqual(h?.timestamp, 0xAABBCCDD)
        XCTAssertEqual(h?.ssrc, 0x11223344)
        XCTAssertEqual(h?.headerLength, 12)
    }

    /// PT = pkt[1] & 0x7F and marker = pkt[1] & 0x80 are independent bits of the second byte.
    func testPayloadTypeAndMarkerMasking() {
        // byte1 = 0xE0 = marker set | PT 0x60 (96).
        let h1 = AppleRTPHeader.parse(hex("80e01234aabbccdd11223344"))
        XCTAssertEqual(h1?.marker, true)
        XCTAssertEqual(h1?.payloadType, 0x60)

        // byte1 = 0xFF = marker set | PT 0x7F (127) — verifies the PT mask strips the marker bit.
        let h2 = AppleRTPHeader.parse(hex("80ff1234aabbccdd11223344"))
        XCTAssertEqual(h2?.marker, true)
        XCTAssertEqual(h2?.payloadType, 0x7F)

        // byte1 = 0x64 = marker clear | PT 100.
        let h3 = AppleRTPHeader.parse(hex("80641234aabbccdd11223344"))
        XCTAssertEqual(h3?.marker, false)
        XCTAssertEqual(h3?.payloadType, 100)
    }

    /// CC padding: hdrLen = 12 + CC*4. byte0 = 0x82 → CC=2 → 8 extra CSRC bytes.
    func testCSRCPadding() {
        // 82 64 | seq/ts/ssrc (12) | 2×4B CSRC (8) = 20-byte header + payload.
        let pkt = hex("82641234aabbccdd11223344" + "aaaaaaaabbbbbbbb" + "cafe")
        let h = AppleRTPHeader.parse(pkt)
        XCTAssertEqual(h?.csrcCount, 2)
        XCTAssertEqual(h?.headerLength, 20)
    }

    /// Extension header: X=1, one extension word → hdrLen = 12 + 4 + 1*4 = 20.
    func testExtensionOneWord() {
        // 90 64 | seq/ts/ssrc (12) | ext: profile 0xBEDE ‖ wordcount 0x0001 (4) | 1 ext word (4)
        let pkt = hex("90641234aabbccdd11223344" + "bede0001" + "12345678" + "cafe")
        let h = AppleRTPHeader.parse(pkt)
        XCTAssertEqual(h?.hasExtension, true)
        XCTAssertEqual(h?.headerLength, 20)
    }

    /// CC padding + extension combine: hdrLen = 12 + 1*4 + 4 + 2*4 = 28.
    func testCSRCPlusExtension() {
        // 91 64 → CC=1, X=1. CSRC(4) then ext at offset 16: profile ‖ wordcount 0x0002, 2 words(8).
        let pkt = hex("91641234aabbccdd11223344" + "0a0b0c0d" + "bede0002" + "1111111122222222" + "ff")
        let h = AppleRTPHeader.parse(pkt)
        XCTAssertEqual(h?.csrcCount, 1)
        XCTAssertEqual(h?.hasExtension, true)
        XCTAssertEqual(h?.headerLength, 28)
    }

    /// Empty-payload case: exactly the fixed header, no trailing payload.
    func testEmptyPayload() {
        let h = AppleRTPHeader.parse(hex("80641234aabbccdd11223344"))
        XCTAssertNotNil(h)
        XCTAssertEqual(h?.headerLength, 12)
    }

    /// Buffers too short to hold the declared header ⇒ nil (malformed → drop).
    func testTooShortReturnsNil() {
        // 11 bytes (< fixed 12).
        XCTAssertNil(AppleRTPHeader.parse(hex("80641234aabbccdd112233")))
        // CC=2 declared but only the 12-byte fixed header present.
        XCTAssertNil(AppleRTPHeader.parse(hex("82641234aabbccdd11223344")))
        // X=1 declared but no room for the 4-byte extension header.
        XCTAssertNil(AppleRTPHeader.parse(hex("90641234aabbccdd11223344")))
        // X=1, extension word count declared but the words are truncated.
        XCTAssertNil(AppleRTPHeader.parse(hex("90641234aabbccdd11223344" + "bede0002" + "12345678")))
    }
}
