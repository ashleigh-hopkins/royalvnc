import XCTest
@testable import RoyalVNCKit

/// Regression tests for `VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia:)` — the
/// tier-dependent plaintext-prelude `SetEncodings` bytes `armAppleRecordLayer()` writes BEFORE the
/// record layer arms (TYPE33-STANDARD-SPECS §4.2 fix).
///
/// Root cause this guards against: `screensharingd` latches its per-session primary codec from the
/// FIRST SetEncodings it ever sees, including this plaintext one. Reusing the HP blob (which correctly
/// leads with `1010`, HP's media codec) for the Apple-Standard tier meant the daemon latched codec 1010
/// before Apple-Standard's own correct, ZRLE-first list arrived (too late, post-arm) — producing a
/// silent blank screen at 0 fps on a real device over a slow WiFi link (invisible on Catalyst loopback,
/// where the late re-latch happened to win the race). Pure function, no socket/mocking required.
final class AppleArmSetEncodingsTests: XCTestCase {
    // MARK: - HP must remain byte-for-byte unchanged (Requirement 1)

    func testHPGetsTheExactHardcodedBlobUnchanged() {
        let bytes = VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia: true)

        // The live-confirmed HP blob (HP-SPECS §4.3 / crib §2b.1): SetEncodings header (0x02, pad,
        // count=13) then 13 s32 BE encodings led by 1010 (0x000003f2), HP's media codec.
        let expectedHex = "0200000d" +
            "000003f2" + "000003f3" + "000003ea" +
            "00000006" + "00000010" + "00000450" +
            "0000044c" + "ffffff21" + "0000044d" +
            "00000451" + "00000453" + "00000455" +
            "00000456"

        XCTAssertEqual(bytes.map { String(format: "%02x", $0) }.joined(), expectedHex,
                       "HP's plaintext-prelude SetEncodings must be byte-for-byte identical to the pre-fix blob — any diff here is a regression against HP-SPECS §4.3")
        XCTAssertEqual(bytes.count, 56)
    }

    func testHPBytesLeadWith1010() {
        let bytes = VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia: true)

        // header = msgType(1) + pad(1) + count u16(2) = 4 bytes, then s32 BE encodings.
        XCTAssertEqual(Array(bytes[4...7]), [0x00, 0x00, 0x03, 0xf2],
                       "HP's FIRST encoding must remain 1010 (its media codec) — unchanged by this fix")
    }

    // MARK: - Apple-Standard must lead with its OWN primary, not HP's 1010 (Requirement 2 / root-cause fix)

    func testAppleStandardLeadsWithZRLENotHP1010() {
        let bytes = VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia: false)

        XCTAssertEqual(bytes[0], 0x02, "SetEncodings message type")

        let firstEncoding = Array(bytes[4...7])
        XCTAssertEqual(firstEncoding, [0x00, 0x00, 0x00, 0x10],
                       "FIRST entry of the Apple-Standard plaintext prelude must be ZRLE(16) — screensharingd latches its primary codec from the FIRST SetEncodings it ever sees, including this one")
        XCTAssertNotEqual(firstEncoding, [0x00, 0x00, 0x03, 0xf2],
                          "REGRESSION GUARD: must NEVER lead with 1010 (HP's media codec) here — that is the exact root cause of the device-reproduced blank-screen-at-0fps defect (silent failure, only visible on a slow/high-latency link, not on loopback)")
    }

    func testAppleStandardBytesAreDerivedFromTheSingleSourceOfTruthNotASecondBlob() {
        let bytes = VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia: false)

        let expectedTypes = AppleStandardBringUp
            .setEncodingsOrder(primary: AppleStandardBringUp.defaultPrimary)
            .map { VNCEncodingType(Int32($0)) }
        let expected = VNCProtocol.SetEncodings(encodingTypes: expectedTypes).data

        XCTAssertEqual(bytes, expected,
                       "must be encoded from AppleStandardBringUp.setEncodingsOrder(primary:) — not an independent hardcoded blob (DRY, SPECS §4.2)")
    }

    func testAppleStandardBytesMatchProbeConfigAExactly() {
        // probe §Method Config A, live-verified (8,239 ZRLE rects): [16, 1011, 1002, 6, 1104, 1105,
        // 1107, 1109, 1110].
        let bytes = VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia: false)

        // header(4) + 9 encodings * 4 bytes = 40 bytes.
        XCTAssertEqual(bytes.count, 40)
        XCTAssertEqual(Array(bytes[2...3]), [0x00, 0x09], "count = 9 encodings")

        let expectedIds: [Int32] = [16, 1011, 1002, 6, 1104, 1105, 1107, 1109, 1110]
        for (index, expectedId) in expectedIds.enumerated() {
            let offset = 4 + index * 4
            let entry = Array(bytes[offset...(offset + 3)])
            let b0 = Int32(entry[0]) << 24
            let b1 = Int32(entry[1]) << 16
            let b2 = Int32(entry[2]) << 8
            let b3 = Int32(entry[3])
            let decoded = b0 | b1 | b2 | b3
            XCTAssertEqual(decoded, expectedId, "encoding #\(index) must be \(expectedId)")
        }
    }

    // MARK: - The two tiers must never accidentally converge on the same bytes

    func testHPAndAppleStandardProduceDifferentBytes() {
        let hp = VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia: true)
        let standard = VNCConnection.armSetEncodingsBytes(negotiatesHighPerformanceMedia: false)

        XCTAssertNotEqual(hp, standard,
                          "the two tiers must send DIFFERENT plaintext-prelude SetEncodings — this is the entire fix; if they ever match again the tier-dependent branch has been removed")
    }
}
