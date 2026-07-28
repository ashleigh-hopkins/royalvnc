import XCTest
@testable import RoyalVNCKit

/// Unit tests for the pure, connection-free Apple-Standard bring-up seam (TYPE33-STANDARD-SPECS §11.1):
/// SetEncodings ordering, the AutoFrameBufferUpdate (`0x09`) byte layout, and the canvas-source resolver.
/// No sockets, no `VNCConnection` — every assertion is against `AppleStandardBringUp`'s static functions.
final class AppleStandardBringUpTests: XCTestCase {
    // MARK: - setEncodingsOrder(primary:)

    func testSetEncodingsOrderZRLEPrimaryMatchesProbeConfigAExactly() {
        // probe §Method Config A: `16, 1011, 1002, 6, 1104, 1105, 1107, 1109, 1110`.
        let order = AppleStandardBringUp.setEncodingsOrder(primary: AppleStandardBringUp.zrle)

        XCTAssertEqual(order, [16, 1011, 1002, 6, 1104, 1105, 1107, 1109, 1110])
    }

    func testSetEncodingsOrderZlibPrimaryMatchesProbeConfigDExactly() {
        // probe §Method Config D: `6, 1011, 1002, 16, 1104, 1105, 1107, 1109, 1110`.
        let order = AppleStandardBringUp.setEncodingsOrder(primary: AppleStandardBringUp.zlib)

        XCTAssertEqual(order, [6, 1011, 1002, 16, 1104, 1105, 1107, 1109, 1110])
    }

    func testSetEncodingsOrderPrimaryAlwaysLeads() {
        for primary in AppleStandardBringUp.decodableWhitelistedEncodings {
            let order = AppleStandardBringUp.setEncodingsOrder(primary: primary)

            XCTAssertEqual(order.first, primary, "primary must be the FIRST entry — this is what screensharingd's whitelist selector latches onto")
        }
    }

    func testSetEncodingsOrderContainsNoDuplicatesAndOmits1010() {
        let order = AppleStandardBringUp.setEncodingsOrder(primary: AppleStandardBringUp.zrle)

        XCTAssertEqual(order.count, Set(order).count, "no duplicate encoding ids")
        XCTAssertFalse(order.contains(1010), "1010 was never advertised by the probe's live-verified configuration — do not re-add it without a new live measurement")
    }

    // MARK: - autoFBUBytes(continuous:width:height:)

    func testAutoFBUBytesContinuousOnZeroesWire4Through7() {
        let bytes = AppleStandardBringUp.autoFBUBytes(continuous: true, width: 1920, height: 1080)

        XCTAssertEqual(bytes.count, 16)
        XCTAssertEqual(bytes[0], 0x09, "message type")
        XCTAssertEqual(Array(bytes[4...7]), [0x00, 0x00, 0x00, 0x00], "wire[4..7] must be 0x00000000 when continuous — the T14 per-viewer continuous-delivery finding")
    }

    func testAutoFBUBytesContinuousOffFillsWire4Through7WithFF() {
        let bytes = AppleStandardBringUp.autoFBUBytes(continuous: false, width: 1920, height: 1080)

        XCTAssertEqual(Array(bytes[4...7]), [0xFF, 0xFF, 0xFF, 0xFF])
    }

    func testAutoFBUBytesByte3IsZero() {
        // ASSUMPTION A4: the probe's own live-proven builder used wire[3]=0x00, not the HP/reference
        // default 0x01 (never A/B tested for this tier).
        let bytes = AppleStandardBringUp.autoFBUBytes(continuous: true, width: 100, height: 100)

        XCTAssertEqual(bytes[3], 0x00)
    }

    func testAutoFBUBytesWidthHeightLandAtWire12Through15() {
        let bytes = AppleStandardBringUp.autoFBUBytes(continuous: true, width: 0x0780, height: 0x0438)

        XCTAssertEqual(Array(bytes[12...15]), [0x07, 0x80, 0x04, 0x38], "1920x1080 BE, matching the probe's exact captured bytes")
    }

    func testAutoFBUBytesMatchesProbeConfigAByteForByte() {
        // probe §Method: `09000000000000000000000007800438` for Config A (continuous ON, 1920x1080).
        let bytes = AppleStandardBringUp.autoFBUBytes(continuous: true, width: 1920, height: 1080)
        let expectedHex = "09000000000000000000000007800438"
        let actualHex = bytes.map { byte -> String in
            let hex = String(byte, radix: 16)
            return hex.count == 1 ? "0" + hex : hex
        }.joined()

        XCTAssertEqual(actualHex, expectedHex)
    }

    // MARK: - resolveCanvasSize(requestedBackingWidth:requestedBackingHeight:serverInit:)

    func testResolveCanvasSizeFallsBackToServerInitWhenNoRequest() {
        // G1: nil is the NORMAL, shipped-default case (host-display default) — not an error state.
        let resolved = AppleStandardBringUp.resolveCanvasSize(requestedBackingWidth: nil,
                                                              requestedBackingHeight: nil,
                                                              serverInit: (width: 3840, height: 2160))

        XCTAssertEqual(resolved.width, 3840)
        XCTAssertEqual(resolved.height, 2160)
    }

    func testResolveCanvasSizeUsesRequestedBackingWhenPresent() {
        let resolved = AppleStandardBringUp.resolveCanvasSize(requestedBackingWidth: 1280,
                                                              requestedBackingHeight: 720,
                                                              serverInit: (width: 3840, height: 2160))

        XCTAssertEqual(resolved.width, 1280)
        XCTAssertEqual(resolved.height, 720)
    }

    func testResolveCanvasSizeFallsBackWhenRequestIsZero() {
        let resolved = AppleStandardBringUp.resolveCanvasSize(requestedBackingWidth: 0,
                                                              requestedBackingHeight: 0,
                                                              serverInit: (width: 1920, height: 1080))

        XCTAssertEqual(resolved.width, 1920)
        XCTAssertEqual(resolved.height, 1080)
    }

    func testResolveCanvasSizeFallsBackWhenOnlyOneDimensionIsPresent() {
        // A malformed partial request (should never happen given HighPerformanceDisplay's paired
        // stored properties, but the resolver must not silently mix a real width with a stale height).
        let resolved = AppleStandardBringUp.resolveCanvasSize(requestedBackingWidth: 1280,
                                                              requestedBackingHeight: nil,
                                                              serverInit: (width: 1920, height: 1080))

        XCTAssertEqual(resolved.width, 1920)
        XCTAssertEqual(resolved.height, 1080)
    }

    func testResolveCanvasSizeFallsBackWhenRequestExceedsUInt16Range() {
        let resolved = AppleStandardBringUp.resolveCanvasSize(requestedBackingWidth: 1 << 20,
                                                              requestedBackingHeight: 1080,
                                                              serverInit: (width: 1920, height: 1080))

        XCTAssertEqual(resolved.width, 1920)
        XCTAssertEqual(resolved.height, 1080)
    }
}
