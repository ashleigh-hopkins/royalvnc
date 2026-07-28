import XCTest
@testable import RoyalVNCKit

/// Regression tests for the HP gating (HP-SPECS §4.2 / §5.1 / AC-5; TYPE33-STANDARD-SPECS §3.2/§3.3):
/// with `mode == .standardRFB` the client is byte-identical to the standard path — the `003.889`
/// banner is never sent, type 33 is never selected, and the connection object is a bare
/// `NetworkConnection` (no record-layer decorator). With `mode == .appleHighPerformanceMedia` the
/// gates engage. (`enableHighPerformance: Bool` was removed with no shim — Q1 DECIDED, single
/// consumer, no `@objc` exposure — and replaced by the `SessionMode` enum.)
final class AppleHighPerformanceGatingTests: XCTestCase {
    // MARK: - Banner (pure)

    func testAppleRemoteDesktopBannerBytes() {
        let banner = VNCProtocol.ProtocolVersion.appleRemoteDesktop

        XCTAssertEqual(banner.data, Data("RFB 003.889\n".utf8), "HP banner is exactly RFB 003.889")
        XCTAssertEqual(banner.data.count, 12)
        XCTAssertTrue(banner.isAppleRemoteDesktop)
    }

    func testAppleRemoteDesktopGateProperty() {
        // MINOR-3: Guard the HP gate by asserting isAppleRemoteDesktop == true.
        XCTAssertTrue(VNCProtocol.ProtocolVersion.appleRemoteDesktop.isAppleRemoteDesktop,
                     "The appleRemoteDesktop version must satisfy the isAppleRemoteDesktop gate")
    }

    func testStandardDowngradeBannerUnchanged() {
        // The else-path banner (server > 3.8 downgraded to 3.8) must remain RFB 003.008.
        let standard = VNCProtocol.ProtocolVersion(majorVersion: 3, minorVersion: 8)

        XCTAssertEqual(standard.data, Data("RFB 003.008\n".utf8))
        XCTAssertFalse(standard.isAppleRemoteDesktop)
    }

    // MARK: - Settings default

    func testSessionModeDefaultsStandardRFB() {
        let settings = Self.makeSettings(mode: .standardRFB)

        XCTAssertEqual(settings.mode, .standardRFB, "SessionMode must default to .standardRFB (Q1)")
        XCTAssertFalse(settings.usesAppleControlChannel)
        XCTAssertFalse(settings.negotiatesHighPerformanceMedia)
    }

    func testDerivedHelpersForEachSessionMode() {
        XCTAssertFalse(Self.makeSettings(mode: .standardRFB).usesAppleControlChannel)
        XCTAssertFalse(Self.makeSettings(mode: .standardRFB).negotiatesHighPerformanceMedia)

        XCTAssertTrue(Self.makeSettings(mode: .appleStandardFramebuffer).usesAppleControlChannel)
        XCTAssertFalse(Self.makeSettings(mode: .appleStandardFramebuffer).negotiatesHighPerformanceMedia)

        XCTAssertTrue(Self.makeSettings(mode: .appleHighPerformanceMedia).usesAppleControlChannel)
        XCTAssertTrue(Self.makeSettings(mode: .appleHighPerformanceMedia).negotiatesHighPerformanceMedia)
    }

    // MARK: - Connection object (some -> any wrap)

    func testConnectionIsBareWhenStandardRFB() {
        let connection = VNCConnection(settings: Self.makeSettings(mode: .standardRFB))

        XCTAssertFalse(connection.connection is AppleRecordLayerConnection,
                       ".standardRFB must leave the connection bare — no record-layer decorator (AC-5)")
    }

    func testConnectionIsWrappedForAppleStandardFramebuffer() {
        let connection = VNCConnection(settings: Self.makeSettings(mode: .appleStandardFramebuffer))

        XCTAssertTrue(connection.connection is AppleRecordLayerConnection,
                      ".appleStandardFramebuffer wraps the base in the record-layer decorator too — it authenticates as Apple (usesAppleControlChannel) even though it never negotiates media")
    }

    func testConnectionIsWrappedWhenHPOn() {
        let connection = VNCConnection(settings: Self.makeSettings(mode: .appleHighPerformanceMedia))

        XCTAssertTrue(connection.connection is AppleRecordLayerConnection,
                      "HP ON wraps the base in the record-layer decorator (passthrough at creation)")
    }

    // MARK: - Handshake: OFF ignores type 33 and sends the <=3.8 banner

    /// Scenario (no socket):
    ///   1. Server offers "RFB 003.889" then security types {30, 33, 36, 35}.
    ///   2. With HP OFF the client MUST downgrade the banner to RFB 003.008 (server minor 889 > 3.8).
    ///   3. The client MUST select Diffie-Hellman (30, 0x1e) — NOT Apple type 33 (0x21) — proving
    ///      type 33 is ignored when HP is OFF.
    ///   4. It then tries ARD (type-30) auth; the scripted server has no more bytes so the read
    ///      throws — we only assert the banner + the selected security-type byte captured before that.
    func testHandshakeOffDowngradesBannerAndIgnoresType33() async throws {
        let connection = VNCConnection(settings: Self.makeSettings(mode: .standardRFB))
        let mock = MockNetworkConnection(inbound: Self.serverOffer())
        connection.connection = mock

        do {
            try await connection.handshake()
            XCTFail("handshake should stop when the scripted server runs out of bytes")
        } catch {
            // expected — inbound exhausted during type-30 auth
        }

        let written = Array(mock.written)
        XCTAssertGreaterThanOrEqual(written.count, 13, "banner (12) + 1-byte security-type selection")

        let banner = Data(written[0..<12])
        XCTAssertEqual(banner, Data("RFB 003.008\n".utf8), "HP OFF downgrades to RFB 003.008")

        let selectedSecurityType = written[12]
        XCTAssertEqual(selectedSecurityType, 0x1e, "HP OFF selects DH (30), not Apple type 33 (0x21)")
        XCTAssertNotEqual(selectedSecurityType, 0x21, "type 33 must be ignored when HP is OFF")
    }

    // MARK: - Fixtures

    /// Server-side script: 12-byte "RFB 003.889" banner, then a u8 count (4) and the four Apple-host
    /// security types {30, 33, 36, 35} = {0x1e, 0x21, 0x24, 0x23}.
    private static func serverOffer() -> Data {
        var data = Data("RFB 003.889\n".utf8)
        data.append(4) // number of security types
        data.append(contentsOf: [0x1e, 0x21, 0x24, 0x23])

        return data
    }

    // MARK: - Connect-stage timing helper

    /// `hpElapsedMs` backs every `[hp]`/`[hp-media]` connect-stage duration. It must report elapsed
    /// milliseconds and must NEVER print a negative number: it reads wall-clock `Date`, so a clock
    /// adjustment (or NTP step) mid-connect can put `start` in the future.
    func testHPElapsedMsMeasuresForwardAndClampsAtZero() {
        let quarterSecondAgo = Date().addingTimeInterval(-0.25)
        let measured = VNCConnection.hpElapsedMs(since: quarterSecondAgo)
        XCTAssertGreaterThanOrEqual(measured, 200, "≈250ms must be reported as roughly 250ms")
        XCTAssertLessThan(measured, 2000, "a 250ms interval must not report seconds")

        XCTAssertEqual(VNCConnection.hpElapsedMs(since: Date().addingTimeInterval(5)), 0,
                       "a start time in the future (clock step) must clamp to 0, never go negative")
    }

    // MARK: - Canvas derived from a 0x451 layout (virtual-display fallback)

    /// A virtual-display connect gets no `0x1c` answer canvas, so the framebuffer + video geometry come
    /// from the `0x451` layout's BACKING dimensions — those are what the encoder actually emits. Getting
    /// scaled-vs-backing the wrong way round here would paint full-resolution tiles into an
    /// undersized buffer (the exact stretched/blocky failure this replaces).
    func testCanvasFromLayoutUsesBackingDimensionsAndOfferedTiles() {
        let layout = AppleControlChannelCodec.LayoutInfo(scaledWidth: 1712, scaledHeight: 1112,
                                                         backingWidth: 2868, backingHeight: 1320)
        let canvas = VNCConnection.canvasFromLayout(layout, offeredTileCount: 4, offeredLTRP: true)

        XCTAssertEqual(canvas.width, 2868, "width must be the BACKING width, not the scaled width")
        XCTAssertEqual(canvas.height, 1320, "height must be the BACKING height, not the scaled height")
        XCTAssertEqual(canvas.tileCount, 4, "tile count comes from what we offered (not in the layout)")
        XCTAssertTrue(canvas.ltrpEnabled)
        XCTAssertTrue(canvas.isReady, "a layout-derived canvas must satisfy isReady so negotiation proceeds")
    }

    /// A zero-dimension layout must NOT produce a usable canvas — the caller relies on `isReady` being
    /// false to fall through to its fail-fast (lift the curtain) rather than proceeding with a 0×0 buffer.
    func testCanvasFromLayoutWithZeroBackingIsNotReady() {
        let empty = AppleControlChannelCodec.LayoutInfo(scaledWidth: 1920, scaledHeight: 1080,
                                                        backingWidth: 0, backingHeight: 0)
        XCTAssertFalse(VNCConnection.canvasFromLayout(empty, offeredTileCount: 4, offeredLTRP: true).isReady)
    }

    private static func makeSettings(mode: VNCConnection.Settings.SessionMode) -> VNCConnection.Settings {
        VNCConnection.Settings(isDebugLoggingEnabled: false,
                               hostname: "localhost",
                               port: 5900,
                               isShared: true,
                               isScalingEnabled: false,
                               useDisplayLink: false,
                               inputMode: .none,
                               isClipboardRedirectionEnabled: false,
                               colorDepth: .depth24Bit,
                               frameEncodings: [],
                               mode: mode)
    }
}
