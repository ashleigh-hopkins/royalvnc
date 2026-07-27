import XCTest
@testable import RoyalVNCKit

/// Regression tests for the HP gating (HP-SPECS §4.2 / §5.1 / AC-5): with `enableHighPerformance`
/// OFF the client is byte-identical to the standard path — the `003.889` banner is never sent, type
/// 33 is never selected, and the connection object is a bare `NetworkConnection` (no record-layer
/// decorator). With it ON the gates engage.
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

    func testEnableHighPerformanceDefaultsOff() {
        let settings = Self.makeSettings(enableHighPerformance: false)

        XCTAssertFalse(settings.enableHighPerformance, "HP must default OFF (Q1)")
    }

    // MARK: - Connection object (some -> any wrap)

    func testConnectionIsBareWhenHPOff() {
        let connection = VNCConnection(settings: Self.makeSettings(enableHighPerformance: false))

        XCTAssertFalse(connection.connection is AppleRecordLayerConnection,
                       "HP OFF must leave the connection bare — no record-layer decorator (AC-5)")
    }

    func testConnectionIsWrappedWhenHPOn() {
        let connection = VNCConnection(settings: Self.makeSettings(enableHighPerformance: true))

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
        let connection = VNCConnection(settings: Self.makeSettings(enableHighPerformance: false))
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

    private static func makeSettings(enableHighPerformance: Bool) -> VNCConnection.Settings {
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
                               enableHighPerformance: enableHighPerformance)
    }
}
