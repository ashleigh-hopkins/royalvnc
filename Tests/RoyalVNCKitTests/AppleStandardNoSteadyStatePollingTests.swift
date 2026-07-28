import XCTest
@testable import RoyalVNCKit

/// Regression tests for the FR-4/SPECS §4.4 "no steady-state polling" rule: once the Apple-Standard
/// tier's AutoFrameBufferUpdate push is armed, the zero-arg `sendFramebufferUpdateRequest()` — called
/// both at initial connect and, critically, after EVERY decoded update by the standard receive loop
/// (`handleFramebufferUpdateMessage()`/`handleEndOfContinuousUpdatesMessage()`, reused unchanged by this
/// tier per SPECS §5.1) — must no-op for this tier. Left ungated this would re-request on every frame,
/// which is the device-confirmed "Change B" stall (fork note #6): requesting while the daemon is still
/// mid-transmitting makes screensharingd stop answering.
final class AppleStandardNoSteadyStatePollingTests: XCTestCase {
    private func makeFramebuffer() throws -> VNCFramebuffer {
        try VNCFramebuffer(logger: VNCPrintLogger(),
                           size: VNCSize(width: 16, height: 16),
                           screens: [],
                           pixelFormat: VNCProtocol.PixelFormat(depth: 24),
                           allocator: nil)
    }

    private func makeConnection(mode: VNCConnection.Settings.SessionMode) -> VNCConnection {
        let settings = VNCConnection.Settings(isDebugLoggingEnabled: false,
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

        return VNCConnection(settings: settings)
    }

    func testSendFramebufferUpdateRequestNoOpsForAppleStandardTier() async throws {
        let connection = makeConnection(mode: .appleStandardFramebuffer)
        connection.framebuffer = try makeFramebuffer()

        let mock = MockNetworkConnection(inbound: Data())
        connection.connection = mock

        try await connection.sendFramebufferUpdateRequest()

        XCTAssertTrue(mock.written.isEmpty,
                      "the Apple-Standard tier must NOT send a FramebufferUpdateRequest via this zero-arg wrapper — AutoFBU is its sole push mechanism (SPECS §4.4/FR-4)")
    }

    func testSendFramebufferUpdateRequestStillSendsForStandardRFB() async throws {
        let connection = makeConnection(mode: .standardRFB)
        connection.framebuffer = try makeFramebuffer()

        let mock = MockNetworkConnection(inbound: Data())
        connection.connection = mock

        try await connection.sendFramebufferUpdateRequest()

        XCTAssertFalse(mock.written.isEmpty,
                       "the pre-existing .standardRFB polling behaviour must be unaffected (AC-5)")
    }
}
