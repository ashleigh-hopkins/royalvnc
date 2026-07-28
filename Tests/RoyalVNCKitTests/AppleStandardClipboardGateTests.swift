import XCTest
@testable import RoyalVNCKit

/// Regression tests for AC-6 / SPECS §3.2 compound row / §5.3: on the Apple-Standard tier, a stray
/// `sendClientCutText` call (e.g. the app's always-visible manual-Paste button) MUST NOT emit an
/// un-primed Apple `0x1f` ClipboardSend — that tier's bring-up intentionally skips the `0x15`/`0x0b`
/// enable-fetch this needs, and its standard receive loop has no tolerance for an unsolicited `0x1f`
/// reply. It must fall through to the standard `0x06` (`ClientCutText`) — a harmless no-op against
/// screensharingd (T12), but NOT protocol traffic the receive loop wasn't built to survive.
final class AppleStandardClipboardGateTests: XCTestCase {
    private func makeConnection(mode: VNCConnection.Settings.SessionMode,
                                isClipboardRedirectionEnabled: Bool) -> VNCConnection {
        let settings = VNCConnection.Settings(isDebugLoggingEnabled: false,
                                              hostname: "localhost",
                                              port: 5900,
                                              isShared: true,
                                              isScalingEnabled: false,
                                              useDisplayLink: false,
                                              inputMode: .none,
                                              isClipboardRedirectionEnabled: isClipboardRedirectionEnabled,
                                              colorDepth: .depth24Bit,
                                              frameEncodings: [],
                                              mode: mode)

        return VNCConnection(settings: settings)
    }

    /// The `0x06` ClientCutText message type byte (RFC 6143 §7.5.6).
    private static let standardClientCutTextMessageType: UInt8 = 0x06

    /// The Apple `0x1f` ClipboardSend message type byte.
    private static let appleClipboardSendMessageType: UInt8 = 0x1f

    func testStrayPasteOnAppleStandardWithRedirectionOffEmitsStandard0x06NotApple0x1f() async throws {
        let connection = makeConnection(mode: .appleStandardFramebuffer, isClipboardRedirectionEnabled: false)
        let mock = MockNetworkConnection(inbound: Data())
        connection.connection = mock

        connection.sendClientCutText("hello")

        // sendClientCutText enqueues onto the client→server queue (drained by the send loop); dequeue and
        // send it directly here to inspect the wire bytes without spinning up a real send loop/Task.
        guard let message = connection.clientToServerMessageQueue.dequeue() else {
            XCTFail("sendClientCutText must enqueue exactly one message")
            return
        }
        try await message.send(connection: mock)

        XCTAssertFalse(mock.written.isEmpty)
        XCTAssertEqual(mock.written.first, Self.standardClientCutTextMessageType,
                       "with clipboard redirection OFF, the Apple-Standard tier MUST fall through to standard 0x06 — the record-layer's own standard receive loop has no tolerance for an unsolicited 0x1f reply")
        XCTAssertNotEqual(mock.written.first, Self.appleClipboardSendMessageType)
    }

    func testStrayPasteOnAppleStandardWithRedirectionOnEmitsApple0x1f() async throws {
        // Phase 2 scenario (SPECS §13): once redirection is actually enabled for this tier (not the
        // Phase-1 shipped default), the rich Apple path IS correct — this pins the OTHER half of the
        // compound gate so a future change cannot silently disable it for both states.
        let connection = makeConnection(mode: .appleStandardFramebuffer, isClipboardRedirectionEnabled: true)
        let mock = MockNetworkConnection(inbound: Data())
        connection.connection = mock

        connection.sendClientCutText("hello")

        guard let message = connection.clientToServerMessageQueue.dequeue() else {
            XCTFail("sendClientCutText must enqueue exactly one message")
            return
        }
        try await message.send(connection: mock)

        XCTAssertEqual(mock.written.first, Self.appleClipboardSendMessageType)
    }

    func testPasteOnStandardRFBIsUnaffected() async throws {
        let connection = makeConnection(mode: .standardRFB, isClipboardRedirectionEnabled: true)
        let mock = MockNetworkConnection(inbound: Data())
        connection.connection = mock

        connection.sendClientCutText("hello")

        guard let message = connection.clientToServerMessageQueue.dequeue() else {
            XCTFail("sendClientCutText must enqueue exactly one message")
            return
        }
        try await message.send(connection: mock)

        XCTAssertEqual(mock.written.first, Self.standardClientCutTextMessageType,
                       ".standardRFB behaviour must be unaffected (AC-5)")
    }
}
