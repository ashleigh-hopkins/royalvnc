#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Apple in-protocol clipboard (type-33 control channel)
//
// Wires `AppleClipboardCodec` onto the live record-layer connection. All four messages ride the
// transparent AES-128-CBC control channel as ordinary RFB messages (the record layer seals each
// `write` / decrypts each `read`), so this only deals in plaintext bytes. HP-gated: nothing here
// fires unless `Settings.enableHighPerformance` is on (the only mode in which the record layer is
// active and the daemon speaks these messages). See `AppleClipboardCodec` +
// `plans/t12-clipboard-perf/T12-EXP1-GOLDEN-FINDINGS.md`.

extension VNCProtocol {
    /// A prebuilt Apple clipboard control message (`0x15`/`0x0b`/`0x1f`). Carries the fully-encoded
    /// plaintext body; the record layer seals it into one CBC record on send.
    struct AppleClipboardControlMessage: VNCSendableMessage {
        let messageType: UInt8
        let data: Data

        func send(connection: NetworkConnectionWriting) async throws {
            try await connection.write(data: data)
        }
    }
}

// MARK: - Send side
extension VNCConnection {
    /// Enqueue the one-time clipboard bring-up (`0x15` AutoPasteboard enable + prime `0x0b` fetch).
    /// Called at send-loop start; no-op unless HP + clipboard redirection are both on. Without the
    /// `0x15` the daemon never pushes clipboard, and the prime fetch seeds the phone with the Mac's
    /// current pasteboard.
    func enqueueAppleClipboardBringUpIfNeeded() {
        guard settings.enableHighPerformance,
              settings.isClipboardRedirectionEnabled else { return }

        logger.logDebug("Apple clipboard: enabling autopasteboard (0x15) + prime fetch (0x0b)")

        enqueueClientToServerMessage(VNCProtocol.AppleClipboardControlMessage(
            messageType: AppleClipboardCodec.msgAutoPasteboard,
            data: AppleClipboardCodec.buildAutoPasteboardEnable()))
        enqueueAppleClipboardFetch()
    }

    /// Enqueue a `0x0b` full-fetch of the host pasteboard (after a `0x14 cmd=2` notify, and at bring-up).
    func enqueueAppleClipboardFetch() {
        enqueueClientToServerMessage(VNCProtocol.AppleClipboardControlMessage(
            messageType: AppleClipboardCodec.msgClipboardRequest,
            data: AppleClipboardCodec.buildClipboardFetch()))
    }
}

extension VNCConnection {
    /// Send clipboard `text` to the host via Apple's rich `0x1f` ClipboardSend, with the `promise=1`
    /// byte that macOS 27 requires to actually write NSPasteboard. Called by `sendClientCutText` in HP
    /// mode (keeping the app transport-agnostic — it still calls `sendClientCutText`). No-op unless
    /// clipboard redirection is enabled. Safe from the main thread (enqueues onto the send queue).
    func sendAppleClipboardText(_ text: String) {
        guard settings.isClipboardRedirectionEnabled else { return }

        do {
            let data = try AppleClipboardCodec.buildClipboardSend(text: text)
            enqueueClientToServerMessage(VNCProtocol.AppleClipboardControlMessage(
                messageType: AppleClipboardCodec.msgClipboardSend,
                data: data))
        } catch {
            logger.logError("Apple clipboard: failed to build ClipboardSend (0x1f): \(error)")
        }
    }
}

// NOTE: The inbound `0x14`/`0x1f` handling moved to the record-framed control loop
// (`VNCConnection+AppleControl.swift`), which parses whole decrypted records in-memory and reassembles a
// multi-record `0x1f` by declared size — reusing `AppleClipboardCodec.decodeInboundText` for decode.
// The old socket-incremental handlers here (dispatched from the standard `didReceive` loop) are gone
// because the HP path no longer runs the standard receive loop.
