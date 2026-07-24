#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Apple HP TCP control-channel receive loop
//
// On the HP path the daemon uses the encrypted type-33 TCP channel for CONTROL only — cursor/layout/
// config pseudo-encodings (inside `0x00` FramebufferUpdates) plus clipboard (`0x14`/`0x1f`). Real pixels
// flow over UDP/SRTP (`VNCConnection+AppleMedia`). This loop REPLACES the standard framebuffer decode
// loop on the HP path: it reads one whole record (= one RFB message) at a time via the record layer's
// `readControlMessage()` and dispatches it in-memory, mirroring the reference `_handle_tcp_msg`.
//
// Record-framing is the whole point: an unknown-length rect (e.g. Apple `1100`/`1101`, whose wire size
// is undocumented) can be skipped by discarding the record's unparsed tail and resyncing on the next
// record, instead of desyncing the byte stream (which surfaced as the phantom "message type 7" — crib
// §7a/§7c). HP-gated; the standard `didReceive` path is untouched.

extension VNCProtocol {
    /// A raw prebuilt control-channel message (already-encoded plaintext body). Used for HP re-arm
    /// (`0x09` AutoFrameBufferUpdate + `0x03` FramebufferUpdateRequest). The record layer seals it into
    /// one CBC record on send; routing it through the send queue keeps writes single-writer (NFR-7).
    struct AppleControlRawMessage: VNCSendableMessage {
        let data: Data

        /// The RFB message type (first byte of the prebuilt body); metadata for the send layer.
        var messageType: UInt8 { data.first ?? 0 }

        func send(connection: NetworkConnectionWriting) async throws {
            try await connection.write(data: data)
        }
    }
}

extension VNCConnection {
    /// Start the HP control-channel receive loop. Requires the armed `AppleRecordLayerConnection`.
    func startAppleControlLoop() {
        guard let recordLayer = connection as? AppleRecordLayerConnection else {
            logger.logError("[hp-ctl] control loop requires the Apple record layer; not starting")
            return
        }

        logger.logDebug("[hp-ctl] starting Apple control-channel receive loop")

        appleControlTask = Task(priority: taskPriority) {
            while !state.disconnectRequested,
                  connection.isReady {
                do {
                    // A read error here is a genuine connection/integrity failure (record SHA-1 mismatch,
                    // socket close) → fatal. Message DISPATCH is non-throwing and swallows per-message
                    // parse/decode errors so one malformed message never tears down the session.
                    let message = try await recordLayer.readControlMessage()
                    handleAppleControlMessage(message)
                } catch {
                    handleBreakingError(error)
                }
            }
        }
    }

    /// Dispatch one decrypted control message by its first byte (crib §7a). A `0x1f` clipboard send may
    /// span multiple records; continuation records carry no type byte, so while a reassembly is in
    /// progress any inbound record is fed to it. Non-throwing by design: a malformed/corrupt control
    /// message is logged and skipped, never propagated to the loop's breaking-error teardown (which would
    /// also kill the live UDP media stream sharing this HP session).
    func handleAppleControlMessage(_ message: Data) {
        if appleClipboardReassembly != nil {
            appleClipboardReassembly?.append(message)
            finishAppleClipboardSendIfComplete()
            return
        }

        guard let type = message.first else { return }

        switch type {
        case 0x00:   // FramebufferUpdate — pseudo-encoding rects only on the TCP control channel
            handleAppleControlFramebufferUpdate(message)

        case AppleClipboardCodec.msgMiscStatus:      // 0x14
            handleAppleControlMiscStatus(message)

        case AppleClipboardCodec.msgClipboardSend:   // 0x1f
            appleClipboardReassembly = message
            finishAppleClipboardSendIfComplete()

        default:
            // 0x02 Bell / 0x03 ServerCutText etc. are not sent by the HP daemon on this channel; log and
            // move on. Record-framing guarantees the next record is a fresh message, so this is safe.
            logger.logDebug("[hp-ctl] ignoring control message type=0x\(String(type, radix: 16)) len=\(message.count)")
        }
    }

    // MARK: - FramebufferUpdate (0x00) — pseudo-encoding rects

    /// Walk a control-channel `0x00` FramebufferUpdate in-memory (crib §7b). We consume cursor `1104`,
    /// display-layout `0x451`, and config blobs by their real length; rendering (cursor pixmap, geometry)
    /// is Phase 5. On a `0x451` we re-arm the daemon's free-running TCP sender so cursor/clipboard keep
    /// flowing across a display/session transition (crib §7d).
    private func handleAppleControlFramebufferUpdate(_ message: Data) {
        guard let walk = AppleControlChannelCodec.walkFramebufferUpdate(message) else { return }

        if walk.stoppedEarly {
            logger.logDebug("[hp-ctl] FBU walk stopped early (\(walk.parsedRects)/\(walk.declaredRects) rects) — record tail discarded, resyncing next record")
        }

        if let layout = walk.layout {
            logger.logDebug("[hp-ctl] AppleDisplayLayout scaled=\(layout.scaledWidth)x\(layout.scaledHeight) backing=\(layout.backingWidth)x\(layout.backingHeight)")
            enqueueAppleCursorRearm(backingWidth: layout.backingWidth, backingHeight: layout.backingHeight)
        }
    }

    /// Re-arm the daemon's free-running TCP update sender (crib §7d): AutoFrameBufferUpdate `0x09`
    /// (backing dims) + a non-incremental FramebufferUpdateRequest `0x03`. Enqueued (single-writer via
    /// the send queue). Falls back to the negotiated canvas, then full (`0xFFFF`), when backing dims are
    /// absent. Phase-5 note: a geometry CHANGE also needs a fresh `0x1c` media re-offer — deferred.
    private func enqueueAppleCursorRearm(backingWidth: Int, backingHeight: Int) {
        let w: UInt16
        let h: UInt16
        if backingWidth > 0, backingHeight > 0 {
            w = UInt16(truncatingIfNeeded: backingWidth)
            h = UInt16(truncatingIfNeeded: backingHeight)
        } else if let canvas = appleHPMediaContext?.canvas, canvas.width > 0, canvas.height > 0 {
            w = UInt16(truncatingIfNeeded: canvas.width)
            h = UInt16(truncatingIfNeeded: canvas.height)
        } else {
            w = 0xFFFF
            h = 0xFFFF
        }

        // AutoFrameBufferUpdate 0x09 (16 B fixed, crib §2b.5).
        var fbu09: [UInt8] = [0x09, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0]
        fbu09[12] = UInt8(w >> 8); fbu09[13] = UInt8(w & 0xFF)
        fbu09[14] = UInt8(h >> 8); fbu09[15] = UInt8(h & 0xFF)
        enqueueClientToServerMessage(VNCProtocol.AppleControlRawMessage(data: Data(fbu09)))

        // Non-incremental FramebufferUpdateRequest 0x03 (10 B, crib §2b.3): full region, incremental=0.
        let fbuRequest: [UInt8] = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]
        enqueueClientToServerMessage(VNCProtocol.AppleControlRawMessage(data: Data(fbuRequest)))

        logger.logDebug("[hp-ctl] re-armed TCP sender (0x09 + non-incremental FBU-req) at \(w)x\(h)")
    }

    // MARK: - MiscStatus (0x14)

    /// `0x14` MiscStatus (crib §7a). On `cmd=2` (remote clipboard changed) reply with a `0x0b` fetch;
    /// other commands (incl. the macOS-27 heartbeat) are ignored.
    private func handleAppleControlMiscStatus(_ message: Data) {
        guard AppleClipboardCodec.isRemoteClipboardChanged(message) else { return }
        guard settings.isClipboardRedirectionEnabled else { return }
        logger.logDebug("[hp-ctl] remote clipboard changed (0x14 cmd=2) — fetching (0x0b)")
        enqueueAppleClipboardFetch()
    }

    // MARK: - ClipboardSend (0x1f), reassembled across records

    /// If the accumulated `0x1f` buffer now holds the full message (`16 + compressedSize` bytes), decode
    /// the text and deliver it via the standard server-cut-text path, then clear the reassembler. Keeps
    /// accumulating otherwise. Reuses `AppleClipboardCodec` for header/decode (DRY).
    private func finishAppleClipboardSendIfComplete() {
        guard let accumulated = appleClipboardReassembly else { return }

        let full: Data
        do {
            guard let complete = try AppleClipboardCodec.completeClipboardSend(accumulated) else {
                return   // header not yet complete, or more continuation records needed
            }
            full = complete
        } catch {
            // Full-length header that doesn't parse as 0x1f — malformed; drop and resync.
            logger.logError("[hp-ctl] malformed 0x1f header; dropping clipboard reassembly")
            appleClipboardReassembly = nil
            return
        }

        appleClipboardReassembly = nil

        guard settings.enableHighPerformance, settings.isClipboardRedirectionEnabled else { return }

        // A decode failure (corrupt/truncated zlib, uncompressed-size mismatch) MUST NOT tear down the
        // session — the daemon can emit such payloads and the reference logs+continues. Swallow and
        // resync so the unified HP session (and its live UDP media) survives. Never log payload bytes
        // (NFR-6).
        do {
            if let text = try AppleClipboardCodec.decodeInboundText(full), !text.isEmpty {
                logger.logDebug("[hp-ctl] clipboard: received \(text.count) chars from host")
                // Same delivery path as standard ServerCutText: the app delegate is the sole pasteboard
                // writer (async on main, with echo-dedup) — T1 Change D.
                notifyDelegateAboutServerCutText(text)
            }
        } catch {
            logger.logError("[hp-ctl] clipboard decode failed; dropping payload, continuing")
        }
    }
}
