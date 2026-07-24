#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Apple HP media negotiation over the armed AES-128-CBC control record layer (HP-PHASE4-SPECS
/// §4.3 / crib §2b). Runs immediately after `performHighPerformanceControlBringUp` arms the record
/// layer: sends the `0x1c` MediaStreamConfiguration offer, reads the `0x1c` answer (a standard
/// FramebufferUpdate carrying an embedded bplist), and parses the negotiated canvas. HP-gated;
/// only reached on the `enableHighPerformance` path.
///
/// SRTP/UDP media receive is a follow-on step (needs a bound local 5900/5901 which collides with
/// the daemon's own ports on a loopback host — validated from a separate client host). The four
/// per-session SRTP master blobs are minted here and retained (`appleHPMediaContext`) for that step;
/// never logged (NFR-6).
extension VNCConnection {
    /// Per-session media negotiation state, retained for the SRTP/UDP receive step.
    struct AppleHPMediaContext {
        /// The four 46-byte SRTP master blobs (client-minted, crib §1d). `videoKeyS` (`vks`) decrypts
        /// inbound video; never logged.
        let audioKeyV: Data
        let audioKeyS: Data
        let videoKeyV: Data
        let videoKeyS: Data
        /// Our advertised send-SSRCs (harvested from the offer; safe to log).
        let videoSSRC: UInt32
        let audioSSRC: UInt32
        /// Negotiated canvas from the answer.
        var canvas: Apple0x1cAnswer.Canvas
    }

    /// Send the `0x1c` offer and read the answer canvas (crib §2b steps 2-5). Assumes SetEncodings
    /// (0x02) was already sent by the caller. Retries the offer on a degenerate `(0,0)` canvas up to
    /// the reference bound (crib §2b).
    func performHighPerformanceMediaOffer() async throws {
        let rnd = VNCProtocol.ARDRSASRPAuthentication.secureRandomBytes
        let akv = try rnd(Apple0x1cOffer.blobLen)
        let aks = try rnd(Apple0x1cOffer.blobLen)
        let vkv = try rnd(Apple0x1cOffer.blobLen)
        let vks = try rnd(Apple0x1cOffer.blobLen)

        let params = Apple0x1cOffer.Params(
            outerCallID: UUID(),
            audioKeyV: akv, audioKeyS: aks, videoKeyV: vkv, videoKeyS: vks,
            videoSessionID: try Self.random32(rnd), videoTimestamp: Self.nowNanos(),
            videoPlistCallID: UUID(),
            audioSessionID: try Self.random32(rnd), audioTimestamp: Self.nowNanos(),
            audioPlistCallID: UUID())

        let config = Apple0x1cOffer.Config(
            flags: .standard,
            blob: .init(),
            remoteEndpointInfo: AppleMediaBlobCodec.buildRemoteEndpointInfo(hwModel: "Mac", avcVersion: "1.0.0", osBuild: "0"))

        let offer = try Apple0x1cOffer.build(config: config, params: params)
        let ssrcs = Apple0x1cOffer.harvestSendSSRCs(offer: offer)
        logger.logDebug("[hp-media] built 0x1c offer (\(offer.count) B) videoSSRC=\(ssrcs?.video ?? 0) audioSSRC=\(ssrcs?.audio ?? 0)")

        // Send 0x1c offer, then the FramebufferUpdateRequest 0x03 (10 B) that wakes the daemon's
        // pseudo-encoding sender (crib §2b.2-3).
        try await connection.write(data: offer)
        try await connection.write(data: Data([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]))

        // Read + parse the answer canvas, with the degenerate-retry loop (crib §2b).
        var canvas = try await readMediaAnswer()
        var attempts = 0
        while !canvas.isReady, attempts < 16 {
            attempts += 1
            logger.logDebug("[hp-media] degenerate canvas, re-sending 0x1c (attempt \(attempts))")
            try await connection.write(data: offer)
            try await Task.sleep(nanoseconds: 200_000_000)   // _DEGENERATE_RETRY_INTERVAL_S = 0.2s
            canvas = try await readMediaAnswer()
        }

        logger.logDebug("[hp-media] answer canvas \(canvas.width)x\(canvas.height) tiles=\(canvas.tileCount) ltrp=\(canvas.ltrpEnabled) ready=\(canvas.isReady)")

        if canvas.isReady {
            // AutoFrameBufferUpdate 0x09 (16 B fixed, crib §2b.5) — sent only after a nonzero canvas.
            var fbu09: [UInt8] = [0x09, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0]
            let w = UInt16(truncatingIfNeeded: canvas.width)
            let h = UInt16(truncatingIfNeeded: canvas.height)
            fbu09[12] = UInt8(w >> 8); fbu09[13] = UInt8(w & 0xFF)
            fbu09[14] = UInt8(h >> 8); fbu09[15] = UInt8(h & 0xFF)
            try await connection.write(data: Data(fbu09))
            logger.logDebug("[hp-media] sent AutoFrameBufferUpdate 0x09 (\(canvas.width)x\(canvas.height))")
        }

        appleHPMediaContext = AppleHPMediaContext(
            audioKeyV: akv, audioKeyS: aks, videoKeyV: vkv, videoKeyS: vks,
            videoSSRC: ssrcs?.video ?? 0, audioSSRC: ssrcs?.audio ?? 0, canvas: canvas)
    }

    /// Accumulate decrypted plaintext off the record layer until an answer with a nonzero canvas is
    /// found (crib §2a: recv a batch, scan for the embedded bplist). Bounded to avoid spinning.
    private func readMediaAnswer() async throws -> Apple0x1cAnswer.Canvas {
        var buffer = Data()
        for _ in 0..<32 {
            let chunk = try await connection.read(minimumLength: 1, maximumLength: 65535)
            buffer.append(chunk)
            let canvas = Apple0x1cAnswer.parse(buffer)
            if canvas.isReady { return canvas }
            if buffer.count > 262_144 { break }   // 256 KiB safety cap
        }
        return Apple0x1cAnswer.parse(buffer)
    }

    private static func random32(_ rnd: (Int) throws -> Data) throws -> UInt32 {
        let b = [UInt8](try rnd(4))
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }

    private static func nowNanos() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
    }
}
