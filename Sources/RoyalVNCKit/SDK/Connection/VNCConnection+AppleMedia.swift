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

        // Bind the two UDP media sockets + start the NAT-prime loop BEFORE the offer (NFR-8): the
        // media burst lands ~100 ms after the answer, so the receivers must already be up.
        #if canImport(Network)
        let media = try startMediaReceive(videoKeyS: vks)
        defer { media?.cancel() }
        #endif

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

            // Observe the media stream: log decrypted RTP as it arrives (the Phase-4 "done" signal).
            #if canImport(Network)
            if let media {
                for _ in 0..<20 {
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                    logger.logDebug("[hp-media] rx: video-datagrams=\(media.stats.videoCount) decrypted-rtp=\(media.stats.decryptedCount) ctrl-datagrams=\(media.stats.ctrlCount)")
                }
            }
            #endif
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

#if canImport(Network)
extension VNCConnection {
    /// Thread-safe media receive counters (UDP callbacks arrive on the socket queues).
    final class MediaStats: @unchecked Sendable {
        private let lock = NSLock()
        private var _video = 0, _dec = 0, _ctrl = 0
        var videoCount: Int { lock.lock(); defer { lock.unlock() }; return _video }
        var decryptedCount: Int { lock.lock(); defer { lock.unlock() }; return _dec }
        var ctrlCount: Int { lock.lock(); defer { lock.unlock() }; return _ctrl }
        func addVideo() { lock.lock(); _video += 1; lock.unlock() }
        func addDecrypted() { lock.lock(); _dec += 1; lock.unlock() }
        func addCtrl() { lock.lock(); _ctrl += 1; lock.unlock() }
    }

    /// Owns the two UDP media sockets for the receive window.
    final class MediaReceiver {
        let stats = MediaStats()
        let videoUDP: AppleUDPDatagramConnection
        let ctrlUDP: AppleUDPDatagramConnection
        init(videoUDP: AppleUDPDatagramConnection, ctrlUDP: AppleUDPDatagramConnection) {
            self.videoUDP = videoUDP
            self.ctrlUDP = ctrlUDP
        }
        func cancel() { videoUDP.cancel(); ctrlUDP.cancel() }
    }

    /// Bind the video (5901) + ctrl (5900) UDP sockets, wire the video socket to SRTP-decrypt with
    /// `vks` and log decrypted RTP, and start the NAT-prime loop (crib §4a-§4e). Returns the receiver
    /// (kept alive for the observation window). Never logs key material (NFR-6); a ≤16-byte payload
    /// prefix is allowed (D5).
    func startMediaReceive(videoKeyS: Data) throws -> MediaReceiver? {
        let host = settings.hostname
        let ctrlPort = settings.port
        let videoPort = settings.port &+ 1

        let videoUDP = AppleUDPDatagramConnection(host: host, remotePort: videoPort, localPort: videoPort, label: "video")
        let ctrlUDP = AppleUDPDatagramConnection(host: host, remotePort: ctrlPort, localPort: ctrlPort, label: "ctrl")
        let receiver = MediaReceiver(videoUDP: videoUDP, ctrlUDP: ctrlUDP)
        let stats = receiver.stats
        let logger = self.logger

        let decryptor = try? AppleSRTPDecryptor(masterBlob: videoKeyS)
        if decryptor == nil { logger.logError("[hp-media] could not build SRTP decryptor from vks") }

        videoUDP.start(onDatagram: { data in
            stats.addVideo()
            guard let dec = decryptor, let (header, payload) = dec.decrypt(packet: data) else { return }
            stats.addDecrypted()
            let prefix = payload.prefix(16).map { String(format: "%02x", $0) }.joined()
            logger.logDebug("[hp-rtp] PT=\(header.payloadType) ssrc=\(header.ssrc) seq=\(header.sequenceNumber) ts=\(header.timestamp) marker=\(header.marker) len=\(payload.count) h[\(prefix)]")
        }, onState: { state in
            logger.logDebug("[hp-media] video UDP(\(videoPort)) state: \(String(describing: state))")
        })

        ctrlUDP.start(onDatagram: { _ in stats.addCtrl() }, onState: { state in
            logger.logDebug("[hp-media] ctrl UDP(\(ctrlPort)) state: \(String(describing: state))")
        })

        videoUDP.startNATPrime()
        ctrlUDP.startNATPrime()
        logger.logDebug("[hp-media] UDP bound video=\(videoPort) ctrl=\(ctrlPort) → host \(host); NAT-prime started")
        return receiver
    }
}
#endif
