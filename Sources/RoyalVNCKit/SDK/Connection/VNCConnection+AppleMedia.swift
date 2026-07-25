#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(VideoToolbox)
import VideoToolbox
import CoreVideo
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
        // media burst lands ~100 ms after the answer, so the receivers must already be up. The
        // receiver runs in the background (its own dispatch queues) and is retained on the connection
        // once negotiation succeeds; cancelled here only if negotiation fails.
        #if canImport(Network)
        let media = try startMediaReceive(videoKeyS: vks)
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

            // Retain the receiver for the life of the connection: video → SRTP decrypt → RTP log runs
            // in the background, and the RTCP keep-alive loop keeps AVConference streaming past ~30s.
            #if canImport(Network)
            if let media {
                media.startRTCPKeepAlive(videoKeyV: vkv, senderSSRC: ssrcs?.video ?? 0, logger: logger)
                #if canImport(VideoToolbox)
                media.onDecodedVideoFrame = appleHPDecodedVideoFrameHandler
                #endif
                appleHPMediaReceiver = media
            }
            #endif
        } else {
            #if canImport(Network)
            media?.cancel()   // negotiation never produced a canvas — don't leak sockets
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

    /// Owns the two UDP media sockets + the RTCP keep-alive loop for the life of the connection.
    final class MediaReceiver {
        let stats = MediaStats()
        let videoUDP: AppleUDPDatagramConnection
        let ctrlUDP: AppleUDPDatagramConnection
        private let rtcpQueue = DispatchQueue(label: "hp.rtcp.tx")
        private var rtcpTimer: DispatchSourceTimer?

        // HP HEVC decode pipeline (crib §8): assemble AUs by (ssrc,ts)+marker on the SOCKET queue, then hand
        // each complete AU to the drop-to-live decode stage (`decodeQueue`) which depays (DONL/AP/FU) + feeds
        // one shared VideoToolbox session. Ownership: `hevcAssembler` is socket-queue-only; `hevcDecoder` +
        // `hevcKnownSSRCs`/`tileIndex` + the frame/error counters are decodeQueue-only; `pendingAUs` is
        // `decodeLock`-guarded. Counters read cross-queue by the throttled log are benign (Int, log-only).
        var hevcAssembler = AppleHEVCAccessUnitAssembler()
        private var hevcKnownSSRCs: [UInt32] = []
        private(set) var hevcFramesDecoded = 0
        private var hevcLoggedFirstFrame = false
        private(set) var hevcDroppedGappedAUs = 0
#if canImport(VideoToolbox)
        let hevcDecoder = AppleHEVCDecoder(requireHardware: false)
        /// Set by the app (or a harness) to receive decoded frames — `(pixelBuffer, tileIndex)` — for
        /// Metal composite/render. Fires on `decodeQueue` (NOT the socket queue) in decode order; the app
        /// hop is thread-agnostic (it coalesces under its own lock).
        var onDecodedVideoFrame: ((CVPixelBuffer, UInt32) -> Void)?

        /// Drop-to-live decode decoupling. VideoToolbox decode (the expensive step) is moved OFF the socket
        /// queue onto `decodeQueue`, so the socket loop re-arms immediately after decrypt+assemble and drains
        /// UDP at line rate (no kernel-buffer backup → no loss/freeze). Only the NEWEST undecoded AU per tile
        /// (ssrc) is kept in `pendingAUs`; older ones are DROPPED before decode, so the stream stays live at
        /// whatever rate the decoder sustains instead of decoding every frame in slow motion. Dropping across
        /// a non-IDR boundary briefly breaks the HEVC reference chain; VideoToolbox conceals until the next
        /// IDR (legacy-FIR every 2s + tile-0 re-root). `decodeLock` guards `pendingAUs`/`decodeScheduled`.
        private let decodeQueue = DispatchQueue(label: "hp.hevc.decode")
        private let decodeLock = NSLock()
        private var pendingAUs: [UInt32: AppleHEVCAccessUnitAssembler.CompletedAccessUnit] = [:]
        private var decodeScheduled = false
        /// Count of AUs superseded (dropped) before decode to stay live — diagnostic only (decodeLock).
        private(set) var hevcDroppedLiveAUs = 0
#endif

        init(videoUDP: AppleUDPDatagramConnection, ctrlUDP: AppleUDPDatagramConnection) {
            self.videoUDP = videoUDP
            self.ctrlUDP = ctrlUDP
        }

        /// Assemble → depay → decode one decrypted video RTP packet (crib §8). Called on the video socket
        /// queue (single-threaded). A completed AU with a sequence gap is dropped after harvesting any
        /// parameter sets it carries (never feed a partial VCL AU — it wedges VideoToolbox).
        func handleDecryptedVideo(header: AppleRTPHeader, payload: Data, logger: VNCLogger) {
            guard let au = hevcAssembler.add(ssrc: header.ssrc, timestamp: header.timestamp,
                                             sequence: header.sequenceNumber, marker: header.marker,
                                             payload: payload) else { return }
#if canImport(VideoToolbox)
            // Assemble on the socket queue (cheap); decode off it, dropping stale AUs to stay live.
            enqueueForDecode(au)
#endif
        }

#if canImport(VideoToolbox)
        /// Hand a completed AU to `decodeQueue`, keeping only the newest per tile (drop-to-live). Returns
        /// on the socket queue immediately so the UDP receive loop re-arms without waiting on decode.
        private func enqueueForDecode(_ au: AppleHEVCAccessUnitAssembler.CompletedAccessUnit) {
            decodeLock.lock()
            if pendingAUs[au.ssrc] != nil { hevcDroppedLiveAUs += 1 }   // superseded an undecoded AU
            pendingAUs[au.ssrc] = au
            let schedule = !decodeScheduled
            if schedule { decodeScheduled = true }
            decodeLock.unlock()
            guard schedule else { return }
            decodeQueue.async { [weak self] in self?.drainDecode() }
        }

        /// Decode the newest pending AU per tile on `decodeQueue`. Older AUs were dropped by
        /// `enqueueForDecode` (drop-to-live), so decode always works on the freshest frame per tile and the
        /// picture stays current instead of playing every frame in slow motion. Gapped AUs harvest params
        /// only (never feed a partial VCL AU — it wedges VideoToolbox).
        private func drainDecode() {
            decodeLock.lock()
            let aus = pendingAUs
            pendingAUs.removeAll(keepingCapacity: true)
            decodeScheduled = false
            decodeLock.unlock()
            for ssrc in aus.keys.sorted() {
                guard let au = aus[ssrc] else { continue }
                let nals = AppleHEVCDepacketizer.depacketizeAccessUnit(au.orderedPayloads)
                let tile = tileIndex(for: au.ssrc)
                if au.hasGap {
                    hevcDroppedGappedAUs += 1
                    let params = nals.filter { (AppleHEVCDepacketizer.nalType($0)).map { !AppleHEVCDepacketizer.isVCL($0) } ?? false }
                    if !params.isEmpty { hevcDecoder.decode(nals: params, context: tile) }
                    continue
                }
                hevcDecoder.decode(nals: nals, context: tile)
            }
        }
#endif

        /// Per-SSRC tile index: sort observed SSRCs ascending; index = position (crib §2, matches the
        /// reference convention). NOTE: until all `tileCount` SSRCs have been seen, a lower SSRC observed
        /// after a higher one shifts earlier indices up by one — a self-healing startup transient (at most
        /// the first frame or two) that steady state resolves to the reference's fixed map. When the app
        /// compositor lands it should freeze the map once `canvas.tileCount` distinct SSRCs are observed
        /// (and buffer/drop the first partial composite) rather than trust provisional early indices.
        private func tileIndex(for ssrc: UInt32) -> UInt32 {
            if !hevcKnownSSRCs.contains(ssrc) {
                hevcKnownSSRCs.append(ssrc)
                hevcKnownSSRCs.sort()
            }
            return UInt32(hevcKnownSSRCs.firstIndex(of: ssrc) ?? 0)
        }

#if canImport(VideoToolbox)
        /// Wire the decoder's output/error callbacks (frame counting + first-frame log + forward to the
        /// app render hook). Call once before the video socket starts delivering.
        func startHEVCDecode(logger: VNCLogger) {
            hevcDecoder.onFrame = { [weak self] pixelBuffer, tile in
                guard let self else { return }
                self.hevcFramesDecoded += 1
                if !self.hevcLoggedFirstFrame {
                    self.hevcLoggedFirstFrame = true
                    let w = CVPixelBufferGetWidth(pixelBuffer)
                    let h = CVPixelBufferGetHeight(pixelBuffer)
                    let fmt = CVPixelBufferGetPixelFormatType(pixelBuffer)
                    let f = [UInt8((fmt >> 24) & 0xFF), UInt8((fmt >> 16) & 0xFF), UInt8((fmt >> 8) & 0xFF), UInt8(fmt & 0xFF)]
                    let fstr = String(bytes: f, encoding: .ascii) ?? String(fmt)
                    logger.logDebug("[hp-hevc] FIRST decoded frame \(w)x\(h) pixelFormat=\(fstr) hw=\(self.hevcDecoder.isHardwareAccelerated()) tile=\(tile)")
                }
                self.onDecodedVideoFrame?(pixelBuffer, tile)
            }
            var loggedError = false
            hevcDecoder.onDecodeError = { status in
                if !loggedError { loggedError = true; logger.logDebug("[hp-hevc] first decode error OSStatus \(status) (VT conceals; continuing)") }
            }
        }
#endif

        /// Start the 0.5 s RTCP TX keep-alive out the ctrl socket (crib §4g): SRTCP-protected empty RR
        /// each tick + empty SR every 5 s + a legacy-FIR (PT=192) periodically. Keeps AVConference
        /// from tearing the stream (~30 s otherwise). `senderSSRC` = our video send-SSRC.
        func startRTCPKeepAlive(videoKeyV: Data, senderSSRC: UInt32, logger: VNCLogger) {
            guard let protector = try? AppleSRTCPProtector(masterBlob: videoKeyV) else {
                logger.logError("[hp-media] could not build SRTCP protector from video_key_v; no RTCP keep-alive")
                return
            }
            let ctrl = ctrlUDP
            let timer = DispatchSource.makeTimerSource(queue: rtcpQueue)
            timer.schedule(deadline: .now() + 0.5, repeating: .milliseconds(500))
            var tick = 0
            timer.setEventHandler {
                tick += 1
                // Empty RR every tick (peers reject feedback not prefixed by SR/RR).
                if let rr = try? protector.protect(AppleRTCPBuilders.rrEmpty(sender: senderSSRC)) {
                    ctrl.send(rr)
                }
                // Empty SR every 10th tick (5 s) so AVConference accepts us as a live sender.
                if tick % 10 == 0 {
                    let sr = AppleRTCPBuilders.srEmpty(sender: senderSSRC, now: Date().timeIntervalSince1970)
                    if let p = try? protector.protect(sr) { ctrl.send(p) }
                }
                // Legacy-FIR (PT=192) every 2 s to keep the encoder producing.
                if tick % 4 == 0 {
                    if let fir = try? protector.protect(
                        AppleRTCPBuilders.compoundWithRR(sender: senderSSRC,
                                                         payload: AppleRTCPBuilders.firLegacy(target: senderSSRC))) {
                        ctrl.send(fir)
                    }
                }
            }
            rtcpTimer = timer
            timer.resume()
            logger.logDebug("[hp-media] RTCP keep-alive started (0.5s RR / 5s SR / 2s legacy-FIR) → ctrl \(ctrl.localPort)")
        }

        func cancel() {
            rtcpTimer?.cancel()
            rtcpTimer = nil
            videoUDP.cancel()
            ctrlUDP.cancel()
        }
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

#if canImport(VideoToolbox)
        receiver.startHEVCDecode(logger: logger)
#endif

        videoUDP.start(onDatagram: { [weak receiver] data in
            stats.addVideo()
            guard let dec = decryptor, let (header, payload) = dec.decrypt(packet: data) else { return }
            stats.addDecrypted()
            // Depay → decode (crib §8). Throttled summary instead of a per-packet line (avoids ~60k logs).
            receiver?.handleDecryptedVideo(header: header, payload: payload, logger: logger)
            if stats.decryptedCount % 1000 == 0 {
                logger.logDebug("[hp-rtp] decrypted=\(stats.decryptedCount) hevc-decoded=\(receiver?.hevcFramesDecoded ?? 0) droppedGappedAUs=\(receiver?.hevcDroppedGappedAUs ?? 0) droppedLiveAUs=\(receiver?.hevcDroppedLiveAUs ?? 0)")
            }
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
