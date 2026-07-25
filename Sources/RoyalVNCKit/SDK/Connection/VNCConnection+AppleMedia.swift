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

    /// TEMP-MEASUREMENT (removed after on-device verify): localizes the live throughput limiter. All calls
    /// happen on the single video *worker* queue (post-decouple) → no locking. One `[hp-prof]` line/wall-sec:
    ///  - busyFrac  = Σ(worker exit−entry)/wall  → worker-queue compute saturation (≈1.0 = compute-bound)
    ///  - decryptMs / decodeMs = mean per-packet SRTP-decrypt vs assemble+decode cost
    ///  - AU/s, pkts/AU, gappedAU/s
    ///  - speed = media-elapsed / wall-elapsed (RTP ts@90kHz vs wallclock; <1.0 = slow motion, = the slope)
    final class MediaProfiler {
        private let logger: VNCLogger
        private var winStartNs: UInt64 = 0
        private var busyNs: UInt64 = 0
        private var decryptNs: UInt64 = 0
        private var decodeNs: UInt64 = 0
        private var pkts = 0
        private var aus = 0
        private var gappedAus = 0
        // Drift reference: track one ssrc's AU timestamp span vs wallclock.
        private var refSSRC: UInt32?
        private var firstTs: UInt32 = 0
        private var lastTs: UInt32 = 0
        private var firstWallNs: UInt64 = 0
        private var lastWallNs: UInt64 = 0

        init(logger: VNCLogger) { self.logger = logger }

        private static func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

        /// Record one datagram's timing. `decryptNs`/`decodeNs` are the sub-costs inside `busyNs`.
        func recordPacket(busyNs b: UInt64, decryptNs d: UInt64, decodeNs c: UInt64) {
            let t = Self.now()
            if winStartNs == 0 { winStartNs = t }
            busyNs += b; decryptNs += d; decodeNs += c; pkts += 1
            let elapsed = t - winStartNs
            if elapsed >= 1_000_000_000 {
                let wallS = Double(elapsed) / 1e9
                let busyFrac = Double(busyNs) / Double(elapsed)
                let decMs = pkts > 0 ? Double(decryptNs) / Double(pkts) / 1e6 : 0
                let codMs = aus > 0 ? Double(decodeNs) / Double(aus) / 1e6 : 0
                let auRate = Double(aus) / wallS
                let pktsPerAU = aus > 0 ? Double(pkts) / Double(aus) : 0
                var speed = 0.0
                if lastWallNs > firstWallNs {
                    let mediaS = Double(lastTs &- firstTs) / 90_000.0
                    let driftWallS = Double(lastWallNs - firstWallNs) / 1e9
                    if driftWallS > 0 { speed = mediaS / driftWallS }
                }
                logger.logDebug(String(format: "[hp-prof] busyFrac=%.2f decryptMs=%.3f decodeMs=%.3f AU/s=%.1f pktsPerAU=%.1f gappedAU/s=%.1f speed=%.3f pkts=%d",
                                        busyFrac, decMs, codMs, auRate, pktsPerAU, Double(gappedAus) / wallS, speed, pkts))
                winStartNs = t; busyNs = 0; decryptNs = 0; decodeNs = 0; pkts = 0; aus = 0; gappedAus = 0
            }
        }

        /// Record a completed AU (for AU/s + drift). Called from `handleDecryptedVideo`.
        func recordAU(ssrc: UInt32, timestamp: UInt32, hasGap: Bool) {
            aus += 1
            if hasGap { gappedAus += 1 }
            if refSSRC == nil { refSSRC = ssrc }
            guard ssrc == refSSRC else { return }
            let t = Self.now()
            if firstWallNs == 0 { firstWallNs = t; firstTs = timestamp }
            lastWallNs = t; lastTs = timestamp
        }
    }

    /// TEMP-MEASUREMENT (removed after diagnosis): runs on the video SOCKET queue in `onDatagram`, BEFORE
    /// the worker handoff, so it measures true INGRESS (what the kernel delivered) independent of the worker.
    /// SRTP leaves the RTP header in clear → read seq/ssrc with zero decrypt. One `[hp-ingress]` line/sec:
    ///  - recv/s + per-SSRC recv/gap-events/missing  → wire-loss vs server-under-send (tile starvation)
    ///  - cbAvgMs/cbMaxMs = socket re-arm cadence; a spike = the serial receive stalled → kernel may drop
    ///  - postGapMaxMs = inter-arrival of the packet AFTER a gap (large pause ⇒ wire; tight ⇒ our-side)
    /// Disambiguation: gaps with normal timing + no cadence spike ⇒ WIRE loss; gaps clustered after cadence
    /// spikes ⇒ RECEIVE-BUFFER overflow. Single-threaded on the socket queue → no locking.
    final class IngressProbe {
        private let logger: VNCLogger
        private var winStartNs: UInt64 = 0
        private var lastCallbackNs: UInt64 = 0
        private var lastPacketNs: UInt64 = 0
        private var callbacks = 0
        private var cbGapSumNs: UInt64 = 0
        private var cbMaxGapNs: UInt64 = 0
        private var postGapMaxMs: Double = 0
        private var expectedNext: [UInt32: UInt16] = [:]
        private var recv: [UInt32: Int] = [:]
        private var gapEvents: [UInt32: Int] = [:]
        private var missing: [UInt32: Int] = [:]

        init(logger: VNCLogger) { self.logger = logger }
        private static func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

        func record(datagram data: Data) {
            let now = Self.now()
            if winStartNs == 0 { winStartNs = now; lastCallbackNs = now; lastPacketNs = now }
            let cbGap = now &- lastCallbackNs
            cbGapSumNs &+= cbGap; if cbGap > cbMaxGapNs { cbMaxGapNs = cbGap }; callbacks += 1
            lastCallbackNs = now
            if data.count >= 12 {
                let b = [UInt8](data.prefix(12))
                let seq = UInt16(b[2]) << 8 | UInt16(b[3])
                let ssrc = UInt32(b[8]) << 24 | UInt32(b[9]) << 16 | UInt32(b[10]) << 8 | UInt32(b[11])
                recv[ssrc, default: 0] += 1
                if let exp = expectedNext[ssrc], seq != exp {
                    let miss = Int(seq &- exp)   // wraparound-aware; ignore reorder/dup (huge deltas)
                    if miss > 0 && miss < 30000 {
                        gapEvents[ssrc, default: 0] += 1
                        missing[ssrc, default: 0] += miss
                        let iaMs = Double(now &- lastPacketNs) / 1e6
                        if iaMs > postGapMaxMs { postGapMaxMs = iaMs }
                    }
                }
                expectedNext[ssrc] = seq &+ 1
            }
            lastPacketNs = now
            let elapsed = now &- winStartNs
            if elapsed >= 1_000_000_000 {
                let wallS = Double(elapsed) / 1e9
                let cbAvgMs = callbacks > 0 ? Double(cbGapSumNs) / Double(callbacks) / 1e6 : 0
                let parts = recv.keys.sorted().map {
                    "\($0 & 0xFFFF):r\(recv[$0] ?? 0)g\(gapEvents[$0] ?? 0)m\(missing[$0] ?? 0)"
                }.joined(separator: " ")
                logger.logDebug(String(format: "[hp-ingress] recv/s=%.0f cbAvgMs=%.2f cbMaxMs=%.1f postGapMaxMs=%.1f [%@]",
                                        Double(callbacks) / wallS, cbAvgMs, Double(cbMaxGapNs) / 1e6, postGapMaxMs, parts))
                winStartNs = now; callbacks = 0; cbGapSumNs = 0; cbMaxGapNs = 0; postGapMaxMs = 0
                recv.removeAll(keepingCapacity: true); gapEvents.removeAll(keepingCapacity: true); missing.removeAll(keepingCapacity: true)
            }
        }
    }

    /// Owns the two UDP media sockets + the RTCP keep-alive loop for the life of the connection.
    final class MediaReceiver {
        let stats = MediaStats()
        /// TEMP-MEASUREMENT (not for commit).
        var profiler: MediaProfiler?
        /// TEMP-MEASUREMENT: ingress probe on the socket queue (set in `startMediaReceive`).
        var ingressProbe: IngressProbe?
        /// TEMP-MEASUREMENT: last FIR send time (stamped on rtcpQueue at both FIR sites), read on the worker
        /// to log FIR→IDR recovery latency. Benign cross-thread read of a diagnostic timestamp.
        var firSentNs: UInt64 = 0
        let videoUDP: AppleUDPDatagramConnection
        let ctrlUDP: AppleUDPDatagramConnection
        private let rtcpQueue = DispatchQueue(label: "hp.rtcp.tx")
        private var rtcpTimer: DispatchSourceTimer?

        /// Serial worker that runs decrypt→assemble→(async)decode OFF the UDP socket queue so the socket can
        /// re-arm `receiveMessage` immediately and drain at line rate. The synchronous pipeline on the socket
        /// queue was the throughput ceiling on A18 (per-frame HW-decode wait blocked UDP intake → kernel
        /// backlog → unbounded latency = slow motion → overflow). FIFO → packet/AU/decode order preserved.
        /// No drop (sparse-IDR stream: dropping any non-IDR AU breaks the cross-tile reference chain).
        private let videoWorkQueue = DispatchQueue(label: "hp.media.video.decode")
        /// SRTP receive-decryptor for the video stream (per-SSRC ROC state; touched only on videoWorkQueue).
        var srtpDecryptor: AppleSRTPDecryptor?

        /// SRTCP protector + our sender SSRC for on-demand FIR (fast keyframe re-request on packet loss).
        /// Set once when the keep-alive starts; the protector's SRTCP index is mutated only on `rtcpQueue`
        /// (both the keep-alive timer and the on-demand FIR dispatch to it → serialized).
        private var rtcpProtector: AppleSRTCPProtector?
        private var rtcpSenderSSRC: UInt32 = 0
        private var lastLossFirNs: UInt64 = 0   // rate-limit (video worker queue only)

        // HP HEVC decode pipeline (crib §8): assemble AUs by (ssrc,ts) + marker, depay (DONL/AP/FU), feed
        // one shared VideoToolbox session. All touched only on the video socket queue → no locking.
        var hevcAssembler = AppleHEVCAccessUnitAssembler()
        private var hevcKnownSSRCs: [UInt32] = []
        private(set) var hevcFramesDecoded = 0
        private var hevcLoggedFirstFrame = false
        private(set) var hevcDroppedGappedAUs = 0
#if canImport(VideoToolbox)
        let hevcDecoder = AppleHEVCDecoder(requireHardware: false)
        /// Set by the app (or a harness) to receive decoded frames — `(pixelBuffer, tileIndex)` — for
        /// Metal composite/render. Fires on the video socket queue in decode order.
        var onDecodedVideoFrame: ((CVPixelBuffer, UInt32) -> Void)?
#endif

        init(videoUDP: AppleUDPDatagramConnection, ctrlUDP: AppleUDPDatagramConnection) {
            self.videoUDP = videoUDP
            self.ctrlUDP = ctrlUDP
        }

        /// Hand one raw video datagram to the serial worker: decrypt → assemble → (async) decode. Returns
        /// immediately so the UDP socket queue re-arms `receiveMessage` at once (drains at line rate). The
        /// worker is FIFO so per-SSRC ROC / AU assembly / decode order are preserved. No drop.
        func enqueueVideoDatagram(_ data: Data, logger: VNCLogger) {
            videoWorkQueue.async { [weak self] in
                guard let self else { return }
                let t0 = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                self.stats.addVideo()
                guard let dec = self.srtpDecryptor, let (header, payload) = dec.decrypt(packet: data) else {
                    let te = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                    self.profiler?.recordPacket(busyNs: te - t0, decryptNs: te - t0, decodeNs: 0)
                    return
                }
                let tDec = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                self.stats.addDecrypted()
                self.handleDecryptedVideo(header: header, payload: payload, logger: logger)
                let t1 = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                self.profiler?.recordPacket(busyNs: t1 - t0, decryptNs: tDec - t0, decodeNs: t1 - tDec)
                if self.stats.decryptedCount % 1000 == 0 {
                    logger.logDebug("[hp-rtp] decrypted=\(self.stats.decryptedCount) hevc-decoded=\(self.hevcFramesDecoded) droppedGappedAUs=\(self.hevcDroppedGappedAUs)")
                }
            }
        }

        /// Assemble → depay → decode one decrypted video RTP packet (crib §8). Called on the video worker
        /// queue (single-threaded). A completed AU with a sequence gap is dropped after harvesting any
        /// parameter sets it carries (never feed a partial VCL AU — it wedges VideoToolbox).
        func handleDecryptedVideo(header: AppleRTPHeader, payload: Data, logger: VNCLogger) {
            guard let au = hevcAssembler.add(ssrc: header.ssrc, timestamp: header.timestamp,
                                             sequence: header.sequenceNumber, marker: header.marker,
                                             payload: payload) else { return }
            profiler?.recordAU(ssrc: au.ssrc, timestamp: au.timestamp, hasGap: au.hasGap)   // TEMP-MEASUREMENT
#if canImport(VideoToolbox)
            let nals = AppleHEVCDepacketizer.depacketizeAccessUnit(au.orderedPayloads)
            let tile = tileIndex(for: au.ssrc)
            // TEMP-MEASUREMENT: FIR→IDR recovery latency. Log when an IRAP (IDR/CRA/BLA, NAL types 16-23)
            // AU arrives, incl. whether that recovery IDR itself came in gapped (→ FIR-loop failure mode).
            if nals.contains(where: { AppleHEVCDepacketizer.nalType($0).map { (16...23).contains($0) } ?? false }) {
                let fs = firSentNs
                let sinceFirMs = fs > 0 ? Double(DispatchTime.now().uptimeNanoseconds &- fs) / 1e6 : -1
                logger.logDebug(String(format: "[hp-idr] IRAP tile=%d hasGap=%@ sinceFIRms=%.0f", Int(tile), au.hasGap ? "Y" : "N", sinceFirMs))
            }
            if au.hasGap {
                hevcDroppedGappedAUs += 1
                // A dropped (gapped) AU breaks the HEVC reference chain → VT conceals every subsequent
                // inter-coded AU until a clean IDR. Request an intra refresh NOW rather than waiting up to
                // 2 s for the periodic keep-alive FIR (rate-limited inside).
                requestKeyframeOnLoss()
                let params = nals.filter { (AppleHEVCDepacketizer.nalType($0)).map { !AppleHEVCDepacketizer.isVCL($0) } ?? false }
                if !params.isEmpty { hevcDecoder.decode(nals: params, context: tile) }
                return
            }
            hevcDecoder.decode(nals: nals, context: tile)
#endif
        }

        /// Send an immediate legacy-FIR (PT=192) to re-root the encoder after packet loss broke the HEVC
        /// reference chain, instead of waiting for the ≤2 s periodic keep-alive FIR. Rate-limited to ≤~4/s
        /// so a lossy link can't provoke an IDR storm (each IDR is large → more bytes → more loss). Called
        /// on the video worker queue; the actual SRTCP protect+send is dispatched to `rtcpQueue` so the
        /// protector's index stays serialized with the keep-alive timer. Backstopped by the periodic FIR.
        func requestKeyframeOnLoss() {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now &- lastLossFirNs > 250_000_000 else { return }
            lastLossFirNs = now
            firSentNs = now   // TEMP-MEASUREMENT: stamp FIR-send for FIR→IDR latency
            guard let protector = rtcpProtector else { return }   // keep-alive not up yet → periodic FIR covers it
            let ssrc = rtcpSenderSSRC
            let ctrl = ctrlUDP
            rtcpQueue.async {
                if let fir = try? protector.protect(
                    AppleRTCPBuilders.compoundWithRR(sender: ssrc,
                                                     payload: AppleRTCPBuilders.firLegacy(target: ssrc))) {
                    ctrl.send(fir)
                }
            }
        }

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
            // Share the protector + sender SSRC with the on-demand loss-recovery FIR (both send via rtcpQueue).
            self.rtcpProtector = protector
            self.rtcpSenderSSRC = senderSSRC
            let ctrl = ctrlUDP
            let timer = DispatchSource.makeTimerSource(queue: rtcpQueue)
            timer.schedule(deadline: .now() + 0.5, repeating: .milliseconds(500))
            var tick = 0
            timer.setEventHandler { [weak self] in
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
                        self?.firSentNs = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
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
        receiver.profiler = MediaProfiler(logger: logger)   // TEMP-MEASUREMENT
        receiver.ingressProbe = IngressProbe(logger: logger)   // TEMP-MEASUREMENT

        let decryptor = try? AppleSRTPDecryptor(masterBlob: videoKeyS)
        if decryptor == nil { logger.logError("[hp-media] could not build SRTP decryptor from vks") }
        receiver.srtpDecryptor = decryptor

#if canImport(VideoToolbox)
        receiver.startHEVCDecode(logger: logger)
#endif

        // Socket-queue callback is now trivial: hand the raw datagram to the serial worker and return so
        // `receiveMessage` re-arms immediately (drains UDP at line rate). All decrypt/assemble/decode work
        // — and the throttled [hp-rtp] summary — runs on the worker (see `enqueueVideoDatagram`).
        videoUDP.start(onDatagram: { [weak receiver] data in
            receiver?.ingressProbe?.record(datagram: data)   // TEMP-MEASUREMENT (socket queue, pre-worker)
            receiver?.enqueueVideoDatagram(data, logger: logger)
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
