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

        // tilesPerFrame=4: Apple's NATIVE/default offer (the reference documents 4 tiles). This is the
        // 1-char revert point — flip back to `1` for a single-tile A/B. The 4-tile offer is what re-arms
        // the negotiated LTR handshake: single-tile Apple RTP carries NO 16-bit DONL, so `ltrp=1` is inert
        // (no per-frame id to ACK) and on loss we fall back to fragile full-IDR recovery → the 1–3.4 s FMV
        // freeze. 4 tiles restore the DONL, so a cleanly-decoded tile-0 frame can be ACKed (PT204 LTR-ACK on
        // the video socket, chain-clean-gated) and the encoder re-roots from a small P-delta LTR instead of
        // a full IDR. screensharingd honors the 4-SSRC offer natively. (AppleMediaBlobCodec.Config already
        // defaults tilesPerFrame:4/codec:.both/ltrpEnabled:true — blob fields 2 & 7 carry the LTRP flag.)
        let config = Apple0x1cOffer.Config(
            flags: .standard,
            blob: .init(tilesPerFrame: 4),
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
        //
        // TIMED: this loop is the main suspect whenever an HP connect (especially one that asked for a
        // `0x1d` virtual display) feels slow — the host has to create the display before it can answer with
        // a usable canvas, so the early answers come back degenerate and we spin here. Each iteration costs
        // a 0.2s sleep plus however long the answer read blocks, up to 16 times, and if it never converges
        // the connection is failed on purpose (see the fail-fast below) and the caller reconnects without
        // the request — i.e. the whole handshake is paid twice. Per-attempt + total timings distinguish
        // "slow but converged" from "exhausted and retried", which need different fixes.
        let negotiationStart = Date()
        var (canvas, layout) = try await readMediaAnswer()
        logger.logDebug("[hp-media] first answer read in \(Self.hpElapsedMs(since: negotiationStart))ms (ready=\(canvas.isReady), layout=\(layout.map { "\($0.backingWidth)x\($0.backingHeight)" } ?? "none"))")
        var attempts = 0
        while !canvas.isReady, layout == nil, attempts < 16 {
            attempts += 1
            let attemptStart = Date()
            logger.logDebug("[hp-media] degenerate canvas, re-sending 0x1c (attempt \(attempts))")
            try await connection.write(data: offer)
            try await Task.sleep(nanoseconds: 200_000_000)   // _DEGENERATE_RETRY_INTERVAL_S = 0.2s
            (canvas, layout) = try await readMediaAnswer()
            logger.logDebug("[hp-media] attempt \(attempts) took \(Self.hpElapsedMs(since: attemptStart))ms (ready=\(canvas.isReady), \(Self.hpElapsedMs(since: negotiationStart))ms cumulative)")
        }

        // No canvas in the answer, but the daemon told us the geometry in a `0x451` — either during this
        // read or back in the pre-rekey burst. Use it: that IS the encoder's output size, and it is the only
        // geometry a virtual-display connect gets.
        if !canvas.isReady, let announced = layout ?? appleHPPendingLayout {
            let derived = Self.canvasFromLayout(announced,
                                                offeredTileCount: config.blob.tilesPerFrame,
                                                offeredLTRP: true)
            if derived.isReady {
                canvas = derived
                logger.logDebug("[hp-vdisp] no 0x1c answer canvas — taking geometry from the 0x451 layout: \(canvas.width)x\(canvas.height) (scaled \(announced.scaledWidth)x\(announced.scaledHeight), tiles=\(canvas.tileCount) from our offer)")
            }
        }
        appleHPPendingLayout = nil

        logger.logDebug("[hp-media] answer canvas \(canvas.width)x\(canvas.height) tiles=\(canvas.tileCount) ltrp=\(canvas.ltrpEnabled) ready=\(canvas.isReady) — negotiated in \(Self.hpElapsedMs(since: negotiationStart))ms after \(attempts) retries")

        // Geometry note: the canvas can legitimately differ from ServerInit (which describes the host's
        // PHYSICAL display and was read before this negotiation). The framebuffer is created AFTER this call
        // returns and takes its size from this canvas, so the difference is expected and handled — logged
        // because it is the single most useful line for explaining a wrong-looking picture.
        if canvas.isReady {
            let fbW = Int(state.framebufferWidth), fbH = Int(state.framebufferHeight)
            if fbW > 0, fbH > 0, fbW != Int(canvas.width) || fbH != Int(canvas.height) {
                logger.logDebug("[hp-geom] canvas \(canvas.width)x\(canvas.height) differs from ServerInit \(fbW)x\(fbH) (virtual display) — framebuffer will follow the canvas")
            }
        }

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
                // Bound the SSRC→tile map to the negotiated geometry (guards mid-session SSRC-group rotation,
                // which the reference observes right after a 0x1d virtual display is created).
                if canvas.tileCount > 0 { media.expectedTileCount = Int(canvas.tileCount) }
                // Must be set BEFORE the keep-alive timer starts — that timer is the only reader.
                media.tmmbrBitsPerSecond = settings.highPerformanceRequestedBitrate
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

        // FAIL FAST when a requested virtual display produced no canvas.
        //
        // Without this the session stays "connected" with the media sockets torn down: the client shows a
        // connected-but-blank screen while the HOST IS CURTAINED — its physical screen is blank and the only
        // tool that could see it just silently gave up. That is the worst possible failure for a machine the
        // user may not be sitting at. Throwing tears the connection down, which drops the daemon's virtual
        // display and lifts the curtain, and lets the caller retry WITHOUT the request (the app suppresses it
        // for one connect). Only applies when WE asked for the virtual display; the plain HP path is
        // unchanged (a degenerate canvas there is the pre-existing, non-curtaining behaviour).
        if !canvas.isReady, settings.highPerformanceDisplay != nil {
            logger.logError("[hp-vdisp] virtual display was requested but the host produced NEITHER a 0x1c answer canvas NOR a 0x451 layout after \(attempts) retries / \(Self.hpElapsedMs(since: negotiationStart))ms — failing the connection so the curtain lifts instead of leaving a blank, curtained host (the caller's next connect omits the request, so this whole handshake is about to be paid again)")
            throw VNCError.protocol(.invalidData)
        }
    }

    /// Accumulate decrypted plaintext off the record layer until an answer with a nonzero canvas is
    /// found (crib §2a: recv a batch, scan for the embedded bplist). Bounded to avoid spinning.
    ///
    /// ALSO stops on a `0x451` AppleDisplayLayout. A virtual-display (`0x1d`) connect does not behave like
    /// the plain HP path: the daemon announces the new geometry with a `0x451` and starts streaming video
    /// immediately, and no `0x1c` answer with a canvas follows on TCP — so waiting only for a bplist canvas
    /// blocks here forever (device-observed: video decoding at full rate while negotiation never returned,
    /// leaving the decoded-frame handler unwired and the framebuffer stuck at the ServerInit size). The
    /// layout is the geometry, so treat it as an answer. Chunk sizes are logged (bounded) because if this
    /// ever stalls again, "did any plaintext arrive at all" is the first thing to know.
    private func readMediaAnswer() async throws -> (canvas: Apple0x1cAnswer.Canvas, layout: AppleControlChannelCodec.LayoutInfo?) {
        var buffer = Data()
        for readIndex in 0..<32 {
            let chunk = try await connection.read(minimumLength: 1, maximumLength: 65535)
            buffer.append(chunk)
            if readIndex < 4 {
                logger.logDebug("[hp-media] answer read #\(readIndex + 1): +\(chunk.count)B (buffer \(buffer.count)B)")
            }

            let canvas = Apple0x1cAnswer.parse(buffer)
            if canvas.isReady { return (canvas, AppleControlChannelCodec.scanForDisplayLayout(buffer)) }

            if let layout = AppleControlChannelCodec.scanForDisplayLayout(buffer) {
                return (canvas, layout)
            }

            if buffer.count > 262_144 { break }   // 256 KiB safety cap
        }
        return (Apple0x1cAnswer.parse(buffer), AppleControlChannelCodec.scanForDisplayLayout(buffer))
    }

    /// The canvas implied by a `0x451` layout, for the virtual-display case where no `0x1c` answer canvas
    /// arrives. `backingWidth/Height` are the encoder's real output — the same numbers the answer's
    /// `sub4/sub5` would have carried — so they size the framebuffer. `tileCount`/`ltrpEnabled` are not in
    /// the layout, so they are taken from what we OFFERED (the daemon honours the 4-tile offer natively);
    /// the tile count is re-derived from the stream anyway once frames arrive.
    static func canvasFromLayout(_ layout: AppleControlChannelCodec.LayoutInfo,
                                 offeredTileCount: Int,
                                 offeredLTRP: Bool) -> Apple0x1cAnswer.Canvas {
        Apple0x1cAnswer.Canvas(width: UInt32(max(0, layout.backingWidth)),
                               height: UInt32(max(0, layout.backingHeight)),
                               tileCount: UInt32(max(0, offeredTileCount)),
                               ltrpEnabled: offeredLTRP)
    }

    private static func random32(_ rnd: (Int) throws -> Data) throws -> UInt32 {
        let b = [UInt8](try rnd(4))
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }

    private static func nowNanos() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
    }

    /// Whole milliseconds elapsed since `start`, for the HP connect-stage timing logs. Clamped at 0 —
    /// `Date` is wall-clock, so a clock adjustment mid-connect must not print a negative duration.
    static func hpElapsedMs(since start: Date) -> Int {
        max(0, Int((-start.timeIntervalSinceNow * 1000).rounded()))
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
        var rawDiagCount = 0   // TEMP: single-tile out-of-band param location
        /// Video RX uses a raw SOCK_DGRAM socket (large SO_RCVBUF, dedicated recv thread) — NWConnection's
        /// UDP receive stalls ~200-300ms on device and drops the high-bitrate tiles (measured). Ctrl (RTCP
        /// TX + low RX) stays on NWConnection.
        let videoUDP: AppleRawUDPDatagramConnection
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
        /// Retained for the teardown [hp-ab] summary (set when the keep-alive starts).
        private var diagLogger: VNCLogger?

        // HP HEVC decode pipeline (crib §8): assemble AUs by (ssrc,ts) + marker, depay (DONL/AP/FU), feed
        // one shared VideoToolbox session. All touched only on the video socket queue → no locking.
        var hevcAssembler = AppleHEVCAccessUnitAssembler()
        /// Whether Apple's 16-bit DONL is present in this stream's RTP payloads. Present on 4-tile streams,
        /// ABSENT on single-tile (tilesPerFrame=1). Auto-detected from the parameter-set Aggregation Packet;
        /// defaults to true (4-tile behavior) until an AP is seen. Getting it wrong drops params / corrupts FUs.
        private var hevcDONL = true
        /// SSRC→tile map (pure value type, unit-tested; see `AppleTileMap`). Touched only on the video worker
        /// queue. Handles SSRC-group rotation and DROPS an SSRC that has no tile slot rather than aliasing it
        /// onto an occupied tile.
        private var tileMap = AppleTileMap()
        /// Tiles the negotiated canvas says to expect (set from the `0x1c` answer). Bounds the SSRC→tile map so
        /// a mid-session SSRC-group rotation can't inflate tile indices past the geometry. Defaults to the
        /// 4-tile offer we send.
        var expectedTileCount = 4
        /// Bitrate (bits/s) to request from the host via periodic RTCP TMMBR; `0` sends none. Set from
        /// `Settings.highPerformanceRequestedBitrate` when negotiation completes — see the TMMBR probe note in
        /// `startRTCPKeepAlive`. Written once before the keep-alive timer starts, read only on `rtcpQueue`.
        var tmmbrBitsPerSecond: UInt64 = 0
        /// AUs dropped because their SSRC had no tile slot. Non-zero means an extra SSRC group is live.
        var ssrcUnmappedDrops: Int { tileMap.unmappedDrops }
        /// TEMP-MEASUREMENT ([hp-tile]): per-SSRC set of HEVC NAL types EVER seen — decisive for tile
        /// independence. If every tile carries its own SPS(33)+IDR(19/20), the 4 streams are independent
        /// (→ 4 parallel VTDecompressionSessions viable). If only tile-0 carries SPS/IDR, tiles 1-3
        /// cross-reference tile-0 (shared DPB → cannot split). Logged when a tile's type-set grows.
        private var splitWinStartNs: UInt64 = 0   // TEMP-MEASUREMENT [hp-split] window
        private var tileTypeSets: [UInt32: Set<Int>] = [:]
        private var tileIRAPCounts: [UInt32: Int] = [:]
        private(set) var hevcFramesDecoded = 0
        private var hevcLoggedFirstFrame = false
        private(set) var hevcDroppedGappedAUs = 0

        // MARK: - LTR (long-term reference) recovery — the FMV-freeze fix

        /// Per-tile chain-clean gate (§1.3b). Touched ONLY on the video worker queue (same queue as
        /// `handleDecryptedVideo`/`onFrame`), so no locking. `chainClean[tile] == true` means that tile's
        /// decoder chain descends from an intact, re-rooted IRAP with no gap since — the ONLY state in which
        /// it is safe to ACK an LTR. VideoToolbox conceals a broken chain with `status == noErr` (advancing
        /// DONL), so `onFrame` firing is NOT a clean-decode signal on its own; ACKing a concealed frame would
        /// poison the server's LTR ring (re-root from a frame we never cleanly decoded → persistent
        /// corruption, worse than the freeze). We ACK tile-0 DONLs only while `chainClean[0] == true`.
        private var chainClean: [UInt32: Bool] = [:]
        /// ACKs suppressed because the chain was not clean (video worker queue; benign racy read on rtcpQueue
        /// for the [hp-ltr] line — monotonic Int).
        private var ltrGateSkips = 0

        /// LTR-ACK egress state — touched ONLY on `rtcpQueue` (serialized with the keep-alive/FIR sends so
        /// the shared SRTCP protector's monotonic index stays coherent). `lastAckedDONL` deduped on `!=`
        /// (not `>`) so ACKs resume after the ~18-min 16-bit DONL wrap.
        private var lastAckedDONL: UInt16?
        private var ltrAckCount = 0
        private var ltrDupSuppressed = 0
        private var ltrWinStartNs: UInt64 = 0
        private var ltrLoggedFirst = false
        private var ltrPrevID: UInt32 = 0
        private var ltrLastID: UInt32 = 0

        // MARK: - Freeze/stall diagnostics ([hp-stall] / [hp-idr] / [hp-ab] / queue depth)

        /// Decoded-output flatline detection (video worker queue only). A gap ≥ 500 ms between decoded
        /// frames (any tile) = a freeze; on the resuming frame we emit one [hp-stall] line with the deltas
        /// accumulated over the flatline window (snapshots taken at each decoded output).
        private var lastDecodedOutputNs: UInt64 = 0
        private var snapGappedAU = 0
        private var snapFir = 0
        private var snapLtrAck = 0
        private var irapSinceLastOutput = false
        private var firCount = 0                 // incremented in requestKeyframeOnLoss (worker queue)
        private var ltrAcksRequested = 0         // LTR-ACKs dispatched from onFrame (worker queue; for [hp-stall])
        private var lastIRAPNs: UInt64 = 0        // [hp-idr] cadence (worker queue)
        private var irapCount = 0

        /// Cross-queue diagnostic rollup — guarded by `diagLock` (recv thread bumps queue depth; the video
        /// worker bumps freeze/IRAP/gapped; `rtcpQueue` bumps LTR-ACK; the rtcp timer reads/resets at 10 s).
        private let diagLock = NSLock()
        private var pendingDatagrams = 0
        private var qDepthMax = 0
        private var qAgeMaxMs: Double = 0
        private var abWinStartNs: UInt64 = 0
        private var abFreezeAccumMs: Double = 0
        private var abFlatlines = 0
        private var abMaxFlatlineMs: Double = 0
        private var abIrap = 0
        private var abLtrAck = 0
        private var abGappedAU = 0
        private var abQDepthMax = 0   // max worker-queue depth within the 10 s AB window ([hp-rtp] resets its own)
#if canImport(VideoToolbox)
        let hevcDecoder = AppleHEVCDecoder(requireHardware: false)
        /// Set by the app (or a harness) to receive decoded frames — `(pixelBuffer, tileIndex)` — for
        /// Metal composite/render. Fires on the video socket queue in decode order.
        var onDecodedVideoFrame: ((CVPixelBuffer, UInt32) -> Void)?
#endif

        init(videoUDP: AppleRawUDPDatagramConnection, ctrlUDP: AppleUDPDatagramConnection) {
            self.videoUDP = videoUDP
            self.ctrlUDP = ctrlUDP
        }

        /// Hand one raw video datagram to the serial worker: decrypt → assemble → (async) decode. Returns
        /// immediately so the UDP socket queue re-arms `receiveMessage` at once (drains at line rate). The
        /// worker is FIFO so per-SSRC ROC / AU assembly / decode order are preserved. No drop.
        func enqueueVideoDatagram(_ data: Data, logger: VNCLogger) {
            // Queue depth/age diagnostic: stamp enqueue time + bump the pending count on the recv thread,
            // decrement + compute the age inside the worker block. Detects self-inflicted backlog (climbing
            // depth ⇒ we're the bottleneck) vs on-wire loss (low depth ⇒ residual loss is on the link).
            let tEnq = DispatchTime.now().uptimeNanoseconds
            diagLock.lock()
            pendingDatagrams += 1
            if pendingDatagrams > qDepthMax { qDepthMax = pendingDatagrams }
            if pendingDatagrams > abQDepthMax { abQDepthMax = pendingDatagrams }
            diagLock.unlock()
            videoWorkQueue.async { [weak self] in
                guard let self else { return }
                let t0 = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                self.diagLock.lock()
                self.pendingDatagrams -= 1
                let ageMs = Double(t0 &- tEnq) / 1e6
                if ageMs > self.qAgeMaxMs { self.qAgeMaxMs = ageMs }
                self.diagLock.unlock()
                self.stats.addVideo()
                guard let dec = self.srtpDecryptor, let (header, payload) = dec.decrypt(packet: data) else {
                    let te = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                    self.profiler?.recordPacket(busyNs: te - t0, decryptNs: te - t0, decodeNs: 0)
                    return
                }
                let tDec = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                self.stats.addDecrypted()
                if self.rawDiagCount < 60 {   // TEMP: locate out-of-band params for single-tile stream
                    self.rawDiagCount += 1
                    let p = [UInt8](payload.prefix(6))
                    logger.logDebug("[hp-raw] pt=\(header.payloadType) ssrc=\(header.ssrc & 0xFFFF) seq=\(header.sequenceNumber) mark=\(header.marker) len=\(payload.count) first=\(p.map { String(format: "%02x", $0) }.joined())")
                }
                self.handleDecryptedVideo(header: header, payload: payload, logger: logger)
                let t1 = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT
                self.profiler?.recordPacket(busyNs: t1 - t0, decryptNs: tDec - t0, decodeNs: t1 - tDec)
#if canImport(VideoToolbox)
                // TEMP-MEASUREMENT [hp-split]: once per wall-second, decompose the per-AU decode cost that
                // [hp-prof] decodeMs lumps together. vtMs = real HW decode; cbMs = inline downstream callback
                // (app composite + LTR-ACK); buildMs = sample-buffer construction; sigMs = param re-signature.
                if self.splitWinStartNs == 0 { self.splitWinStartNs = t0 }
                if t0 &- self.splitWinStartNs >= 1_000_000_000 {
                    let p = self.hevcDecoder.takeProbe()
                    let aus = max(p.aus, 1)
                    logger.logDebug(String(format: "[hp-split] perAU: vtMs=%.3f cbMs=%.3f buildMs=%.3f sigMs=%.3f | aus=%d feeds=%d totalMs=%.3f",
                                           Double(p.vtNs) / Double(aus) / 1e6,
                                           Double(p.cbNs) / Double(aus) / 1e6,
                                           Double(p.buildNs) / Double(aus) / 1e6,
                                           Double(p.sigNs) / Double(aus) / 1e6,
                                           p.aus, p.feeds,
                                           Double(p.vtNs &+ p.cbNs &+ p.buildNs &+ p.sigNs) / Double(aus) / 1e6))
                    self.splitWinStartNs = t0
                }
#endif
                if self.stats.decryptedCount % 1000 == 0 {
                    self.diagLock.lock()
                    let qd = self.qDepthMax; let qa = self.qAgeMaxMs
                    self.qDepthMax = 0; self.qAgeMaxMs = 0
                    self.diagLock.unlock()
                    logger.logDebug(String(format: "[hp-rtp] decrypted=%d hevc-decoded=%d droppedGappedAUs=%d qDepthMax=%d qAgeMaxMs=%.1f",
                                           self.stats.decryptedCount, self.hevcFramesDecoded, self.hevcDroppedGappedAUs, qd, qa))
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
            // Resolve the tile FIRST. An SSRC with no slot (an extra group arriving inside the coalescing
            // window) is dropped here with NO side effects — in particular it must not be allowed to flip the
            // per-stream DONL detection below, and it must never be decoded into another tile's strip.
            guard let tile = tileIndex(for: au.ssrc, logger: logger) else { return }
            // Auto-detect DONL presence from the parameter-set AP (single-tile omits it); apply per-stream.
            if let first = au.orderedPayloads.first,
               let detected = AppleHEVCDepacketizer.detectDONL(fromAggregationPacket: first) {
                hevcDONL = detected
            }
            let nals = AppleHEVCDepacketizer.depacketizeAccessUnit(au.orderedPayloads, donl: hevcDONL)
            // ltr_id = the tile-0 AU's first-packet 16-bit DONL, zero-extended (no transform); forwarded to
            // the decode-success callback so a cleanly-decoded tile-0 frame can be ACKed.
            let donl = AppleHEVCDepacketizer.firstDONL(au.orderedPayloads, donl: hevcDONL)

            // [hp-idr]: IRAP cadence + FIR→IDR recovery latency. IRAP NAL types 16-21 (BLA 16-18, IDR 19-20,
            // CRA 21). The win under motion = these lines COLLAPSE (LTR recovery is a small P-delta, not an
            // IRAP); `hasGap=Y` on a recovery IRAP = a FIR-storm still present.
            // TEMP-MEASUREMENT [hp-tile]: track per-SSRC NAL-type set + IRAP count (tile-independence probe).
            do {
                var set = tileTypeSets[au.ssrc] ?? []
                let before = set.count
                for n in nals { if let t = AppleHEVCDepacketizer.nalType(n) { set.insert(t) } }
                if set.count != before {
                    tileTypeSets[au.ssrc] = set
                    logger.logDebug("[hp-tile] ssrc=\(au.ssrc & 0xFFFF) tile=\(tile) typesEverSeen=\(set.sorted()) (33=SPS 34=PPS 32=VPS 19/20=IDR 21=CRA <=31 VCL)")
                }
                if let it = nals.compactMap({ AppleHEVCDepacketizer.nalType($0) }).first(where: { AppleHEVCDepacketizer.isIRAP($0) }) {
                    tileIRAPCounts[au.ssrc, default: 0] += 1
                    if tileIRAPCounts[au.ssrc] == 1 {
                        logger.logDebug("[hp-tile] ssrc=\(au.ssrc & 0xFFFF) tile=\(tile) FIRST-IRAP type=\(it)")
                    }
                }
            }
            let irapType = nals.compactMap { AppleHEVCDepacketizer.nalType($0) }.first { AppleHEVCDepacketizer.isIRAP($0) }
            if let irapType {
                let nowNs = DispatchTime.now().uptimeNanoseconds
                let sinceLastIRAPms = lastIRAPNs > 0 ? Double(nowNs &- lastIRAPNs) / 1e6 : -1
                lastIRAPNs = nowNs
                irapCount += 1
                irapSinceLastOutput = true
                diagLock.lock(); abIrap += 1; diagLock.unlock()
                let fs = firSentNs
                let sinceFirMs = fs > 0 ? Double(nowNs &- fs) / 1e6 : -1
                let kind = (19...20).contains(irapType) ? "IDR" : (irapType == 21 ? "CRA" : "BLA")
                logger.logDebug(String(format: "[hp-idr] IRAP tile=%d kind=%@ hasGap=%@ sinceLastIRAPms=%.0f irapCount=%d sinceFIRms=%.0f",
                                       Int(tile), kind, au.hasGap ? "Y" : "N", sinceLastIRAPms, irapCount, sinceFirMs))
            }

            if au.hasGap {
                hevcDroppedGappedAUs += 1
                diagLock.lock(); abGappedAU += 1; diagLock.unlock()
                // The chain broke for this tile → CLEAR its chain-clean gate so we stop ACKing its LTR
                // (never poison the server's LTR ring with a frame we didn't cleanly decode) until a clean
                // IRAP re-roots it. Then request an intra refresh NOW (rate-limited) rather than waiting up
                // to 2 s for the periodic keep-alive FIR.
                chainClean[tile] = false
                requestKeyframeOnLoss()
                let params = nals.filter { (AppleHEVCDepacketizer.nalType($0)).map { !AppleHEVCDepacketizer.isVCL($0) } ?? false }
                if !params.isEmpty { hevcDecoder.decode(nals: params, context: tile, donl: nil) }
                return
            }

            // A clean (non-gapped) tile-0 IRAP re-roots the shared decoder chain → it is now safe to ACK
            // tile-0 LTRs (this frame + the clean P-deltas that follow). SET before decode so the IRAP's own
            // inline `onFrame` ACKs it; a real decode error during it re-clears the gate via `onDecodeError`.
            if tile == 0, irapType != nil { chainClean[0] = true }
            hevcDecoder.decode(nals: nals, context: tile, donl: donl)
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
            firCount += 1   // [hp-stall] "firSentDuring" (video worker queue)
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
        ///
        /// **SSRC-GROUP ROTATION.** The daemon can retire a 4-SSRC group and start a fresh one mid-session —
        /// notably right after a `0x1d` virtual display is created, where the reference observes TWO new groups
        /// within ~2 s as the curtain engages. Without handling, every new SSRC would just be appended, so the
        /// map would grow to 8 or 12 entries, tile indices would run past `tileCount`, strips would collapse to
        /// 1/8th or 1/12th height, and the per-tile chain-clean / LTR-ACK state would be keyed to the wrong
        /// tile. So once the map is full, an unknown SSRC is treated as a NEW GROUP: reset the map and the
        /// per-tile decode state and start over. A ≥3 s coalescing guard (matching the reference) stops a
        /// burst of new groups from thrashing the reset.
        ///
        /// Returns `nil` when the SSRC has NO legitimate slot, and the caller must then DROP the access unit.
        /// An unmappable SSRC must never be aliased onto a real tile: the previous code appended it anyway and
        /// clamped the index to `expectedTileCount - 1`, so an extra stream arriving inside the coalescing
        /// window rendered into the LAST tile alongside the real one — two different streams writing the same
        /// strip, i.e. foreign content flickering in the bottom band, plus that tile's chain-clean/LTR-ACK
        /// state keyed to whichever stream wrote last. Dropping is strictly better: one strip goes stale for
        /// at most the coalescing window (`loadAction .load` keeps its last good content) instead of showing
        /// another region's pixels, and the next out-of-window unknown SSRC performs a clean group reset.
        private func tileIndex(for ssrc: UInt32, logger: VNCLogger) -> UInt32? {
            tileMap.expectedTileCount = expectedTileCount
            switch tileMap.outcome(for: ssrc, nowNs: DispatchTime.now().uptimeNanoseconds) {
            case .index(let tile):
                return tile
            case .indexAfterGroupReset(let tile):
                // A new SSRC group took over: rebuild the per-group decode state the old SSRCs owned.
                logger.logDebug("[hp-ssrc] new SSRC group (ssrc=\(ssrc & 0xFFFF), reset #\(tileMap.groupResets)) — tile map + per-tile decode state reset")
                hevcAssembler = AppleHEVCAccessUnitAssembler()
                chainClean.removeAll(keepingCapacity: true)
                return tile
            case .drop:
                let drops = tileMap.unmappedDrops
                if drops == 1 || drops % 1000 == 0 {
                    logger.logDebug("[hp-ssrc] SSRC \(ssrc & 0xFFFF) has no tile slot (expected \(expectedTileCount)) — dropping its AUs rather than aliasing onto a real tile (unmappedDrops=\(drops))")
                }
                return nil
            }
        }

#if canImport(VideoToolbox)
        /// Wire the decoder's output/error callbacks (frame counting + first-frame log + forward to the
        /// app render hook). Call once before the video socket starts delivering.
        func startHEVCDecode(logger: VNCLogger) {
            hevcDecoder.onFrame = { [weak self] pixelBuffer, tile, donl in
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
                // Decoded output resumed — close any [hp-stall] flatline before delivering/ACKing.
                self.noteDecodedOutput(logger: logger)
                self.onDecodedVideoFrame?(pixelBuffer, tile)
                // Decode-gated + chain-clean-gated LTR-ACK (the crux). Only tile-0; only while the chain is
                // clean (§1.3b). `onFrame` firing alone is NOT a clean-decode signal (VT conceals with
                // status==noErr) — the chain-clean gate is what prevents LTR-ack poisoning.
                if tile == 0, let donl {
                    if self.chainClean[0] == true {
                        self.ltrAcksRequested += 1
                        self.sendLTRAck(donl: donl, logger: logger)
                    } else {
                        self.ltrGateSkips += 1   // benign racy read on rtcpQueue for [hp-ltr]
                    }
                }
            }
            var loggedError = false
            hevcDecoder.onDecodeError = { [weak self] status, tile in
                guard let self else { return }
                // A real (non-noErr) decode error means the chain broke for this tile → stop ACKing until a
                // clean IRAP re-roots it (poisoning guard, §1.3b).
                self.chainClean[tile] = false
                if !loggedError { loggedError = true; logger.logDebug("[hp-hevc] first decode error OSStatus \(status) tile=\(tile) (VT conceals; continuing)") }
            }
        }
#endif

        /// [hp-stall]: called on every decoded output (video worker queue). If ≥ 500 ms elapsed since the
        /// previous decoded frame (any tile), a freeze just ended — emit one line with the flatline duration
        /// and the deltas accumulated over it, and fold the freeze time into the [hp-ab] rollup. `recoveredVia`
        /// = IDR if an IRAP arrived during the flatline, else LTR if an LTR-ACK went out (P-delta recovery),
        /// else a bare resume.
        func noteDecodedOutput(logger: VNCLogger) {
            let now = DispatchTime.now().uptimeNanoseconds
            if lastDecodedOutputNs != 0 {
                let flatMs = Double(now &- lastDecodedOutputNs) / 1e6
                if flatMs >= 500 {
                    let gappedDuring = hevcDroppedGappedAUs - snapGappedAU
                    let firDuring = firCount - snapFir
                    let ltrDuring = ltrAcksRequested - snapLtrAck   // worker-local (no cross-queue race)
                    let via = irapSinceLastOutput ? "IDR" : (ltrDuring > 0 ? "LTR" : "resume")
                    logger.logDebug(String(format: "[hp-stall] flatlineMs=%.0f recoveredVia=%@ gappedAUduring=%d firSentDuring=%d ltrAcksDuring=%d",
                                           flatMs, via, gappedDuring, firDuring, ltrDuring))
                    diagLock.lock()
                    abFreezeAccumMs += flatMs
                    abFlatlines += 1
                    if flatMs > abMaxFlatlineMs { abMaxFlatlineMs = flatMs }
                    diagLock.unlock()
                }
            }
            lastDecodedOutputNs = now
            snapGappedAU = hevcDroppedGappedAUs
            snapFir = firCount
            snapLtrAck = ltrAcksRequested
            irapSinceLastOutput = false
        }

        /// Send a decode-gated, chain-clean-gated LTR-ACK (Apple RTCP_APP PT204 subtype 5) on the VIDEO
        /// socket (5901) so the encoder re-roots from a long-term reference (small P-delta) instead of a full
        /// IDR on loss. `ltr_id` = the tile-0 AU's first-packet HEVC DONL, zero-extended (no transform).
        /// REUSES the one existing SRTCP protector on `rtcpQueue` — a second protector would restart the
        /// SRTCP index under the same key+SSRC → host replay-drop + CTR keystream reuse (NFR-6). Called from
        /// the video worker queue inside the decode-success + chain-clean gate; the protect+send is dispatched
        /// to `rtcpQueue` so the protector's monotonic index stays serialized with the keepalive/FIR.
        func sendLTRAck(donl: UInt16, logger: VNCLogger) {
            guard let protector = rtcpProtector else { return }   // keep-alive not up yet → nothing to reuse
            let ssrc = rtcpSenderSSRC
            let video = videoUDP
            let ltrID = UInt32(donl)
            rtcpQueue.async { [weak self] in
                guard let self else { return }
                // Dedupe on `!=` (not `>`) so ACKs resume after the 16-bit DONL wraps (~18 min @60fps).
                if self.lastAckedDONL == donl { self.ltrDupSuppressed += 1; return }
                self.lastAckedDONL = donl
                guard let pkt = try? protector.protect(AppleRTCPBuilders.appLtrAck(sender: ssrc, ltrID: ltrID)) else { return }
                video.send(pkt)
                self.ltrAckCount += 1
                self.ltrLastID = ltrID
                self.diagLock.lock(); self.abLtrAck += 1; self.diagLock.unlock()

                // FIRST-send line ONCE — the crux egress proof: localPort MUST be 5901, and `donlOnWire`
                // (the 16-bit value read off the wire) MUST equal `ltrID & 0xFFFF` (proves the id is the real
                // payload DONL, not a POC/ordinal — the silent-no-op regression). Never logs key/IV/salt (a
                // DONL is a public frame counter, safe).
                if !self.ltrLoggedFirst {
                    self.ltrLoggedFirst = true
                    let match = UInt16(truncatingIfNeeded: ltrID) == donl
                    logger.logDebug("[hp-ltr] FIRST ltrID=\(ltrID) tile=0 socket=video localPort=\(video.localPort) senderSSRC=\(ssrc & 0xFFFF) donlOnWire=\(donl) match=\(match)")
                }
                // 1/s aggregate (the raw ACK fires at frame rate — NEVER log per-ACK). `dDONL == 0` with
                // acks/s > 0 = FAIL (silent no-op / non-advancing id).
                let now = DispatchTime.now().uptimeNanoseconds
                if self.ltrWinStartNs == 0 { self.ltrWinStartNs = now; self.ltrPrevID = ltrID }
                let elapsed = now &- self.ltrWinStartNs
                if elapsed >= 1_000_000_000 {
                    let dDONL = Int(self.ltrLastID) - Int(self.ltrPrevID)
                    logger.logDebug(String(format: "[hp-ltr] acks/s=%.0f lastLtrID=%d dDONL=%d dupSuppressed=%d gateSkips=%d",
                                           Double(self.ltrAckCount) / (Double(elapsed) / 1e9), self.ltrLastID, dDONL,
                                           self.ltrDupSuppressed, self.ltrGateSkips))
                    self.ltrWinStartNs = now; self.ltrAckCount = 0; self.ltrDupSuppressed = 0; self.ltrPrevID = self.ltrLastID
                }
            }
        }

        /// [hp-ab]: the one line that proves the fix. `freezeSecPerMin` = cumulative decoded-output flatline
        /// time over the window, normalized to 60 s (target ≈ 0 for the 4-tile+LTR build). Emitted every 10 s
        /// off the rtcp timer and once on teardown, under `diagLock` so the cross-queue accumulators are
        /// read+reset atomically.
        func logABSummary(logger: VNCLogger, reason: String) {
            let now = DispatchTime.now().uptimeNanoseconds
            diagLock.lock()
            let windowNs = abWinStartNs > 0 ? (now &- abWinStartNs) : 0
            let windowS = max(Double(windowNs) / 1e9, 0.001)
            let freezeSecPerMin = (abFreezeAccumMs / 1000.0) / windowS * 60.0
            let flatlinesPerMin = Double(abFlatlines) / windowS * 60.0
            let maxFlat = abMaxFlatlineMs
            let irapPerMin = Double(abIrap) / windowS * 60.0
            let ltrPerMin = Double(abLtrAck) / windowS * 60.0
            let gappedPerMin = Double(abGappedAU) / windowS * 60.0
            let qdMax = abQDepthMax
            abWinStartNs = now
            abFreezeAccumMs = 0; abFlatlines = 0; abMaxFlatlineMs = 0
            abIrap = 0; abLtrAck = 0; abGappedAU = 0; abQDepthMax = 0
            diagLock.unlock()
            logger.logDebug(String(format: "[hp-ab] (%@ %.1fs) freezeSecPerMin=%.2f flatlines/min=%.1f maxFlatlineMs=%.0f irap/min=%.1f ltrAck/min=%.0f gappedAU/min=%.1f qDepthMax=%d",
                                   reason, windowS, freezeSecPerMin, flatlinesPerMin, maxFlat, irapPerMin, ltrPerMin, gappedPerMin, qdMax))
        }

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
            self.diagLogger = logger
            self.abWinStartNs = DispatchTime.now().uptimeNanoseconds   // start the [hp-ab] window
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
                // TMMBR bitrate probe (PT=205 FMT=3) every 2 s, offset from the FIR tick so the two are not
                // in the same datagram burst.
                //
                // WHY: the host sends ~15 Mbps regardless of canvas size (measured across 1920x1080,
                // 2868x1320 and 3840x2160), so a larger virtual display just spreads the same bits thinner
                // and goes blocky. We have never told it we can take more — RR/SR/FIR/PLI/NACK say nothing
                // about bandwidth. This asks. It is a PROBE: if `pktsPerAU` in [hp-prof] does not move, Apple
                // ignores TMMBR and the bitrate lever is elsewhere (the 0x1c HEVC bank's res/params fields).
                if tick % 4 == 2, let requested = self?.tmmbrBitsPerSecond, requested > 0 {
                    if let tmmbr = try? protector.protect(
                        AppleRTCPBuilders.compoundWithRR(sender: senderSSRC,
                                                         payload: AppleRTCPBuilders.tmmbr(sender: senderSSRC,
                                                                                          target: senderSSRC,
                                                                                          bitsPerSecond: requested))) {
                        ctrl.send(tmmbr)
                        if tick == 2 {
                            logger.logDebug("[hp-tmmbr] requesting \(requested / 1_000_000) Mbps via TMMBR (PT205 FMT3) every 2s — watch pktsPerAU in [hp-prof]")
                        }
                    }
                }
                // [hp-ab] freeze/recovery summary every 10 s (tick runs on rtcpQueue — same queue that reads
                // the diagLock-guarded AB accumulators).
                if tick % 20 == 0 { self?.logABSummary(logger: logger, reason: "10s") }
            }
            rtcpTimer = timer
            timer.resume()
            logger.logDebug("[hp-media] RTCP keep-alive started (0.5s RR / 5s SR / 2s legacy-FIR) → ctrl \(ctrl.localPort)")
        }

        func cancel() {
            if let diagLogger { logABSummary(logger: diagLogger, reason: "teardown") }
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

        let videoUDP = AppleRawUDPDatagramConnection(host: host, remotePort: videoPort, localPort: videoPort, label: "video")
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
            receiver?.ingressProbe?.record(datagram: data)   // TEMP-MEASUREMENT (recv thread, pre-worker)
            receiver?.enqueueVideoDatagram(data, logger: logger)
        }, onState: { state in
            logger.logDebug("[hp-media] video UDP(\(videoPort)) [raw] state: \(state)")
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
