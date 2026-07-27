#if canImport(VideoToolbox)

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import VideoToolbox
import CoreMedia
import CoreVideo

/// Live Apple HP HEVC decoder: harvests VPS/SPS/PPS parameter sets, builds one shared
/// `VTDecompressionSession`, and feeds depayed VCL NAL units to produce `CVPixelBuffer`s (crib §8/§3).
///
/// Darwin-only (VideoToolbox/CoreMedia); the whole file is `#if canImport(VideoToolbox)` so RoyalVNCKit
/// still builds on Linux. Technique (param-set harvest → `CMVideoFormatDescriptionCreateFromHEVCParameterSets`
/// with `nalUnitHeaderLength=4` → one HW-preferred session → 4-byte-length-prefixed sample buffers → sync
/// output handler) mirrors the HP B1/B2 probes; original code, no AGPL copied.
///
/// Threading: `decode(nals:context:donl:)` is called from a single serial queue (the media decode worker).
/// Decode is SYNCHRONOUS (`VTDecompressionSessionDecodeFrame` flags `[]`): the output handler fires INLINE
/// on the caller's queue before `feed()` returns, in strict FIFO decode order (cross-tile refs / shared DPB
/// preserved). Async decode was tried for throughput but WEDGED under FMV on A18 (see `feed`). Because
/// decode is synchronous, the per-`feed` `donl` captured for the LTR-ACK is unambiguously the DONL of the
/// frame that `onFrame` emits — no `ts→DONL` side-map is needed. If VT is ever reconfigured async, that
/// association breaks and the DONL would need a ts-keyed map instead.
/// Not thread-safe for concurrent callers by design (one queue submits; VT serializes output).
final class AppleHEVCDecoder {
    /// Called with each decoded frame, the caller's `context` tag (the tile index), and the tile-0 AU's
    /// first-packet DONL (`nil` when the stream carries no DONL or for a params-only feed). Fires INLINE on
    /// the calling queue, in decode order. The `donl` lets the caller send a decode-gated LTR-ACK.
    var onFrame: ((CVPixelBuffer, UInt32, UInt16?) -> Void)?
    /// Called with the first non-`noErr` decode/feed status and the tile `context` it occurred on
    /// (throttling is the caller's concern). The context lets the caller clear the per-tile chain-clean gate.
    var onDecodeError: ((OSStatus, UInt32) -> Void)?

    private let requireHardware: Bool

    private var session: VTDecompressionSession?
    private var formatDescription: CMFormatDescription?

    // Harvested parameter sets (latest VPS/SPS; PPS deduped by exact bytes, insertion-ordered).
    private var vps: Data?
    private var sps: Data?
    private var ppsList: [Data] = []
    /// Signature (VPS‖SPS‖PPS…) of the parameter sets the current session was built from; a rebuild
    /// happens only when this changes, so Apple's per-IDR param resends (byte-identical) are no-ops and
    /// never wipe the DPB (crib §3 risk 7). A genuine SPS/resolution change rebuilds.
    private var builtSignature: Data?

    #if DEBUG
    private var diagCount = 0   // TEMP [hp-dec]: single-tile decode diagnosis

    // TEMP-MEASUREMENT [hp-split]: decompose the per-AU cost that `[hp-prof] decodeMs` lumps together.
    // The inline VT completion handler runs INSIDE VTDecompressionSessionDecodeFrame, so the only way to
    // separate real HW decode from the downstream callback (app composite + LTR-ACK) is to time the handler
    // and subtract it from the decode call's span. Resolves: is the ceiling HW compute, blocked wait, or
    // inline callback work? Read+reset by the media receiver once per second.
    //
    // DEBUG-only: this costs six `DispatchTime.now()` reads per access unit on the decode-critical worker
    // queue, which is exactly the path being measured. A measurement that ships is a measurement that
    // changes what it measures.
    private(set) var probeSignatureNs: UInt64 = 0    // harvest + per-AU param signature build/compare
    private(set) var probeSampleBuildNs: UInt64 = 0  // makeSampleBuffer (malloc + memcpy + CoreMedia objects)
    private(set) var probeVTNs: UInt64 = 0           // decode call span MINUS the inline callback = real VT
    private(set) var probeCallbackNs: UInt64 = 0     // inline onFrame (app composite/coalesce + LTR-ACK)
    private(set) var probeFeeds = 0                  // VCL NALs fed
    private(set) var probeAUs = 0                    // decode() calls

    /// Read + zero the [hp-split] accumulators (called on the media worker queue, same queue as `decode`).
    func takeProbe() -> (sigNs: UInt64, buildNs: UInt64, vtNs: UInt64, cbNs: UInt64, feeds: Int, aus: Int) {
        defer {
            probeSignatureNs = 0; probeSampleBuildNs = 0; probeVTNs = 0; probeCallbackNs = 0
            probeFeeds = 0; probeAUs = 0
        }
        return (probeSignatureNs, probeSampleBuildNs, probeVTNs, probeCallbackNs, probeFeeds, probeAUs)
    }
    #endif
    private(set) var framesDecoded = 0
    private(set) var decodeErrors = 0
    private(set) var negotiatedPixelFormat: OSType?
    private(set) var decodedWidth: Int32 = 0
    private(set) var decodedHeight: Int32 = 0

    init(requireHardware: Bool = false) {
        self.requireHardware = requireHardware
    }

    deinit { invalidate() }

    func invalidate() {
        if let session {
            // Async decode is in flight; drain queued frames before teardown so a rebuild (DPB swap on a
            // real param change) or deinit never races the VT output thread or drops in-flight frames.
            VTDecompressionSessionWaitForAsynchronousFrames(session)
            VTDecompressionSessionInvalidate(session)
        }
        session = nil
    }

    /// Decode one access unit's NAL units (already depayed, in decode order) for `context` (tile index).
    /// Harvests any parameter sets first (rebuilding the session on a real change), then feeds the VCL
    /// slices. No-ops until a full VPS+SPS+PPS set has been seen. `donl` = the AU's first-packet DONL,
    /// forwarded to `onFrame` (for the LTR-ACK); `nil` for a params-only feed.
    func decode(nals: [Data], context: UInt32, donl: UInt16? = nil) {
        #if DEBUG
        let tSig0 = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT [hp-split]
        #endif
        harvestParameterSets(nals)
        rebuildIfParametersChanged(context: context)
        #if DEBUG
        probeSignatureNs &+= DispatchTime.now().uptimeNanoseconds &- tSig0
        probeAUs += 1

        if diagCount < 60 {
            diagCount += 1
            let types = nals.map { nal -> String in
                let t = AppleHEVCDepacketizer.nalType(nal).map { Int($0) } ?? -1
                return "\(t)(\(nal.count))"
            }
            print("[hp-dec] ctx=\(context) nals=\(types) vps=\(vps != nil) sps=\(sps != nil) pps=\(ppsList.count) session=\(session != nil)")
        }
        #endif

        guard let session, let formatDescription else { return }

        for nal in nals {
            guard let type = AppleHEVCDepacketizer.nalType(nal), AppleHEVCDepacketizer.isVCL(type) else {
                continue   // VPS/SPS/PPS/SEI come from the format description, never fed as samples
            }
            feed(nal: nal, session: session, format: formatDescription, context: context, donl: donl)
        }
    }

    // MARK: - Parameter sets

    private func harvestParameterSets(_ nals: [Data]) {
        for nal in nals {
            guard let type = AppleHEVCDepacketizer.nalType(nal) else { continue }
            switch type {
            case AppleHEVCDepacketizer.nalTypeVPS: vps = nal
            case AppleHEVCDepacketizer.nalTypeSPS: sps = nal
            case AppleHEVCDepacketizer.nalTypePPS:
                if !ppsList.contains(nal) { ppsList.append(nal) }
            default: break
            }
        }
    }

    private func currentSignature() -> Data? {
        guard let vps, let sps, !ppsList.isEmpty else { return nil }
        var sig = Data()
        sig.append(vps)
        sig.append(sps)
        for pps in ppsList { sig.append(pps) }
        return sig
    }

    /// (Re)build the format description + session when the harvested parameter sets change. Identical
    /// resends are no-ops (DPB-preserving).
    private func rebuildIfParametersChanged(context: UInt32) {
        guard let sig = currentSignature(), sig != builtSignature else { return }
        guard let vps, let sps else { return }

        let parameterSets = [vps, sps] + ppsList
        let sizes = parameterSets.map { $0.count }

        var newFormat: CMFormatDescription?
        let createStatus = withParameterSetPointers(parameterSets) { pointers -> OSStatus in
            pointers.withUnsafeBufferPointer { buf in
                CMVideoFormatDescriptionCreateFromHEVCParameterSets(
                    allocator: kCFAllocatorDefault,
                    parameterSetCount: parameterSets.count,
                    parameterSetPointers: buf.baseAddress!,
                    parameterSetSizes: sizes,
                    nalUnitHeaderLength: 4,
                    extensions: nil,
                    formatDescriptionOut: &newFormat)
            }
        }
        guard createStatus == noErr, let fmt = newFormat else {
            onDecodeError?(createStatus, context)
            return
        }

        // Tear down the old session before swapping the format (a rebuild resets the DPB — only reached
        // on a genuine parameter change, not per-IDR).
        invalidate()

        let dims = CMVideoFormatDescriptionGetDimensions(fmt)
        decodedWidth = dims.width
        decodedHeight = dims.height

        // The hardware-decoder specification keys are iOS 17+ / macOS 10.9+ (they were macOS-only before
        // iOS 17). On older iOS, omit them and let VT pick its default decoder (HEVC HW decode still works
        // where the SoC supports it). macOS (fork tests + harness) always satisfies this, so live behavior
        // is unchanged there.
        var decoderSpec: [CFString: Any] = [:]
        if #available(iOS 17.0, tvOS 17.0, macOS 10.9, *) {
            decoderSpec[kVTVideoDecoderSpecification_EnableHardwareAcceleratedVideoDecoder] = true
            if requireHardware {
                decoderSpec[kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder] = true
            }
        }
        // No pixel-format key: let VT negotiate its native output (a forced FourCC risks a false
        // kVTPixelTransferNotSupportedErr for 4:4:4 — crib §3/§5). IOSurface-backed for zero-copy render.
        let imageBufferAttributes: [CFString: Any] = [
            kCVPixelBufferWidthKey: Int(dims.width),
            kCVPixelBufferHeightKey: Int(dims.height),
            kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary
        ]

        var newSession: VTDecompressionSession?
        let sessionStatus = VTDecompressionSessionCreate(
            allocator: kCFAllocatorDefault,
            formatDescription: fmt,
            decoderSpecification: decoderSpec as CFDictionary,
            imageBufferAttributes: imageBufferAttributes as CFDictionary,
            outputCallback: nil,
            decompressionSessionOut: &newSession)

        guard sessionStatus == noErr, let created = newSession else {
            onDecodeError?(sessionStatus, context)
            return
        }

        session = created
        formatDescription = fmt
        builtSignature = sig
    }

    // MARK: - Feeding

    private func feed(nal: Data, session: VTDecompressionSession, format: CMFormatDescription, context: UInt32, donl: UInt16?) {
        #if DEBUG
        let tBuild0 = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT [hp-split]
        #endif
        guard let sample = makeSampleBuffer(nal: nal, format: format) else {
            recordError(noErr, context: context)
            return
        }
        #if DEBUG
        probeSampleBuildNs &+= DispatchTime.now().uptimeNanoseconds &- tBuild0
        probeFeeds += 1
        // The completion handler fires INLINE inside the decode call below; accumulate its own span here so
        // it can be subtracted → probeVTNs = real HW decode, probeCallbackNs = downstream inline work.
        var callbackNs: UInt64 = 0
        let tDec0 = DispatchTime.now().uptimeNanoseconds
        #endif
        // SYNCHRONOUS decode (flags: []): the output handler fires inline before this returns, so decode
        // never falls behind its own feed. Async decode (`kVTDecodeFrame_EnableAsynchronousDecompression`)
        // was tried for throughput but WEDGED under FMV load on A18 — large frames fed at high rate into the
        // one shared session backed up VT's async queue and output stopped, and even a fresh self-contained
        // IDR just queued behind the jam (device: clean IDR fed, hevc-decoded frozen). Async is unnecessary
        // now: decode runs on the decoupled media worker (fed by the raw-socket recv thread), so a blocking
        // HW round-trip here no longer stalls UDP intake. Decode order / shared DPB preserved as before.
        let status = VTDecompressionSessionDecodeFrame(
            session, sampleBuffer: sample, flags: [], infoFlagsOut: nil
        ) { [weak self] status, _, imageBuffer, _, _ in
            guard let self else { return }
            #if DEBUG
            let tCb0 = DispatchTime.now().uptimeNanoseconds   // TEMP-MEASUREMENT [hp-split]
            defer { callbackNs &+= DispatchTime.now().uptimeNanoseconds &- tCb0 }
            #endif
            if status == noErr, let imageBuffer {
                self.framesDecoded += 1
                if self.negotiatedPixelFormat == nil {
                    self.negotiatedPixelFormat = CVPixelBufferGetPixelFormatType(imageBuffer)
                }
                self.onFrame?(imageBuffer, context, donl)
            } else {
                self.recordError(status, context: context)
            }
        }
        #if DEBUG
        // TEMP-MEASUREMENT [hp-split]: decode-call span minus the inline callback = real VT decode cost.
        let span = DispatchTime.now().uptimeNanoseconds &- tDec0
        probeVTNs &+= span > callbackNs ? (span &- callbackNs) : 0
        probeCallbackNs &+= callbackNs
        #endif
        if status != noErr { recordError(status, context: context) }
    }

    private func recordError(_ status: OSStatus, context: UInt32) {
        decodeErrors += 1
        onDecodeError?(status, context)
    }

    /// Wrap a NAL as a 4-byte-BE length-prefixed (AVCC, matches `nalUnitHeaderLength=4`) sample buffer.
    /// The malloc block is handed to CoreMedia, which frees it.
    private func makeSampleBuffer(nal: Data, format: CMFormatDescription) -> CMSampleBuffer? {
        let nalLength = nal.count
        let totalLength = 4 + nalLength
        guard let raw = malloc(totalLength) else { return nil }
        let bytes = raw.assumingMemoryBound(to: UInt8.self)
        bytes[0] = UInt8((nalLength >> 24) & 0xFF)
        bytes[1] = UInt8((nalLength >> 16) & 0xFF)
        bytes[2] = UInt8((nalLength >> 8) & 0xFF)
        bytes[3] = UInt8(nalLength & 0xFF)
        nal.withUnsafeBytes { src in
            if let base = src.baseAddress { memcpy(raw.advanced(by: 4), base, nalLength) }
        }

        var blockBuffer: CMBlockBuffer?
        let bbStatus = CMBlockBufferCreateWithMemoryBlock(
            allocator: kCFAllocatorDefault,
            memoryBlock: raw,
            blockLength: totalLength,
            blockAllocator: kCFAllocatorDefault,   // CM owns + frees `raw`
            customBlockSource: nil,
            offsetToData: 0,
            dataLength: totalLength,
            flags: 0,
            blockBufferOut: &blockBuffer)
        guard bbStatus == kCMBlockBufferNoErr, let bb = blockBuffer else {
            free(raw)
            return nil
        }

        var sampleBuffer: CMSampleBuffer?
        var sampleSize = totalLength
        let sbStatus = CMSampleBufferCreateReady(
            allocator: kCFAllocatorDefault,
            dataBuffer: bb,
            formatDescription: format,
            sampleCount: 1,
            sampleTimingEntryCount: 0,
            sampleTimingArray: nil,
            sampleSizeEntryCount: 1,
            sampleSizeArray: &sampleSize,
            sampleBufferOut: &sampleBuffer)
        guard sbStatus == noErr else { return nil }
        return sampleBuffer
    }

    /// Build the `[UnsafePointer<UInt8>]` VT's C API needs, keeping each `Data` alive across `body`.
    private func withParameterSetPointers<R>(_ sets: [Data], _ body: ([UnsafePointer<UInt8>]) -> R) -> R {
        func recurse(_ index: Int, _ acc: [UnsafePointer<UInt8>]) -> R {
            if index == sets.count { return body(acc) }
            return sets[index].withUnsafeBytes { raw -> R in
                let ptr = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return recurse(index + 1, acc + [ptr])
            }
        }
        return recurse(0, [])
    }

    /// Whether the session negotiated hardware-accelerated decode (readback; best-effort).
    func isHardwareAccelerated() -> Bool {
        guard let session else { return false }
        // The readback property key is iOS 17+ / macOS 10.9+ (see the spec-key note above).
        guard #available(iOS 17.0, tvOS 17.0, macOS 10.9, *) else { return false }
        var value: CFTypeRef?
        let status = VTSessionCopyProperty(
            session,
            key: kVTDecompressionPropertyKey_UsingHardwareAcceleratedVideoDecoder,
            allocator: kCFAllocatorDefault,
            valueOut: &value)
        guard status == noErr, let cf = value, CFGetTypeID(cf) == CFBooleanGetTypeID() else { return false }
        return CFBooleanGetValue((cf as! CFBoolean))
    }
}

#endif
