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
/// Threading: `decode(nals:context:)` is called from a single queue (the media socket queue); the sync
/// output handler fires inline on that queue before return, so `onFrame` is serialized. Not thread-safe
/// for concurrent callers by design (the media receiver drives it from one queue).
final class AppleHEVCDecoder {
    /// Called with each decoded frame and the caller's `context` tag (the tile index). Fires on the
    /// calling queue, in decode order.
    var onFrame: ((CVPixelBuffer, UInt32) -> Void)?
    /// Called with the first non-`noErr` decode/feed status (throttling is the caller's concern).
    var onDecodeError: ((OSStatus) -> Void)?

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
        if let session { VTDecompressionSessionInvalidate(session) }
        session = nil
    }

    /// Decode one access unit's NAL units (already depayed, in decode order) for `context` (tile index).
    /// Harvests any parameter sets first (rebuilding the session on a real change), then feeds the VCL
    /// slices. No-ops until a full VPS+SPS+PPS set has been seen.
    func decode(nals: [Data], context: UInt32) {
        harvestParameterSets(nals)
        rebuildIfParametersChanged()

        guard let session, let formatDescription else { return }

        for nal in nals {
            guard let type = AppleHEVCDepacketizer.nalType(nal), AppleHEVCDepacketizer.isVCL(type) else {
                continue   // VPS/SPS/PPS/SEI come from the format description, never fed as samples
            }
            feed(nal: nal, session: session, format: formatDescription, context: context)
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
    private func rebuildIfParametersChanged() {
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
            onDecodeError?(createStatus)
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
            onDecodeError?(sessionStatus)
            return
        }

        session = created
        formatDescription = fmt
        builtSignature = sig
    }

    // MARK: - Feeding

    private func feed(nal: Data, session: VTDecompressionSession, format: CMFormatDescription, context: UInt32) {
        guard let sample = makeSampleBuffer(nal: nal, format: format) else {
            recordError(noErr)
            return
        }
        let status = VTDecompressionSessionDecodeFrame(
            session, sampleBuffer: sample, flags: [], infoFlagsOut: nil
        ) { [weak self] status, _, imageBuffer, _, _ in
            guard let self else { return }
            if status == noErr, let imageBuffer {
                self.framesDecoded += 1
                if self.negotiatedPixelFormat == nil {
                    self.negotiatedPixelFormat = CVPixelBufferGetPixelFormatType(imageBuffer)
                }
                self.onFrame?(imageBuffer, context)
            } else {
                self.recordError(status)
            }
        }
        if status != noErr { recordError(status) }
    }

    private func recordError(_ status: OSStatus) {
        decodeErrors += 1
        onDecodeError?(status)
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
