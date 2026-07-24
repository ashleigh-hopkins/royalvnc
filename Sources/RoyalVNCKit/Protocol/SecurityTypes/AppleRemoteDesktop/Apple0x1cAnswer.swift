#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) parser for the Apple HP `0x1c` **answer**
/// (HP-PHASE4-SPECS §5.3 / crib §2a).
///
/// The answer arrives as a standard RFB FramebufferUpdate (**first byte `0x00`**), NOT a `0x1c`-typed
/// record. Inside it, an Apple binary plist is located by scanning for the literal ASCII `bplist`
/// header and growing the slice end (in steps of 2) until it decodes. The plist's
/// `avcMediaStreamNegotiatorMediaBlob` is zlib-inflated and its protobuf **field 5** (video config)
/// carries the canvas geometry: `sub4 = width`, `sub5 = height`, `sub6 = tileCount`,
/// `sub7 = ltrpEnabled`. Zeros ⇒ "encoder not ready" ⇒ the caller retries (crib §2b). The answer
/// carries **no SRTP keys and no SSRCs** — server SSRCs are learned from received RTP.
enum Apple0x1cAnswer {
    /// Parsed canvas geometry from the answer.
    struct Canvas: Equatable {
        let width: UInt32
        let height: UInt32
        let tileCount: UInt32
        let ltrpEnabled: Bool

        /// A nonzero `width` and `height` mean the encoder is ready; zeros ⇒ retry (crib §2b).
        var isReady: Bool { width != 0 && height != 0 }

        static let notReady = Canvas(width: 0, height: 0, tileCount: 0, ltrpEnabled: false)
    }

    private static let bplistMagic = Data("bplist".utf8)

    /// Parse the answer. Returns `Canvas.notReady` (all zeros) when the first byte isn't `0x00`, no
    /// decodable bplist with a nonzero canvas is found, or the MediaBlob can't be inflated/parsed.
    static func parse(_ answer: Data) -> Canvas {
        guard let first = answer.first, first == 0x00 else { return .notReady }

        var searchStart = answer.startIndex
        while let magicRange = answer.range(of: bplistMagic, in: searchStart..<answer.endIndex) {
            let idx = magicRange.lowerBound
            if let canvas = canvasFromPlist(in: answer, startingAt: idx), canvas.isReady {
                return canvas
            }
            // Not a usable plist here — advance past this "bplist" and keep scanning (crib §2a).
            searchStart = answer.index(idx, offsetBy: 6)
        }
        return .notReady
    }

    /// Try to decode a binary plist starting at `idx`, growing the slice end by 2 until it parses,
    /// then read the canvas from its MediaBlob. Returns `nil` if no decodable plist / MediaBlob.
    private static func canvasFromPlist(in answer: Data, startingAt idx: Data.Index) -> Canvas? {
        // Grow the slice end in steps of 2 (framing is search-based today — crib §2a).
        var end = answer.index(idx, offsetBy: 1, limitedBy: answer.endIndex) ?? answer.endIndex
        while end <= answer.endIndex {
            let slice = answer.subdata(in: idx..<end)
            if let obj = try? PropertyListSerialization.propertyList(from: slice, options: [], format: nil),
               let dict = obj as? [String: Any] {
                guard let compressed = dict["avcMediaStreamNegotiatorMediaBlob"] as? Data,
                      let blob = try? ZlibStream().decompressedData(compressedData: compressed) else {
                    return nil   // decoded a plist but no usable MediaBlob
                }
                return canvasFromMediaBlob(blob)
            }
            guard let next = answer.index(end, offsetBy: 2, limitedBy: answer.endIndex) else {
                // Try the exact end once, then stop.
                if end < answer.endIndex { end = answer.endIndex; continue }
                break
            }
            end = next
        }
        return nil
    }

    /// Walk the MediaBlob protobuf: top-level field 5 (video config), then its varint sub-fields
    /// 4/5/6/7 (crib §2a).
    private static func canvasFromMediaBlob(_ blob: Data) -> Canvas? {
        let bytes = [UInt8](blob)
        var pos = 0
        while pos < bytes.count {
            guard let (tag, afterTag) = AppleMediaBlobCodec.readVarint(bytes, pos) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 7)
            pos = afterTag
            switch wireType {
            case 0:
                guard let (_, next) = AppleMediaBlobCodec.readVarint(bytes, pos) else { return nil }
                pos = next
            case 2:
                guard let (len, afterLen) = AppleMediaBlobCodec.readVarint(bytes, pos) else { return nil }
                let start = afterLen
                let end = start + Int(len)
                guard end <= bytes.count else { return nil }
                if fieldNum == 5 {
                    return parseVideoConfig(Array(bytes[start..<end]))
                }
                pos = end
            case 1:
                pos += 8
            case 5:
                pos += 4
            default:
                return nil
            }
        }
        return nil
    }

    /// Read the F5 video-config sub-message: sub4=width, sub5=height, sub6=tileCount, sub7=ltrp.
    private static func parseVideoConfig(_ sub: [UInt8]) -> Canvas? {
        var cw: UInt32 = 0, ch: UInt32 = 0, ct: UInt32 = 0
        var ltrp = false
        var pos = 0
        while pos < sub.count {
            guard let (tag, afterTag) = AppleMediaBlobCodec.readVarint(sub, pos) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 7)
            pos = afterTag
            switch wireType {
            case 0:
                guard let (v, next) = AppleMediaBlobCodec.readVarint(sub, pos) else { return nil }
                pos = next
                switch fieldNum {
                case 4: cw = UInt32(truncatingIfNeeded: v)
                case 5: ch = UInt32(truncatingIfNeeded: v)
                case 6: ct = UInt32(truncatingIfNeeded: v)
                case 7: ltrp = v != 0
                default: break
                }
            case 2:
                guard let (len, afterLen) = AppleMediaBlobCodec.readVarint(sub, pos) else { return nil }
                pos = afterLen + Int(len)
            case 1:
                pos += 8
            case 5:
                pos += 4
            default:
                return nil
            }
        }
        return Canvas(width: cw, height: ch, tileCount: ct, ltrpEnabled: ltrp)
    }
}
