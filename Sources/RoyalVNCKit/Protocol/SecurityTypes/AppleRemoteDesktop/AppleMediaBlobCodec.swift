#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) codec for the Apple HP `AVCMediaStreamNegotiator` **MediaBlob**
/// protobuf (HP-PHASE4-SPECS §5.2 / crib §1c). This is the protobuf layer only — building the
/// surrounding binary plist, zlib-compressing, and assembling the `0x1c` buffer live in
/// `Apple0x1cOffer` / `Apple0x1cAnswer`.
///
/// The MediaBlob is a hand-rolled protobuf whose field map is reverse-engineered from
/// `-[AVCMediaStreamNegotiator createOffer]`. Output is byte-identical to AVConference modulo the
/// per-session `sessionID`/`timestamp`. Mode 7 = video descriptor (field 5), mode 8 = audio
/// descriptor (field 3). The video descriptor's `field 1` doubles as our **send-SSRC** (crib §1c).
///
/// All varints are little-endian base-128; all field tags are `(fieldNumber<<3)|wireType`.
enum AppleMediaBlobCodec {
    static let videoMode = 7
    static let audioMode = 8

    /// Which codec bank(s) to advertise in the video descriptor.
    enum VideoCodec {
        case both   // HEVC bank (PT 100) then AVC bank (PT 123) — Apple SS.app default
        case avc    // AVC only (PT 123)
        case hevc   // HEVC only (PT 100)
    }

    /// Build config for the MediaBlob (injectable for deterministic tests; NFR-3).
    struct Config {
        var tilesPerFrame: Int
        var codec: VideoCodec
        var ltrpEnabled: Bool
        /// The `field 6` product string. Live-pin whether the host validates it (spec §11 R6).
        var productString: String

        init(tilesPerFrame: Int = 4,
             codec: VideoCodec = .both,
             ltrpEnabled: Bool = true,
             productString: String = "iShareScreen 1.0") {
            self.tilesPerFrame = tilesPerFrame
            self.codec = codec
            self.ltrpEnabled = ltrpEnabled
            self.productString = productString
        }
    }

    // MARK: - Verbatim host constants (crib §1c)

    /// AVC/H.264 feature-list string (field 3 of the AVC bank). Always carries `LTR;`.
    static let avcParams = Array("FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;".utf8)
    /// HEVC RExt 4:4:4 feature-list string, LTRP enabled (with `LTR;`).
    static let hevcParamsLTR = avcParams
    /// HEVC feature-list string, LTRP disabled (drops `LTR;`).
    static let hevcParamsNoLTR = Array("FLS;MS:-1;LF:-1;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;".utf8)

    /// Apple's canonical `field 9` audio-config tier list (10 entries, verbatim). `(f1, f2, f3?)`.
    static let audioF9Tiers: [(f1: UInt64, f2: UInt64, f3: UInt64?)] = [
        (0, 40_000_000, 12288), (0, 6_000_000, 131072), (4074, 0, 16384),
        (16, 4100, nil), (0, 75_000_000, 524288), (0, 20_000_000, 98304),
        (4, 6500, nil), (0, 60_000_000, 262144), (1, 299, nil),
        (0, 100_000_000, 1_048_576),
    ]

    // MARK: - protobuf primitives

    /// Encode an unsigned varint (little-endian base-128).
    static func varint(_ value: UInt64) -> [UInt8] {
        var v = value
        var out = [UInt8]()
        while v > 0x7F {
            out.append(UInt8((v & 0x7F) | 0x80))
            v >>= 7
        }
        out.append(UInt8(v & 0x7F))
        return out
    }

    /// A wire-type-0 (varint) field: `tag ‖ varint(value)`.
    static func fieldVarint(_ field: Int, _ value: UInt64) -> [UInt8] {
        varint(UInt64(field << 3)) + varint(value)
    }

    /// A wire-type-2 (length-delimited) field: `tag ‖ varint(len) ‖ bytes`.
    static func fieldBytes(_ field: Int, _ value: [UInt8]) -> [UInt8] {
        varint(UInt64((field << 3) | 2)) + varint(UInt64(value.count)) + value
    }

    /// Decode a varint at `pos`. Returns the value and the next position, or `nil` on truncation.
    static func readVarint(_ data: [UInt8], _ pos: Int) -> (value: UInt64, next: Int)? {
        var val: UInt64 = 0
        var shift: UInt64 = 0
        var p = pos
        while p < data.count {
            let b = data[p]
            p += 1
            val |= UInt64(b & 0x7F) << shift
            if (b & 0x80) == 0 { return (val, p) }
            shift += 7
            if shift >= 64 { return nil }   // malformed / overlong
        }
        return nil   // truncated
    }

    // MARK: - MediaBlob build

    /// Build the video (mode 7) MediaBlob protobuf (uncompressed). `sessionID` is our video
    /// send-SSRC (crib §1c).
    static func buildVideoMediaBlob(sessionID: UInt32, timestamp: UInt64, config: Config) -> Data {
        let res = fieldVarint(1, 1) + fieldVarint(2, 1) + fieldVarint(3, 50115) + fieldVarint(4, 0)
        let resAlt = fieldVarint(1, 1) + fieldVarint(2, 2) + fieldVarint(3, 50115) + fieldVarint(4, 0)

        // AVC/H.264 bank — RTP PT 123. 4 res entries [op1,op2,op1,op2], field4=1.
        let avcBank = fieldVarint(1, 123)
            + fieldBytes(2, res) + fieldBytes(2, resAlt)
            + fieldBytes(2, res) + fieldBytes(2, resAlt)
            + fieldBytes(3, avcParams)
            + fieldVarint(4, 1)

        // HEVC RExt 4:4:4 bank — RTP PT 100. 2 res entries [op1,op2], field4=14.
        let hevcParams = config.ltrpEnabled ? hevcParamsLTR : hevcParamsNoLTR
        let hevcBank = fieldVarint(1, 100)
            + fieldBytes(2, res) + fieldBytes(2, resAlt)
            + fieldBytes(3, hevcParams)
            + fieldVarint(4, 14)

        let banks: [UInt8]
        switch config.codec {
        case .avc:  banks = fieldBytes(3, avcBank)
        case .hevc: banks = fieldBytes(3, hevcBank)
        case .both: banks = fieldBytes(3, hevcBank) + fieldBytes(3, avcBank)   // HEVC then AVC
        }

        let ltrp: UInt64 = config.ltrpEnabled ? 1 : 0
        let desc = fieldVarint(1, UInt64(sessionID)) + fieldVarint(2, ltrp)
            + banks
            + fieldVarint(6, UInt64(config.tilesPerFrame)) + fieldVarint(7, ltrp)
            + fieldVarint(8, 63) + fieldVarint(9, 1) + fieldVarint(12, 1)

        return buildOuter(descField: fieldBytes(5, desc),
                          productString: config.productString, timestamp: timestamp)
    }

    /// Build the audio (mode 8) MediaBlob protobuf (uncompressed). `sessionID` is our audio SSRC.
    static func buildAudioMediaBlob(sessionID: UInt32, timestamp: UInt64, config: Config) -> Data {
        let desc = fieldVarint(1, UInt64(sessionID)) + fieldVarint(2, 0)
            + fieldVarint(3, 0) + fieldVarint(4, 24191)
            + fieldVarint(5, 0) + fieldVarint(6, 0)
        return buildOuter(descField: fieldBytes(3, desc),
                          productString: config.productString, timestamp: timestamp)
    }

    /// The shared outer MediaBlob wrapper (identical for video/audio; only `descField` differs).
    private static func buildOuter(descField: [UInt8], productString: String, timestamp: UInt64) -> Data {
        var out = fieldVarint(1, 1) + fieldVarint(2, 1)
        out += descField
        out += fieldBytes(6, Array(productString.utf8))
        out += fieldVarint(8, 0)
        out += appleAudioF9
        out += fieldVarint(13, timestamp)
        out += fieldVarint(14, 2) + fieldVarint(16, 0) + fieldVarint(18, 1)
        return Data(out)
    }

    /// The verbatim `field 9` audio tier list, built once.
    static let appleAudioF9: [UInt8] = {
        var out = [UInt8]()
        for tier in audioF9Tiers {
            var body = fieldVarint(1, tier.f1) + fieldVarint(2, tier.f2)
            if let f3 = tier.f3 { body += fieldVarint(3, f3) }
            out += fieldBytes(9, body)
        }
        return out
    }()

    // MARK: - Send-SSRC harvest (crib §1c)

    /// Extract our advertised send-SSRC from an (uncompressed) MediaBlob: video = field 5 → sub 1,
    /// audio = field 3 → sub 1. Returns `nil` if not found. AVConference accepts RTP/RTCP only from
    /// this SSRC.
    static func extractOfferSSRC(mediaBlob: Data, videoField field: Int) -> UInt32? {
        let bytes = [UInt8](mediaBlob)
        var pos = 0
        while pos < bytes.count {
            guard let (tag, afterTag) = readVarint(bytes, pos) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 7)
            pos = afterTag
            switch wireType {
            case 0:   // varint
                guard let (_, next) = readVarint(bytes, pos) else { return nil }
                pos = next
            case 2:   // length-delimited
                guard let (len, afterLen) = readVarint(bytes, pos) else { return nil }
                let start = afterLen
                let end = start + Int(len)
                guard end <= bytes.count else { return nil }
                if fieldNum == field {
                    // First sub-field (field 1, varint) of the descriptor = the SSRC.
                    let inner = Array(bytes[start..<end])
                    guard let (innerTag, innerAfter) = readVarint(inner, 0) else { return nil }
                    if (innerTag & 7) == 0 && (innerTag >> 3) == 1 {
                        guard let (ssrc, _) = readVarint(inner, innerAfter) else { return nil }
                        return UInt32(truncatingIfNeeded: ssrc)
                    }
                }
                pos = end
            case 1:   // 64-bit
                pos += 8
            case 5:   // 32-bit
                pos += 4
            default:
                return nil
            }
        }
        return nil
    }

    /// Convenience: the video send-SSRC (field 5 → sub 1).
    static func extractVideoSSRC(mediaBlob: Data) -> UInt32? { extractOfferSSRC(mediaBlob: mediaBlob, videoField: 5) }
    /// Convenience: the audio send-SSRC (field 3 → sub 1).
    static func extractAudioSSRC(mediaBlob: Data) -> UInt32? { extractOfferSSRC(mediaBlob: mediaBlob, videoField: 3) }
}
