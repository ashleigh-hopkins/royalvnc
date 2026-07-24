#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) builder for the Apple HP `0x1c` MediaStreamConfiguration
/// **offer** (HP-PHASE4-SPECS §5.1 / crib §1a-§1d). Assembles the big-endian header, the six-byte
/// gap, the outer CallID, the four 46-byte SRTP master blobs, and the two `FMT_BINARY` offer plists
/// (each wrapping a zlib-compressed `AppleMediaBlobCodec` protobuf).
///
/// **SRTP is 100% client-keyed** — all four master blobs are minted by the caller and placed in the
/// offer; the answer carries none (crib §1d). The compressed MediaBlob uses the vendored zlib
/// (`ZlibDeflateStream`, RFC-1950) — byte-match to Python is not required (D4); the host inflates
/// any valid stream.
///
/// All per-session randomness (keys, CallIDs, session IDs, timestamps) is injected via `Params` so
/// the builder is deterministic for tests (NFR-3). In production the caller supplies
/// `SecRandomCopyBytes`-backed values.
enum Apple0x1cOffer {
    static let messageType: UInt8 = 0x1C
    static let version: UInt16 = 3
    static let blobLen = 46
    /// Fixed non-payload overhead inside MS (crib §1a).
    static let fixedOverhead = 0xD8

    /// `config_flags` (BE u32 @ +0x06, crib §1b). bit0=60fps s1, bit1=60fps s2, bit2=no-cursor.
    enum ConfigFlags: UInt32 {
        case standard = 7       // 3 | 4  (default: 60fps + no-cursor)
        case altSession = 5     // (3 & ~2) | 4
        case legacyCursor = 3   // 3      (cursor baked into framebuffer)
    }

    /// Static build config (shared across the audio/video sub-offers).
    struct Config {
        var flags: ConfigFlags
        var blob: AppleMediaBlobCodec.Config
        /// `avcMediaStreamOptionRemoteEndpointInfo` (host-unvalidated; see `AppleMediaBlobCodec.buildRemoteEndpointInfo`).
        var remoteEndpointInfo: Data

        init(flags: ConfigFlags = .standard,
             blob: AppleMediaBlobCodec.Config = .init(),
             remoteEndpointInfo: Data) {
            self.flags = flags
            self.blob = blob
            self.remoteEndpointInfo = remoteEndpointInfo
        }
    }

    /// Per-session values (injected; `urandom`/`uuid4`/`randbits`/`time_ns` in production).
    struct Params {
        var outerCallID: UUID           // 16 raw bytes @ 0x14
        var audioKeyV: Data             // akv, 46 B @ 0x24
        var audioKeyS: Data             // aks, 46 B @ 0x52
        var videoKeyV: Data             // vkv, 46 B @ vo
        var videoKeyS: Data             // vks, 46 B @ vo+0x2E
        var videoSessionID: UInt32      // = our video send-SSRC
        var videoTimestamp: UInt64
        var videoPlistCallID: UUID      // avcMediaStreamOptionCallID (video plist)
        var audioSessionID: UInt32      // = our audio send-SSRC
        var audioTimestamp: UInt64
        var audioPlistCallID: UUID
    }

    // MARK: - Build

    /// Build the full `0x1c` offer buffer. Throws on a wrong-length key or an oversize sub-offer.
    static func build(config: Config, params: Params) throws -> Data {
        for key in [params.audioKeyV, params.audioKeyS, params.videoKeyV, params.videoKeyS] {
            guard key.count == blobLen else { throw VNCError.protocol(.invalidData) }
        }

        let videoBlob = AppleMediaBlobCodec.buildVideoMediaBlob(
            sessionID: params.videoSessionID, timestamp: params.videoTimestamp, config: config.blob)
        let audioBlob = AppleMediaBlobCodec.buildAudioMediaBlob(
            sessionID: params.audioSessionID, timestamp: params.audioTimestamp, config: config.blob)

        let audioOffer = try buildOfferPlist(mode: AppleMediaBlobCodec.audioMode, mediaBlob: audioBlob,
                                             remoteEndpointInfo: config.remoteEndpointInfo,
                                             callID: params.audioPlistCallID)
        let videoOffer = try buildOfferPlist(mode: AppleMediaBlobCodec.videoMode, mediaBlob: videoBlob,
                                             remoteEndpointInfo: config.remoteEndpointInfo,
                                             callID: params.videoPlistCallID)

        let audioSize = audioOffer.count
        let videoSize = videoOffer.count
        let messageSize = audioSize + videoSize + fixedOverhead
        // MS/AS/VS are u16 on the wire.
        guard audioSize <= 0xFFFF, videoSize <= 0xFFFF, messageSize <= 0xFFFF else {
            throw VNCError.protocol(.invalidData)
        }

        var buf = [UInt8](repeating: 0, count: messageSize + 4)
        buf[0] = messageType
        // buf[1] = 0 (pad)
        writeBE16(&buf, 2, UInt16(messageSize))
        writeBE16(&buf, 4, version)
        writeBE32(&buf, 6, config.flags.rawValue)   // BE u32 (crib §1b)
        writeBE16(&buf, 10, UInt16(audioSize))
        writeBE16(&buf, 12, UInt16(videoSize))
        // 0x0E..0x13 = 6-byte gap (stays 0, crib §1a).
        writeBytes(&buf, 0x14, uuidBytes(params.outerCallID))   // 16 B
        writeBytes(&buf, 0x24, [UInt8](params.audioKeyV))       // 46 B
        writeBytes(&buf, 0x52, [UInt8](params.audioKeyS))       // 46 B
        writeBytes(&buf, 0x80, [UInt8](audioOffer))
        let vo = 0x80 + audioSize
        writeBytes(&buf, vo, [UInt8](params.videoKeyV))         // 46 B
        writeBytes(&buf, vo + 0x2E, [UInt8](params.videoKeyS))  // 46 B
        writeBytes(&buf, vo + 0x5C, [UInt8](videoOffer))

        return Data(buf)
    }

    /// Build a single `FMT_BINARY` offer plist wrapping a zlib-compressed MediaBlob (crib §1c).
    static func buildOfferPlist(mode: Int, mediaBlob: Data, remoteEndpointInfo: Data, callID: UUID) throws -> Data {
        let compressed = try ZlibDeflateStream().compressedData(data: mediaBlob, flush: .finish)
        let dict: [String: Any] = [
            "avcMediaStreamOptionRemoteEndpointInfo": remoteEndpointInfo,
            "avcMediaStreamNegotiatorMode": mode,
            "avcMediaStreamNegotiatorMediaBlob": compressed,
            "avcMediaStreamOptionCallID": callID.uuidString,   // uppercase on Apple platforms
        ]
        return try PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
    }

    // MARK: - Send-SSRC harvest (crib §1c)

    /// Harvest our advertised send-SSRCs from a built `0x1c` buffer by slicing out the two sub-offer
    /// plists (via the header AS/VS), decoding each, decompressing its MediaBlob, and reading the
    /// SSRC (video field 5→1, audio field 3→1). Returns `nil` if the buffer is malformed.
    static func harvestSendSSRCs(offer buffer: Data) -> (video: UInt32, audio: UInt32)? {
        let bytes = [UInt8](buffer)
        guard bytes.count >= 0x80, bytes[0] == messageType else { return nil }
        let audioSize = Int(readBE16(bytes, 10))
        let videoSize = Int(readBE16(bytes, 12))
        let audioStart = 0x80
        let vo = 0x80 + audioSize
        let videoStart = vo + 0x5C
        guard videoStart + videoSize <= bytes.count else { return nil }

        let audioPlist = buffer.subdata(in: audioStart..<(audioStart + audioSize))
        let videoPlist = buffer.subdata(in: videoStart..<(videoStart + videoSize))
        guard let audio = ssrc(fromOfferPlist: audioPlist, videoField: 3),
              let video = ssrc(fromOfferPlist: videoPlist, videoField: 5) else { return nil }
        return (video: video, audio: audio)
    }

    /// Decode an offer plist, decompress its MediaBlob, and extract the SSRC (crib §1c).
    static func ssrc(fromOfferPlist plist: Data, videoField field: Int) -> UInt32? {
        guard let obj = try? PropertyListSerialization.propertyList(from: plist, options: [], format: nil),
              let dict = obj as? [String: Any],
              let compressed = dict["avcMediaStreamNegotiatorMediaBlob"] as? Data,
              let blob = try? ZlibStream().decompressedData(compressedData: compressed) else { return nil }
        return AppleMediaBlobCodec.extractOfferSSRC(mediaBlob: blob, videoField: field)
    }

    // MARK: - Byte helpers

    private static func uuidBytes(_ uuid: UUID) -> [UInt8] {
        let u = uuid.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    private static func writeBytes(_ buf: inout [UInt8], _ offset: Int, _ src: [UInt8]) {
        for (i, b) in src.enumerated() { buf[offset + i] = b }
    }

    private static func writeBE16(_ buf: inout [UInt8], _ offset: Int, _ v: UInt16) {
        buf[offset] = UInt8(v >> 8 & 0xFF)
        buf[offset + 1] = UInt8(v & 0xFF)
    }

    private static func writeBE32(_ buf: inout [UInt8], _ offset: Int, _ v: UInt32) {
        buf[offset] = UInt8(v >> 24 & 0xFF)
        buf[offset + 1] = UInt8(v >> 16 & 0xFF)
        buf[offset + 2] = UInt8(v >> 8 & 0xFF)
        buf[offset + 3] = UInt8(v & 0xFF)
    }

    private static func readBE16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
}
