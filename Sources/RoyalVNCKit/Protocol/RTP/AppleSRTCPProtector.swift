#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

/// Pure (Foundation + CryptoSwift, no socket) SRTCP protect/unprotect for the Apple HP media path
/// (HP-PHASE4-SPECS §5.6-5.7 / crib §3h). AES-256-CTR + HMAC-SHA1-80, RTCP KDF **labels 3/4/5**.
///
/// TX `protect` (D1 Must) wraps outbound RR/FIR so AVConference keeps the stream alive; RX
/// `unprotect` + `parseSRArrivals` (D3 Could) recover inbound SR timing. Session keys are derived
/// once from the 46-byte master blob (our TX uses `video_key_v`).
///
/// SRTCP layout: `hdr(8, clear) ‖ ciphertext ‖ e_index(4) ‖ auth(10)`, where `e_index` is the
/// E-flag (bit31, always set on TX) OR the 31-bit SRTCP index, the ciphertext is AES-256-CTR over
/// everything after the clear 8-byte header, and the auth tag is HMAC-SHA1-80 over
/// `hdr ‖ ciphertext ‖ e_index`. The IV reuses `AppleSRTPKeySchedule.counterBlock` with the SRTCP
/// index (crib §3h — same integer formula as RTP).
///
/// `protect` must be called serially (from the single RTCP TX loop); `txIndex` is not lock-guarded.
/// Security (NFR-6): never log the session keys, salt, or IVs.
final class AppleSRTCPProtector {
    static let authTagLen = 10
    static let eIndexLen = 4
    static let clearHeaderLen = 8               // RTCP header (4) + sender SSRC (4)
    static let eFlag: UInt32 = 0x8000_0000
    static let indexMask: UInt32 = 0x7FFF_FFFF
    static let minProtectedLen = clearHeaderLen + eIndexLen + authTagLen  // 22

    private let sessionKeys: AppleSRTPKeySchedule.SessionKeys
    private let saltIV: [UInt8]                  // 16-byte salt_int base (label-5 salt ‖ 0x0000)

    /// Monotonic SRTCP TX index. Starts at 0, increments once per `protect`. Exposed read-only.
    private(set) var txIndex: UInt32 = 0

    /// Build a protector from a 46-byte SRTP master blob (the `video_key_v` blob for our TX).
    init(masterBlob: Data) throws {
        self.sessionKeys = try AppleSRTPKeySchedule.deriveRTCPSessionKeys(blob: masterBlob)
        self.saltIV = [UInt8](try AppleSRTPKeySchedule.saltIV16(sessionSalt: sessionKeys.salt))
    }

    /// SRTCP-protect one plaintext RTCP packet (crib §3h). Consumes one TX index.
    func protect(_ rtcp: Data) throws -> Data {
        guard rtcp.count >= Self.clearHeaderLen else {
            throw VNCError.protocol(.invalidData)
        }
        let index = txIndex
        txIndex &+= 1

        let bytes = [UInt8](rtcp)
        let header = Array(bytes[0..<Self.clearHeaderLen])
        let plaintext = Array(bytes[Self.clearHeaderLen...])
        let ssrc = Self.beUInt32(bytes, offset: 4)

        var body = Data(header)
        if !plaintext.isEmpty {
            let iv = AppleSRTPKeySchedule.counterBlock(saltIV16: saltIV, ssrc: ssrc, index: UInt64(index))
            let aes = try AES(key: Array(sessionKeys.encryption), blockMode: CTR(iv: iv), padding: .noPadding)
            body.append(contentsOf: try aes.encrypt(plaintext))
        }
        // E-flag always set on TX (encrypted) ‖ 31-bit index.
        body.append(Self.eFlag | (index & Self.indexMask), bigEndian: true)

        let tag = try HMAC(key: Array(sessionKeys.authentication), variant: .sha1).authenticate([UInt8](body))
        return body + Data(tag.prefix(Self.authTagLen))
    }

    /// SRTCP-unprotect one packet (crib §3h). Returns the plaintext RTCP (`header ‖ payload`) on a
    /// valid tag, else `nil` (auth failure / too short). Handles the E=0 (unencrypted) case.
    func unprotect(_ srtcp: Data) -> Data? {
        guard srtcp.count >= Self.minProtectedLen else { return nil }
        let bytes = [UInt8](srtcp)
        let bodyLen = bytes.count - Self.authTagLen
        let body = Array(bytes[0..<bodyLen])
        let receivedTag = Array(bytes[bodyLen...])

        guard let digest = try? HMAC(key: Array(sessionKeys.authentication), variant: .sha1)
            .authenticate(body) else { return nil }
        guard AppleSRPClient.constantTimeEquals(Data(digest.prefix(Self.authTagLen)),
                                                Data(receivedTag)) else { return nil }

        let eIndexOffset = bodyLen - Self.eIndexLen
        let eIndex = Self.beUInt32(bytes, offset: eIndexOffset)
        let encrypted = (eIndex & Self.eFlag) != 0
        let index = eIndex & Self.indexMask
        let header = Array(bytes[0..<Self.clearHeaderLen])
        let ciphertext = Array(bytes[Self.clearHeaderLen..<eIndexOffset])

        guard encrypted, !ciphertext.isEmpty else {
            return Data(header) + Data(ciphertext)
        }

        let ssrc = Self.beUInt32(bytes, offset: 4)
        let iv = AppleSRTPKeySchedule.counterBlock(saltIV16: saltIV, ssrc: ssrc, index: UInt64(index))
        guard let aes = try? AES(key: Array(sessionKeys.encryption), blockMode: CTR(iv: iv), padding: .noPadding),
              let plaintext = try? aes.decrypt(ciphertext) else { return nil }
        return Data(header) + Data(plaintext)
    }

    /// Walk a plaintext compound RTCP buffer and return each SR's `(ssrc, ntpMid32)` (crib §3i).
    /// The caller stamps arrival time (kept out to preserve determinism). Non-crypto — operates on
    /// already-unprotected RTCP.
    static func parseSRArrivals(_ data: Data) -> [(ssrc: UInt32, ntpMid32: UInt32)] {
        var out: [(ssrc: UInt32, ntpMid32: UInt32)] = []
        let bytes = [UInt8](data)
        var pos = 0
        while pos + 4 <= bytes.count {
            let pt = bytes[pos + 1]
            let length = Int(bytes[pos + 2]) << 8 | Int(bytes[pos + 3])
            let pktLen = (length + 1) * 4
            guard pktLen > 0, pos + pktLen <= bytes.count else { break }
            if pt == AppleRTCPBuilders.ptSenderReport && pktLen >= 28 {
                let ssrc = beUInt32(bytes, offset: pos + 4)
                let ntpSec = beUInt32(bytes, offset: pos + 8)
                let ntpFrac = beUInt32(bytes, offset: pos + 12)
                let mid32 = ((ntpSec & 0xFFFF) << 16) | ((ntpFrac >> 16) & 0xFFFF)
                out.append((ssrc: ssrc, ntpMid32: mid32))
            }
            pos += pktLen
        }
        return out
    }

    // MARK: - Byte helpers

    private static func beUInt32(_ bytes: [UInt8], offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }

    private static func beBytes32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
    }
}
