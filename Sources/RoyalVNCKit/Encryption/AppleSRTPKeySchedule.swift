#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

/// Pure (Foundation-only, no socket) SRTP key schedule for the Apple HP media path (HP-PHASE4-SPECS
/// §5.4 / crib §3a–§3b). RFC-3711 AES-CM key-derivation using an **AES-256** PRF.
///
/// A 46-byte master blob = 32-byte master key ‖ 14-byte master salt. From it the RTP session keys are
/// derived once (kdr = 0, no per-packet rekey): `enc = KDF(label 0, 32)`, `auth = KDF(label 1, 20)`,
/// `salt = KDF(label 2, 14)`. The viewer decrypts video with the `vks` (server→viewer) blob.
///
/// KDF (RFC 3711 §4.3.1): `iv0 = (14 zero bytes with byte[7]=label) XOR master_salt`; the AES-CM
/// keystream block `i` is `AES-256-ECB(master_key, iv0 ‖ u16-BE(i))` (the 128-bit counter is `iv0<<16`
/// plus the block index in its low 16 bits — no carry into `iv0` for the ≤2 blocks we ever need);
/// concatenate blocks and truncate to `outLen`.
///
/// Security (NFR-6): callers must never log the returned key material. All inputs are value-typed;
/// no `CCCryptorRef` (uses the already-vendored CryptoSwift, per NFR-4).
enum AppleSRTPKeySchedule {
    static let masterKeyLen = 32
    static let masterSaltLen = 14
    static let blobLen = 46          // masterKeyLen + masterSaltLen

    /// KDF labels (crib §3b): RTP 0/1/2, RTCP 3/4/5.
    enum Label: UInt8 {
        case rtpEncryption = 0
        case rtpAuthentication = 1
        case rtpSalt = 2
        case rtcpEncryption = 3
        case rtcpAuthentication = 4
        case rtcpSalt = 5
    }

    /// Session key sizes (crib §3b).
    static let sessionEncLen = 32
    static let sessionAuthLen = 20
    static let sessionSaltLen = 14

    struct SessionKeys {
        let encryption: Data   // 32 B — AES-256-CTR key
        let authentication: Data   // 20 B — HMAC-SHA1 key
        let salt: Data         // 14 B — session salt (feeds the per-packet IV)
    }

    /// Split a 46-byte master blob into `(masterKey[32], masterSalt[14])`.
    static func split(blob: Data) throws -> (masterKey: Data, masterSalt: Data) {
        guard blob.count == blobLen else {
            throw VNCError.protocol(.invalidData)
        }
        let bytes = Array(blob)
        return (masterKey: Data(bytes[0..<masterKeyLen]),
                masterSalt: Data(bytes[masterKeyLen..<blobLen]))
    }

    /// Derive the three RTP session keys from a master blob (crib §3b).
    static func deriveRTPSessionKeys(blob: Data) throws -> SessionKeys {
        let (masterKey, masterSalt) = try split(blob: blob)
        return SessionKeys(
            encryption: try kdf(masterKey: masterKey, masterSalt: masterSalt,
                                label: .rtpEncryption, outLen: sessionEncLen),
            authentication: try kdf(masterKey: masterKey, masterSalt: masterSalt,
                                    label: .rtpAuthentication, outLen: sessionAuthLen),
            salt: try kdf(masterKey: masterKey, masterSalt: masterSalt,
                          label: .rtpSalt, outLen: sessionSaltLen))
    }

    /// Derive the three RTCP session keys from a master blob (crib §3b/§3h, labels 3/4/5). Same
    /// sizes as RTP. Used by `AppleSRTCPProtector` to encrypt/authenticate outbound RTCP.
    static func deriveRTCPSessionKeys(blob: Data) throws -> SessionKeys {
        let (masterKey, masterSalt) = try split(blob: blob)
        return SessionKeys(
            encryption: try kdf(masterKey: masterKey, masterSalt: masterSalt,
                                label: .rtcpEncryption, outLen: sessionEncLen),
            authentication: try kdf(masterKey: masterKey, masterSalt: masterSalt,
                                    label: .rtcpAuthentication, outLen: sessionAuthLen),
            salt: try kdf(masterKey: masterKey, masterSalt: masterSalt,
                          label: .rtcpSalt, outLen: sessionSaltLen))
    }

    /// RFC-3711 AES-CM KDF with an AES-256 PRF (crib §3b).
    static func kdf(masterKey: Data, masterSalt: Data, label: Label, outLen: Int) throws -> Data {
        try kdf(masterKey: masterKey, masterSalt: masterSalt, label: label.rawValue, outLen: outLen)
    }

    /// Raw-label variant (RTCP labels 3/4/5 reuse this).
    static func kdf(masterKey: Data, masterSalt: Data, label: UInt8, outLen: Int) throws -> Data {
        guard masterKey.count == masterKeyLen, masterSalt.count == masterSaltLen, outLen > 0 else {
            throw VNCError.protocol(.invalidData)
        }

        // iv0 = key_id XOR master_salt, key_id = 14 zero bytes with byte[7] = label.
        var iv0 = Array(masterSalt)               // 14 bytes
        iv0[7] ^= label

        var keystream = [UInt8]()
        keystream.reserveCapacity(((outLen + 15) / 16) * 16)

        var blockIndex: UInt16 = 0
        while keystream.count < outLen {
            // Counter block = iv0(14) ‖ u16-BE(blockIndex). (iv0<<16 + blockIndex; no carry for our sizes.)
            var block = iv0
            block.append(UInt8(blockIndex >> 8))
            block.append(UInt8(blockIndex & 0xFF))

            keystream.append(contentsOf: try Self.aes256ECBBlock(block, key: masterKey))
            blockIndex &+= 1
        }

        return Data(keystream.prefix(outLen))
    }

    /// The 16-byte IV base for the per-packet AES-CTR counter: `salt_int = int(salt(14) ‖ 0x0000)`
    /// as a 16-byte big-endian value (crib §3b/§3d). The decryptor XORs SSRC/index into this.
    static func saltIV16(sessionSalt: Data) throws -> Data {
        guard sessionSalt.count == sessionSaltLen else {
            throw VNCError.protocol(.invalidData)
        }
        return sessionSalt + Data([0x00, 0x00])
    }

    // MARK: - Shared AES-CTR initial counter (SRTP + SRTCP)

    /// Build the 16-byte AES-CTR initial counter shared by SRTP and SRTCP (crib §3d/§3h,
    /// RFC 3711 §4.1.1): `IV = salt_int XOR (ssrc<<64) XOR (index<<16)`. `index` is the 48-bit RTP
    /// packet index `((roc<<16)|seq)` or the 32-bit SRTCP index — both land in the low 64-bit word.
    /// The low 16 bits (bytes 14-15) stay 0: the AES-CTR block counter starts there.
    ///
    /// Computed on the 128-bit value split into two `UInt64` halves so the byte positions follow
    /// the arithmetic exactly (`ssrc` → bytes 4-7, `index` → bytes 8-13 for RTP / 10-13 for SRTCP).
    static func counterBlock(saltIV16: [UInt8], ssrc: UInt32, index: UInt64) -> [UInt8] {
        precondition(saltIV16.count == 16, "CTR salt IV must be 16 bytes")
        var hi = beUInt64(saltIV16, offset: 0)   // bytes 0-7  (bits 64-127)
        var lo = beUInt64(saltIV16, offset: 8)   // bytes 8-15 (bits 0-63)
        hi ^= UInt64(ssrc)                       // ssrc<<64 → high word bits 64-95
        lo ^= index << 16                        // index<<16 → low word bits 16-63
        return beBytes64(hi) + beBytes64(lo)
    }

    private static func beUInt64(_ bytes: [UInt8], offset: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v = (v << 8) | UInt64(bytes[offset + i]) }
        return v
    }

    private static func beBytes64(_ value: UInt64) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 { out[i] = UInt8((value >> (8 * (7 - i))) & 0xFF) }
        return out
    }

    // MARK: - AES-256-ECB single block (no padding) — the KDF PRF

    private static func aes256ECBBlock(_ block: [UInt8], key: Data) throws -> [UInt8] {
        guard block.count == 16, key.count == masterKeyLen else {
            throw VNCError.protocol(.invalidData)
        }
        do {
            let aes = try AES(key: Array(key), blockMode: ECB(), padding: .noPadding)
            return try aes.encrypt(block)
        } catch {
            throw VNCError.protocol(.invalidData)
        }
    }
}
