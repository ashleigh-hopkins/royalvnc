#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

/// Pure (Foundation-only, no socket) key schedule for the Apple `0x44f` rekey (HP-SPECS §5.3 /
/// dossier §3.3).
///
/// The 36-byte rekey carries a 32-bit generation and two independently AES-128-ECB-wrapped 16-byte
/// halves (`enc_key`, `enc_iv`). Each half is unwrapped independently under the current wrap key.
/// The recovered `(key, iv)` become BOTH the AES-128-CBC content key/iv (both directions) AND the
/// next wrap key used to unwrap the following rekey.
///
/// An inline AES-128-ECB **decrypt** is used because `Encryption/AES128ECBEncryption.swift`
/// only exposes an encrypt path; it cannot be extended without stepping outside this task's
/// five-seam scope. The same vendored CryptoSwift AES primitive is used — no new dependency (NFR-4).
enum AppleRecordKeySchedule {
    /// Total wire size of a `0x44f` rekey body.
    static let rekeyLength = 36

    /// Parse a 36-byte `0x44f` rekey body into its generation and the two wrapped 16-byte halves.
    ///
    /// Layout: `u32 generation || enc_key[16] || enc_iv[16]` (generation big-endian, RFB convention).
    static func parseRekey(_ data: Data) throws -> (gen: UInt32, keyWrapped: Data, ivWrapped: Data) {
        guard data.count == rekeyLength else {
            throw VNCError.protocol(.invalidData)
        }

        let bytes = Array(data)
        let gen = (UInt32(bytes[0]) << 24)
            | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8)
            | UInt32(bytes[3])
        let keyWrapped = Data(bytes[4..<20])
        let ivWrapped = Data(bytes[20..<36])

        return (gen: gen, keyWrapped: keyWrapped, ivWrapped: ivWrapped)
    }

    /// Independently AES-128-ECB-decrypt the two wrapped halves under `wrapKey`.
    ///
    /// - Parameters:
    ///   - wrapped: The `(keyWrapped, ivWrapped)` halves from `parseRekey`.
    ///   - wrapKey: The current 16-byte wrap key (`SHA-256(K)[0:16]` for the first rekey, or the
    ///     previously-recovered key for subsequent rekeys).
    /// - Returns: The recovered 16-byte content `key` and `iv`.
    static func unwrap(_ wrapped: (keyWrapped: Data, ivWrapped: Data),
                       wrapKey: Data) throws -> (key: Data, iv: Data) {
        guard wrapKey.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }

        let key = try ecbDecryptBlock(wrapped.keyWrapped, wrapKey: wrapKey)
        let iv = try ecbDecryptBlock(wrapped.ivWrapped, wrapKey: wrapKey)

        return (key: key, iv: iv)
    }

    /// The wrap key used to unwrap the *next* rekey: the currently-recovered content key itself
    /// (HP-SPECS §5.3 — "recovered key/iv become … the next wrap key"). Forward rotation only.
    static func nextWrapKey(recoveredKey: Data) throws -> Data {
        guard recoveredKey.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }

        return recoveredKey
    }

    // MARK: - AES-128-ECB decrypt (no padding, single block)

    private static func ecbDecryptBlock(_ block: Data, wrapKey: Data) throws -> Data {
        guard block.count == 16, wrapKey.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }

        do {
            let aes = try AES(key: Array(wrapKey), blockMode: ECB(), padding: .noPadding)
            let plaintext = try aes.decrypt(Array(block))
            return Data(plaintext)
        } catch {
            throw VNCError.protocol(.invalidData)
        }
    }
}
