#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

/// Pure (Foundation-only, no socket) encoder for the Apple encrypted input event `0x10`
/// (HP-SPECS §5.5 / dossier §3.3).
///
/// `EncryptedInputEvent = 0x10 00 || AES-128-ECB(16-byte block)`, with `byte[10] = 0xff` sentinel,
/// where the ECB block is keyed on the CURRENT rotated CBC **content key** — never the SRP wrap key
/// (getting this wrong silently drops all input; `input.py:75`). The whole `0x10` message is then
/// sent as a normal CBC record by the record layer (Phase 5c).
enum AppleInputEventCodec {
    /// Index within the 16-byte block that must hold the `0xff` sentinel.
    static let sentinelIndex = 10

    /// Encode a 16-byte input block into the `0x10` message.
    ///
    /// - Parameters:
    ///   - block: The 16-byte plaintext input block. `byte[10]` is forced to `0xff` regardless of
    ///     its incoming value.
    ///   - contentKey: The 16-byte current CBC content key (NOT the SRP wrap key).
    /// - Returns: `0x10 00 || AES-128-ECB(block')` (18 bytes).
    static func encode0x10(block: Data, contentKey: Data) throws -> Data {
        guard block.count == 16, contentKey.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }

        var blockBytes = Array(block)
        blockBytes[sentinelIndex] = 0xff

        do {
            let aes = try AES(key: Array(contentKey), blockMode: ECB(), padding: .noPadding)
            let encrypted = try aes.encrypt(blockBytes)

            var message = Data([0x10, 0x00])
            message.append(contentsOf: encrypted)
            return message
        } catch {
            throw VNCError.protocol(.invalidData)
        }
    }
}
