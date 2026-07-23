#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

/// Pure (Foundation-only, no socket) AES-128-CBC control-record codec (HP-SPECS §5.4 / dossier §3.3).
///
/// Wire record: `u16 ciphertext_len (nonzero, multiple of 16, big-endian) || ciphertext`.
/// Plaintext (before CBC): `u16 body_len || body || filler || trailer[20]`, where
/// `filler_len = (−(2 + body_len + 20)) mod 16` and
/// `trailer = SHA1(u32_be(seq) || plaintext-excluding-trailer)` — plain SHA-1, NOT HMAC.
///
/// The filler is random padding purely for 16-byte alignment; `open` MUST NOT validate its value
/// (it only re-checks the SHA-1 trailer). The persistent per-direction CBC IV is modelled by the
/// `iv` in / `nextIV` out threading (the caller feeds each record's `nextIV` as the next `iv`);
/// the IV is chained across records and never reset. `seq` is supplied by the caller (per-direction,
/// monotonic, never reset even across rekey).
enum AppleControlRecordCodec {
    /// SHA-1 trailer length in bytes.
    static let trailerLength = 20

    /// `filler_len = (−(2 + body_len + 20)) mod 16` — pads the plaintext up to a 16-byte boundary.
    static func fillerLen(bodyLen: Int) -> Int {
        let unpadded = 2 + bodyLen + trailerLength
        let remainder = unpadded % 16

        return (16 - remainder) % 16
    }

    /// `trailer = SHA1(u32_be(seq) || plaintextExcludingTrailer)` (plain SHA-1).
    ///
    /// - Parameter plaintextExcludingTrailer: `u16 body_len || body || filler`.
    static func trailer(seq: UInt32, plaintext plaintextExcludingTrailer: Data) -> Data {
        var input = bigEndian32(seq)
        input.append(plaintextExcludingTrailer)

        return Data(SHA1().calculate(for: Array(input)))
    }

    /// Build one CBC record from a plaintext body.
    ///
    /// - Parameters:
    ///   - body: The RFB message bytes to wrap.
    ///   - seq: The per-direction sequence number (folded into the SHA-1 trailer).
    ///   - iv: The 16-byte CBC IV for this record (the previous record's `nextIV`).
    ///   - key: The 16-byte AES-128 content key.
    ///   - filler: Optional explicit filler bytes; must equal `fillerLen(bodyLen:)` in length. When
    ///     `nil`, non-secret random filler is generated (NFR-3 lets tests inject deterministic bytes).
    /// - Returns: The wire `record` (`u16 ciphertext_len || ciphertext`) and the `nextIV` (this
    ///   record's last ciphertext block) for chaining into the next `seal`.
    static func seal(body: Data,
                     seq: UInt32,
                     iv: Data,
                     key: Data,
                     filler: Data? = nil) throws -> (record: Data, nextIV: Data) {
        guard key.count == 16, iv.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }
        guard body.count <= 0xFFFF else {
            throw VNCError.protocol(.invalidData)
        }

        let fillerLength = fillerLen(bodyLen: body.count)
        let fillerBytes: Data
        if let filler {
            guard filler.count == fillerLength else {
                throw VNCError.protocol(.invalidData)
            }
            fillerBytes = filler
        } else {
            fillerBytes = Data((0..<fillerLength).map { _ in UInt8.random(in: 0...255) })
        }

        var plaintextExcludingTrailer = bigEndian16(UInt16(body.count))
        plaintextExcludingTrailer.append(body)
        plaintextExcludingTrailer.append(fillerBytes)

        let recordTrailer = trailer(seq: seq, plaintext: plaintextExcludingTrailer)

        var plaintext = plaintextExcludingTrailer
        plaintext.append(recordTrailer)

        let ciphertext = try cbcEncrypt(plaintext, key: key, iv: iv)

        var record = bigEndian16(UInt16(ciphertext.count))
        record.append(ciphertext)

        let nextIV = Data(ciphertext.suffix(16))

        return (record: record, nextIV: nextIV)
    }

    /// Parse and decrypt one CBC record, verifying its SHA-1 trailer.
    ///
    /// - Parameters:
    ///   - record: The wire record (`u16 ciphertext_len || ciphertext`).
    ///   - seq: The per-direction sequence number expected for this record.
    ///   - iv: The 16-byte CBC IV for this record.
    ///   - key: The 16-byte AES-128 content key.
    /// - Returns: The recovered `body` and the `nextIV` for chaining into the next `open`.
    /// - Throws: `VNCError.protocol(.invalidData)` on a bad length frame or a SHA-1 trailer mismatch
    ///   (no partial-plaintext delivery). Filler bytes are never validated.
    static func open(record: Data,
                     seq: UInt32,
                     iv: Data,
                     key: Data) throws -> (body: Data, nextIV: Data) {
        guard key.count == 16, iv.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }

        let recordBytes = Array(record)
        guard recordBytes.count >= 2 else {
            throw VNCError.protocol(.invalidData)
        }

        let ciphertextLen = (Int(recordBytes[0]) << 8) | Int(recordBytes[1])
        guard ciphertextLen != 0,
              ciphertextLen % 16 == 0,
              recordBytes.count == 2 + ciphertextLen else {
            throw VNCError.protocol(.invalidData)
        }

        let ciphertext = Data(recordBytes[2..<(2 + ciphertextLen)])
        let plaintext = try cbcDecrypt(ciphertext, key: key, iv: iv)

        let plaintextBytes = Array(plaintext)
        guard plaintextBytes.count >= 2 + trailerLength else {
            throw VNCError.protocol(.invalidData)
        }

        let bodyLen = (Int(plaintextBytes[0]) << 8) | Int(plaintextBytes[1])
        let expectedLength = 2 + bodyLen + fillerLen(bodyLen: bodyLen) + trailerLength
        guard plaintextBytes.count == expectedLength else {
            throw VNCError.protocol(.invalidData)
        }

        let body = Data(plaintextBytes[2..<(2 + bodyLen)])

        let trailerStart = plaintextBytes.count - trailerLength
        let plaintextExcludingTrailer = Data(plaintextBytes[0..<trailerStart])
        let receivedTrailer = Data(plaintextBytes[trailerStart..<plaintextBytes.count])
        let expectedTrailer = trailer(seq: seq, plaintext: plaintextExcludingTrailer)
        guard receivedTrailer == expectedTrailer else {
            throw VNCError.protocol(.invalidData)
        }

        let nextIV = Data(ciphertext.suffix(16))

        return (body: body, nextIV: nextIV)
    }

    // MARK: - AES-128-CBC (no padding)

    private static func cbcEncrypt(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
        do {
            let aes = try AES(key: Array(key), blockMode: CBC(iv: Array(iv)), padding: .noPadding)
            return Data(try aes.encrypt(Array(plaintext)))
        } catch {
            throw VNCError.protocol(.invalidData)
        }
    }

    private static func cbcDecrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        do {
            let aes = try AES(key: Array(key), blockMode: CBC(iv: Array(iv)), padding: .noPadding)
            return Data(try aes.decrypt(Array(ciphertext)))
        } catch {
            throw VNCError.protocol(.invalidData)
        }
    }

    // MARK: - Big-endian helpers

    private static func bigEndian16(_ value: UInt16) -> Data {
        Data([UInt8(value >> 8), UInt8(value & 0xFF)])
    }

    private static func bigEndian32(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ])
    }
}
