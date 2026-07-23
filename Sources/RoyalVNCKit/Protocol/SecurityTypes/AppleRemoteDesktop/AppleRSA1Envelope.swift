#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) framing for the Apple Remote Desktop "RSA1" auth-33 envelopes.
///
/// Responsibilities (HP-SPECS §5.2 / dossier §3.2):
/// - `rsa1Init()` — the 10-byte RSA1 init body.
/// - `parseSPKI(_:)` — DER SubjectPublicKeyInfo → RSA `(n, e)`.
/// - `identity(username:)` — the identity blob that the coordinator RSA-encrypts.
/// - `c2s1(rsaEncrypted:)` — the 650-byte step-1 envelope wrapping the 256-byte RSA block.
/// - `c2s2(A:M1:opts:clientRandom:)` — the 1076-byte step-3 envelope.
///
/// This type performs **no** RSA encryption itself: `c2s1` receives the already-encrypted 256-byte
/// block (`rsaEncrypted:`). RSA-PKCS#1 encryption (with injectable padding per NFR-3) and the SRP
/// iteration-count wire read live in the auth coordinator (`ARDRSASRPAuthentication`, Phase 5c).
///
/// `parseSPKI` is a hand-written DER walk rather than CryptoSwift's `ASN1.Decoder`: that decoder
/// (and the whole `ASN1` enum) is `internal` to the CryptoSwift module and therefore unreachable
/// from RoyalVNCKit. HP-SPECS §5.2 anticipates this with its "small pure ASN.1 walk" fallback.
enum AppleRSA1Envelope {
    /// The `rsaEncryption` OID value bytes (1.2.840.113549.1.1.1), i.e. the content of the OID TLV.
    static let rsaEncryptionOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

    /// RSA1 init body (HP-SPECS §5.2 step 0): `01 00 'RSA1' 00 00 00 00` (10 bytes).
    ///
    /// The `0x21` security-type selector and the `u32` length prefix (`00 00 00 0a`) are prepended
    /// by the coordinator, not here.
    static func rsa1Init() -> Data {
        var data = Data()
        data.append(contentsOf: [0x01, 0x00])                   // version
        data.append(contentsOf: [0x52, 0x53, 0x41, 0x31])       // 'RSA1'
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00])       // reserved
        return data
    }

    // MARK: - SPKI parsing

    /// Extract RSA `(n, e)` from a DER-encoded SubjectPublicKeyInfo (RFC5280 §4.1.2.7).
    ///
    /// `SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING(RSAPublicKey) }` where
    /// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    ///
    /// Returned `n`/`e` are minimal big-endian magnitudes (a DER INTEGER's leading `0x00` sign byte
    /// is stripped). Throws `VNCError.protocol(.invalidData)` on truncated data, a wrong outer tag,
    /// a non-RSA algorithm OID, or any structural violation.
    static func parseSPKI(_ der: Data) throws -> (n: Data, e: Data) {
        var reader = DERReader(bytes: Array(der))

        // SubjectPublicKeyInfo SEQUENCE
        let spki = try reader.readConstructed(expected: 0x30)
        var spkiReader = DERReader(bytes: spki)

        // AlgorithmIdentifier SEQUENCE { OID, ... }
        // Note: Per HP-SPECS §5.2 code-review F2, AlgorithmIdentifier parameters are intentionally
        // not validated (should be absent or NULL). The downstream (n,e) extraction from the public
        // key BIT STRING fully constrains the key material, mitigating risk from unexpected parameters.
        let algId = try spkiReader.readConstructed(expected: 0x30)
        var algReader = DERReader(bytes: algId)
        let oid = try algReader.readPrimitive(expected: 0x06)
        guard oid == rsaEncryptionOID else {
            throw VNCError.protocol(.invalidData)
        }

        // subjectPublicKey BIT STRING → its content is `00`(unused bits) || RSAPublicKey DER.
        let bitString = try spkiReader.readPrimitive(expected: 0x03)
        guard let firstByte = bitString.first, firstByte == 0x00 else {
            throw VNCError.protocol(.invalidData)
        }
        let rsaPublicKeyDER = Array(bitString.dropFirst())

        // RSAPublicKey SEQUENCE { INTEGER n, INTEGER e }
        var pkReader = DERReader(bytes: rsaPublicKeyDER)
        let inner = try pkReader.readConstructed(expected: 0x30)
        var innerReader = DERReader(bytes: inner)
        let n = try innerReader.readPrimitive(expected: 0x02)
        let e = try innerReader.readPrimitive(expected: 0x02)

        let nStripped = stripLeadingZeros(n)
        let eStripped = stripLeadingZeros(e)

        // Reject degenerate keys: modulus must be > 1 byte, exponent must be non-empty.
        guard nStripped.count > 1, !eStripped.isEmpty else {
            throw VNCError.protocol(.invalidData)
        }

        return (n: nStripped, e: eStripped)
    }

    private static func stripLeadingZeros(_ bytes: [UInt8]) -> Data {
        var slice = bytes[...]

        while let first = slice.first, first == 0x00, slice.count > 1 {
            slice = slice.dropFirst()
        }

        return Data(slice)
    }

    // MARK: - Identity

    /// The identity blob (dossier §3.2 step 1):
    /// `u32 payload_len || u32 username_len || username || u16 0 || u8 0`.
    ///
    /// `payload_len` counts the bytes following it (`username_len` + username + the trailing `u16`
    /// and `u8`), i.e. `7 + username.utf8.count`. All lengths big-endian. For the empty username
    /// (the Apple auth-33 case) this is an 11-byte blob with `payload_len = 7`.
    static func identity(username: String) -> Data {
        let usernameBytes = Data(username.utf8)
        let usernameLen = UInt32(usernameBytes.count)
        let payloadLen = UInt32(4 + usernameBytes.count + 2 + 1)

        var data = Data()
        data.append(bigEndian32(payloadLen))
        data.append(bigEndian32(usernameLen))
        data.append(usernameBytes)
        data.append(bigEndian16(0))
        data.append(0x00)
        return data
    }

    // MARK: - c2s1 / c2s2

    /// The 650-byte step-1 envelope (HP-SPECS §5.2 step 1) wrapping the 256-byte RSA block:
    /// `01 00 || 'RSA1' || 00 02 || 01 00 || rsaEncrypted[256] || zero[384]`.
    ///
    /// - Parameter rsaEncrypted: The `RSA-PKCS#1v1.5(server_pub, identity)` output, exactly 256B.
    static func c2s1(rsaEncrypted: Data) throws -> Data {
        guard rsaEncrypted.count == 256 else {
            throw VNCError.protocol(.invalidData)
        }

        var data = Data()
        data.append(contentsOf: [0x01, 0x00])                   // version
        data.append(contentsOf: [0x52, 0x53, 0x41, 0x31])       // 'RSA1'
        data.append(bigEndian16(0x0002))                        // authtype = 2
        data.append(bigEndian16(0x0100))                        // inner_len = 256
        data.append(rsaEncrypted)                               // 256 bytes
        data.append(Data(repeating: 0, count: 384))             // zero padding
        // 2 + 4 + 2 + 2 + 256 + 384 = 650
        return data
    }

    /// The step-3 envelope (HP-SPECS §5.2 step 3), zero-padded ("framed") to 1076 bytes:
    /// `u16 A_len || A || u8 64 || M1[64] || u16 opts_len || opts || u8 16 || client_random[16]`.
    ///
    /// The exact 1076-byte composition (A wire-width, pad placement) is oracle-gated at O5
    /// (HP-SPECS §8): this takes the literal dossier field list and zero-pads the remainder, with
    /// `A` written at its supplied length (`AppleSRPClient` supplies the 512-byte PAD-ed `A`).
    static func c2s2(A: Data, M1: Data, opts: Data, clientRandom: Data) throws -> Data {
        guard M1.count == 64, clientRandom.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }
        guard A.count <= 0xFFFF, opts.count <= 0xFFFF else {
            throw VNCError.protocol(.invalidData)
        }

        var data = Data()
        data.append(bigEndian16(UInt16(A.count)))               // A_len
        data.append(A)
        data.append(0x40)                                       // u8 64
        data.append(M1)                                         // 64 bytes
        data.append(bigEndian16(UInt16(opts.count)))            // opts_len
        data.append(opts)
        data.append(0x10)                                       // u8 16
        data.append(clientRandom)                               // 16 bytes

        guard data.count <= 1076 else {
            throw VNCError.protocol(.invalidData)
        }
        if data.count < 1076 {
            data.append(Data(repeating: 0, count: 1076 - data.count))
        }
        return data
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

/// Minimal DER TLV reader for `parseSPKI`. Supports the definite-length short and long forms and
/// throws `VNCError.protocol(.invalidData)` on any out-of-bounds or malformed length.
private struct DERReader {
    private let bytes: [UInt8]
    private var position = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// Read a constructed TLV (e.g. SEQUENCE) and return its content bytes.
    mutating func readConstructed(expected tag: UInt8) throws -> [UInt8] {
        try readValue(expected: tag)
    }

    /// Read a primitive TLV (e.g. INTEGER, OID, BIT STRING) and return its content bytes.
    mutating func readPrimitive(expected tag: UInt8) throws -> [UInt8] {
        try readValue(expected: tag)
    }

    private mutating func readValue(expected tag: UInt8) throws -> [UInt8] {
        let actualTag = try readByte()
        guard actualTag == tag else {
            throw VNCError.protocol(.invalidData)
        }

        let length = try readLength()
        guard position + length <= bytes.count else {
            throw VNCError.protocol(.invalidData)
        }

        let value = Array(bytes[position..<(position + length)])
        position += length
        return value
    }

    private mutating func readByte() throws -> UInt8 {
        guard position < bytes.count else {
            throw VNCError.protocol(.invalidData)
        }

        let byte = bytes[position]
        position += 1
        return byte
    }

    private mutating func readLength() throws -> Int {
        let first = try readByte()

        // Short form: bit 7 clear, length is the low 7 bits.
        if first & 0x80 == 0 {
            return Int(first)
        }

        // Long form: low 7 bits give the number of subsequent length octets (big-endian).
        let numberOfBytes = Int(first & 0x7F)
        guard numberOfBytes > 0, numberOfBytes <= 8 else {
            throw VNCError.protocol(.invalidData)
        }

        var lengthValue: UInt64 = 0
        for _ in 0..<numberOfBytes {
            lengthValue = (lengthValue << 8) | UInt64(try readByte())
        }

        // Guard against overflow: the accumulated length must fit safely in Int and remain non-negative.
        guard let length = Int(exactly: lengthValue), length >= 0 else {
            throw VNCError.protocol(.invalidData)
        }

        return length
    }
}
