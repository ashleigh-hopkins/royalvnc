#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) RTP header parser for the Apple HP media path
/// (HP-PHASE4-SPECS §5.4 / crib §3f). All multibyte fields are **BIG-ENDIAN**.
///
/// Layout (RFC 3550 fixed header, 12 bytes minimum):
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// |                           timestamp                           |
/// |                             SSRC                              |
/// |                       CSRC (0..CC) ...                        |
/// ```
///
/// `headerLength = 12 + CC*4`, plus (if the extension bit `X` is set) a 4-byte extension
/// header (`profile:16 ‖ extWordCount:16`) followed by `extWordCount*4` extension bytes.
///
/// No RTP-version validation and **no payload-type allow-list** — the reference reads the
/// PT verbatim (`pkt[1] & 0x7F`) and logs it (crib §3f).
struct AppleRTPHeader: Equatable {
    /// Minimum fixed-header length (RFC 3550): 12 bytes.
    static let fixedHeaderLength = 12

    let version: UInt8          // pkt[0] >> 6 (not validated)
    let csrcCount: UInt8        // pkt[0] & 0x0F
    let hasExtension: Bool      // (pkt[0] >> 4) & 1
    let marker: Bool            // pkt[1] & 0x80
    let payloadType: UInt8      // pkt[1] & 0x7F
    let sequenceNumber: UInt16  // pkt[2:4]  BE
    let timestamp: UInt32       // pkt[4:8]  BE
    let ssrc: UInt32            // pkt[8:12] BE
    /// Total header length in bytes (fixed + CSRC list + optional extension). The encrypted
    /// payload begins at this offset.
    let headerLength: Int

    /// Parse an RTP header. Returns `nil` if the buffer is too short to contain the declared
    /// fixed header, CSRC list, or extension header (malformed → drop, crib §3f).
    static func parse(_ packet: Data) -> AppleRTPHeader? {
        let bytes = [UInt8](packet)
        guard bytes.count >= fixedHeaderLength else { return nil }

        let version = bytes[0] >> 6
        let csrcCount = bytes[0] & 0x0F
        let hasExtension = ((bytes[0] >> 4) & 1) == 1
        let marker = (bytes[1] & 0x80) != 0
        let payloadType = bytes[1] & 0x7F
        let sequenceNumber = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        let timestamp = UInt32(bytes[4]) << 24 | UInt32(bytes[5]) << 16
            | UInt32(bytes[6]) << 8 | UInt32(bytes[7])
        let ssrc = UInt32(bytes[8]) << 24 | UInt32(bytes[9]) << 16
            | UInt32(bytes[10]) << 8 | UInt32(bytes[11])

        var headerLength = fixedHeaderLength + Int(csrcCount) * 4
        // CSRC list must be fully present.
        guard bytes.count >= headerLength else { return nil }

        if hasExtension {
            // 4-byte extension header: 16-bit profile ‖ 16-bit word count (BE).
            guard bytes.count >= headerLength + 4 else { return nil }
            let extWordCount = Int(bytes[headerLength + 2]) << 8 | Int(bytes[headerLength + 3])
            headerLength += 4 + extWordCount * 4
            guard bytes.count >= headerLength else { return nil }
        }

        return AppleRTPHeader(version: version,
                              csrcCount: csrcCount,
                              hasExtension: hasExtension,
                              marker: marker,
                              payloadType: payloadType,
                              sequenceNumber: sequenceNumber,
                              timestamp: timestamp,
                              ssrc: ssrc,
                              headerLength: headerLength)
    }
}
