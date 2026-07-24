#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) codec for Apple Screen Sharing's in-protocol
/// clipboard sync, carried over the type-33 AES-128-CBC control-record channel
/// (a sibling of `AppleInputEventCodec`'s `0x10`). Each message below is a record
/// *body*: the wiring layer seals it with `AppleControlRecordCodec.seal` outbound
/// and hands each `open`ed body to the dispatcher inbound.
///
/// The wire spec is single-source (iShareScreen RE of screensharingd 15.3) but was
/// **live-confirmed on macOS 27 / RFB 003.889** (Experiment 1,
/// `plans/t12-clipboard-perf/T12-EXP1-GOLDEN-FINDINGS.md`), which also uncovered the
/// outbound `promise`-byte fix below. Reference code was studied only; this is a
/// clean-room reimplementation from the confirmed byte layout.
///
/// Message quartet:
///   * `0x15` AutoPasteboard  C→S  the enable gate (`mode=1`), sent once at bring-up.
///   * `0x0b` ClipboardFetch  C→S  exactly 8 bytes; sent after a `0x14 cmd=2` notify.
///   * `0x14` MiscStatus      S→C  `cmd=2` = remote clipboard changed → reply `0x0b`.
///   * `0x1f` ClipboardSend   both a 16-byte header + `Z_SYNC_FLUSH` zlib archive.
enum AppleClipboardCodec {
    // MARK: RFB message-type bytes

    static let msgAutoPasteboard: UInt8 = 0x15
    static let msgClipboardRequest: UInt8 = 0x0b
    static let msgMiscStatus: UInt8 = 0x14
    static let msgClipboardSend: UInt8 = 0x1f

    // MARK: Confirmed constants (macOS 27)

    /// `0x15` selector: `1` = start monitoring the host pasteboard. `2` is rejected
    /// by the agent ("unknown command") — confirmed on wire.
    static let autoPasteboardEnableMode: UInt16 = 1

    /// `0x14` MiscStatus command meaning "remote clipboard changed" (reply with a fetch).
    static let miscStatusClipboardChanged: UInt16 = 2

    /// **The macOS-27 outbound fix.** The `0x1f` header `promise` byte (`[2]`) MUST be
    /// `1` for a viewer→host paste to be written to NSPasteboard; `0` is silently
    /// dropped on macOS 27 (Experiment 1, A/B-confirmed). Inbound sends observed `0`.
    static let clipboardSendPromiseCommit: UInt8 = 1

    /// `0x1f` fixed header length.
    static let headerLength = 16

    /// Apple's preferred plain-text flavor.
    static let utf8TextUTI = "public.utf8-plain-text"
    static let traditionalMacTextUTI = "com.apple.traditional-mac-plain-text"

    // MARK: - Outbound builders

    /// `0x15` AutoPasteboard enable — `15 00 00 01 00 00 00 00` (8 bytes). Send once at
    /// bring-up (immediately followed by a prime fetch); without it the daemon is silent.
    static func buildAutoPasteboardEnable() -> Data {
        var msg = Data([msgAutoPasteboard, 0x00])
        msg.append(bigEndian16(autoPasteboardEnableMode))
        msg.append(Data([0x00, 0x00, 0x00, 0x00]))
        return msg
    }

    /// `0x0b` ClipboardFetch — **exactly 8 bytes** (9 desyncs the daemon parser and
    /// silently drops all subsequent fetches). `promiseOnly` = metadata-only poll.
    static func buildClipboardFetch(promiseOnly: Bool = false) -> Data {
        Data([msgClipboardRequest, promiseOnly ? 0x01 : 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    }

    /// `0x1f` ClipboardSend carrying one `public.utf8-plain-text` item (outbound paste).
    /// Sets the `promise` byte to `1` (see `clipboardSendPromiseCommit`). A single utf8
    /// flavor is sufficient — flavor count is irrelevant to landing on macOS 27.
    static func buildClipboardSend(text: String) throws -> Data {
        let inner = buildSingleItemArchive(text: text)
        let compressed = try ZlibDeflateStream().compressedData(data: inner)

        guard inner.count <= Int(UInt32.max), compressed.count <= Int(UInt32.max) else {
            throw VNCError.protocol(.invalidData)
        }

        var msg = Data()
        msg.append(msgClipboardSend)                      // [0]
        msg.append(0x00)                                  // [1] pad
        msg.append(clipboardSendPromiseCommit)            // [2] promise = 1
        msg.append(0x00)                                  // [3] pad
        msg.append(bigEndian32(0))                        // [4..8]  reserved
        msg.append(bigEndian32(UInt32(inner.count)))      // [8..12] uncompressed size
        msg.append(bigEndian32(UInt32(compressed.count))) // [12..16] compressed size
        msg.append(compressed)
        return msg
    }

    /// Inner pasteboard archive with a single `public.utf8-plain-text` item, no aliases:
    /// `u32 item_count=1 || u32 uti_len‖uti || u32 reserved=0 || u32 alias_count=0 || u32 data_len‖data`.
    static func buildSingleItemArchive(text: String) -> Data {
        let uti = Data(utf8TextUTI.utf8)
        let data = Data(text.utf8)

        var inner = Data()
        inner.append(bigEndian32(1))                 // item_count
        inner.append(bigEndian32(UInt32(uti.count)))
        inner.append(uti)
        inner.append(bigEndian32(0))                 // reserved
        inner.append(bigEndian32(0))                 // alias_count
        inner.append(bigEndian32(UInt32(data.count)))
        inner.append(data)
        return inner
    }

    // MARK: - MiscStatus (0x14)

    /// The MiscStatus command word (`u16` at body `[6..8]`), or `nil` if `body` is not a
    /// well-formed `0x14`.
    static func miscStatusCommand(_ body: Data) -> UInt16? {
        let b = [UInt8](body)
        guard b.count >= 8, b[0] == msgMiscStatus else { return nil }
        return (UInt16(b[6]) << 8) | UInt16(b[7])
    }

    /// True iff `body` is a `0x14` "remote clipboard changed" notify (reply with a fetch).
    static func isRemoteClipboardChanged(_ body: Data) -> Bool {
        miscStatusCommand(body) == miscStatusClipboardChanged
    }

    // MARK: - Inbound 0x1f parsing

    struct SendHeader: Equatable {
        let promise: UInt8
        let reserved: UInt32
        let uncompressedSize: UInt32
        let compressedSize: UInt32
    }

    /// Reassembly: given an accumulating `0x1f` buffer (a `0x1f` first record plus zero or more
    /// continuation records, which carry no type byte — crib §7a), return the complete message
    /// (`16 + compressedSize` bytes) once enough records have arrived, or `nil` if more are needed
    /// (buffer shorter than the header, or shorter than the declared total). Throws on a full-length
    /// header that isn't a valid `0x1f`.
    static func completeClipboardSend(_ accumulated: Data) throws -> Data? {
        guard accumulated.count >= headerLength else { return nil }
        guard let header = parseSendHeader(accumulated) else {
            throw VNCError.protocol(.invalidData)
        }
        let total = headerLength + Int(header.compressedSize)
        guard accumulated.count >= total else { return nil }
        return Data(accumulated.prefix(total))
    }

    /// Parse the 16-byte `0x1f` header, or `nil` if too short / not a `0x1f`.
    static func parseSendHeader(_ data: Data) -> SendHeader? {
        let b = [UInt8](data)
        guard b.count >= headerLength, b[0] == msgClipboardSend else { return nil }
        return SendHeader(promise: b[2],
                          reserved: readBE32(b, 4),
                          uncompressedSize: readBE32(b, 8),
                          compressedSize: readBE32(b, 12))
    }

    struct Item: Equatable {
        let primaryUTI: String
        let primaryData: Data
        let aliases: [Alias]

        struct Alias: Equatable {
            let name: String
            let value: Data
        }
    }

    /// Decode the decompressed inner archive. Tolerant: a buffer too short to hold the
    /// `item_count` (e.g. the empty-clipboard case) yields `[]` rather than throwing, and
    /// a truncated item stops decoding at the last complete item.
    static func parseItems(_ decompressed: Data) -> [Item] {
        let b = [UInt8](decompressed)
        guard b.count >= 4 else { return [] }

        var p = 0
        func u32() -> UInt32? {
            guard p + 4 <= b.count else { return nil }
            let v = readBE32(b, p)
            p += 4
            return v
        }
        func lpBytes() -> Data? {
            guard let n = u32(), p + Int(n) <= b.count else { return nil }
            let d = Data(b[p..<(p + Int(n))])
            p += Int(n)
            return d
        }

        guard let itemCount = u32() else { return [] }

        var items: [Item] = []
        for _ in 0..<itemCount {
            guard let utiData = lpBytes() else { break }
            guard u32() != nil else { break }              // reserved
            guard let aliasCount = u32() else { break }

            var aliases: [Item.Alias] = []
            var aliasesOK = true
            for _ in 0..<aliasCount {
                guard let nameData = lpBytes(), let valueData = lpBytes() else { aliasesOK = false; break }
                aliases.append(.init(name: String(decoding: nameData, as: UTF8.self), value: valueData))
            }
            guard aliasesOK else { break }

            guard let primaryData = lpBytes() else { break }
            items.append(.init(primaryUTI: String(decoding: utiData, as: UTF8.self),
                               primaryData: primaryData,
                               aliases: aliases))
        }
        return items
    }

    /// Pick the best text flavor: `public.utf8-plain-text`, then any `public.*text*`
    /// (utf16 decoded BE for the "external" variant else LE), then traditional latin-1.
    static func text(from items: [Item]) -> String? {
        for it in items where it.primaryUTI == utf8TextUTI {
            return String(decoding: it.primaryData, as: UTF8.self)
        }
        for it in items where it.primaryUTI.hasPrefix("public.") && it.primaryUTI.contains("text") {
            if it.primaryUTI.contains("utf16") {
                // Apple emits UTF-16 big-endian for public.utf16-plain-text (confirmed on wire).
                return String(data: it.primaryData, encoding: .utf16BigEndian)
            }
            return String(decoding: it.primaryData, as: UTF8.self)
        }
        for it in items where it.primaryUTI == traditionalMacTextUTI {
            return String(data: it.primaryData, encoding: .isoLatin1)
        }
        return nil
    }

    /// Full inbound decode: reassembled `0x1f` (header + compressed) → text, or `nil` for an
    /// empty clipboard (`uncompressed_size == 0`) or no text flavor.
    static func decodeInboundText(_ fullMessage: Data) throws -> String? {
        guard let header = parseSendHeader(fullMessage) else {
            throw VNCError.protocol(.invalidData)
        }
        if header.uncompressedSize == 0 { return nil }

        let bytes = [UInt8](fullMessage)
        guard bytes.count >= headerLength else { throw VNCError.protocol(.invalidData) }
        let payload = Data(bytes[headerLength...])

        let decompressed = try ZlibStream().decompressedData(compressedData: payload,
                                                             uncompressedSize: UInt(header.uncompressedSize))
        return text(from: parseItems(decompressed))
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

    private static func readBE32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }
}
