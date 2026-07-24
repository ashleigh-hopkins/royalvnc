#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) codec for the Apple HP **TCP control channel** server→client
/// FramebufferUpdate (`0x00`). On the encrypted type-33 channel the daemon uses `0x00` to carry ONLY
/// pseudo-encoding rects (cursor `1104`, display-layout `0x451`, config blobs `1010/1011/1107/1109/1110`)
/// — the real pixels flow over UDP/SRTP, never here (crib §7a-§7b).
///
/// This walker consumes each rect by its **real** length so a whole FBU can be parsed in-memory from one
/// decrypted record body. On an unknown-length encoding (e.g. `1100`/`1101`, which the reference never
/// parses) or a truncated rect it stops and reports `stoppedEarly` — the caller discards the record's
/// unparsed tail and resyncs on the next record (crib §7c). It never reads off a socket, so the wire
/// spec is fully unit-testable against byte vectors.
///
/// Clean-room: reimplemented from the confirmed byte layout (offsets/sizes/endianness), no reference
/// code copied.
enum AppleControlChannelCodec {
    /// Display geometry carried in a `0x451` AppleDisplayLayout rect (crib §7b). All u16 BE. Present only
    /// when the rect's `prefix_len >= 10`; a layout with nonzero `backingW/H` marks a display/session
    /// transition the caller should re-arm for (crib §7d).
    struct LayoutInfo: Equatable {
        let scaledWidth: Int
        let scaledHeight: Int
        let backingWidth: Int
        let backingHeight: Int
    }

    /// The outcome of walking one `0x00` FramebufferUpdate record body.
    struct FBUWalk: Equatable {
        /// `n_rects` declared in the FBU header.
        let declaredRects: Int
        /// Rects fully consumed by their real length before the walk ended.
        let parsedRects: Int
        /// The last `0x451` layout seen with `prefix_len >= 10`, if any.
        let layout: LayoutInfo?
        /// `true` if the walk stopped before all declared rects (unknown encoding or truncation) — the
        /// caller must discard the record tail and resync on the next record.
        let stoppedEarly: Bool
    }

    // MARK: - Encoding numbers (server→client, TCP control channel)

    static let encCursor = 1104                                   // Apple cached-cursor pseudo-encoding
    static let encDisplayLayout = 0x451                           // == 1105 AppleDisplayLayout
    /// Config blobs framed as `u16 size + payload` (crib §7b). `0x451`(1105) shares this framing but is
    /// handled separately so its geometry can be parsed.
    static let lengthPrefixedConfigEncodings: Set<Int> = [1010, 1011, 1107, 1109, 1110]

    // MARK: - FramebufferUpdate walk

    /// Walk one `0x00` FramebufferUpdate record body. Returns `nil` if `msg` is not a `0x00` FBU or is
    /// too short to hold the 4-byte header.
    static func walkFramebufferUpdate(_ msg: Data) -> FBUWalk? {
        let b = [UInt8](msg)
        guard b.count >= 4, b[0] == 0x00 else { return nil }

        let declaredRects = (Int(b[2]) << 8) | Int(b[3])
        var offset = 4
        var parsed = 0
        var lastLayout: LayoutInfo?

        for _ in 0..<declaredRects {
            // Rect header: f0,f1,f2,f3 (u16 BE ×4) + encoding (s32 BE) = 12 bytes.
            guard offset + 12 <= b.count else {
                return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: true)
            }
            let cursorWidth = readU16(b, offset + 4)      // f2 for a cursor rect
            let cursorHeight = readU16(b, offset + 6)     // f3 for a cursor rect
            let encoding = Int(Int32(bitPattern: readU32(b, offset + 8)))
            offset += 12

            let bodyLength: Int?
            switch encoding {
            case encCursor:
                bodyLength = cursorBodyLength(b, offset)
            case encDisplayLayout:
                let (len, layout) = displayLayoutBody(b, offset)
                if let layout { lastLayout = layout }
                bodyLength = len
                _ = cursorWidth; _ = cursorHeight   // unused for layout rects
            case let e where lengthPrefixedConfigEncodings.contains(e):
                bodyLength = lengthPrefixedBodyLength(b, offset)
            default:
                // Unknown encoding (e.g. 1100/1101) — length unknown; stop and resync on next record.
                return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: true)
            }

            guard let bodyLength, offset + bodyLength <= b.count else {
                return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: true)
            }
            offset += bodyLength
            parsed += 1
        }

        return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: false)
    }

    // MARK: - Per-encoding body sizing (bytes past the 12-byte rect header)

    /// `1104` cursor body: `u32 cache_id, u32 comp_size`, then `comp_size` bytes when nonzero (crib §7b).
    /// `comp_size == 0` is a cache-hit (body = 8). Returns `nil` if the fixed 8-byte prefix is truncated.
    private static func cursorBodyLength(_ b: [UInt8], _ offset: Int) -> Int? {
        guard offset + 8 <= b.count else { return nil }
        let compSize = Int(readU32(b, offset + 4))
        return 8 + compSize
    }

    /// Length-prefixed config body: `u16 size + size bytes` → consumed `2 + size` (crib §7b).
    private static func lengthPrefixedBodyLength(_ b: [UInt8], _ offset: Int) -> Int? {
        guard offset + 2 <= b.count else { return nil }
        return 2 + readU16(b, offset)
    }

    /// `0x451` AppleDisplayLayout body: `u16 prefix_len + prefix_len bytes` → consumed `2 + prefix_len`.
    /// When `prefix_len >= 10`, the scaled/backing dims sit at offsets 4/6/8/10 measured from the
    /// `prefix_len` field itself (i.e. `payload + 2/4/6/8`) — crib §7b. `offset` here points at the
    /// `prefix_len` u16, so we read `offset + 4/6/8/10` directly. Returns `(consumed, layout?)`.
    private static func displayLayoutBody(_ b: [UInt8], _ offset: Int) -> (Int?, LayoutInfo?) {
        guard offset + 2 <= b.count else { return (nil, nil) }
        let prefixLen = readU16(b, offset)
        let consumed = 2 + prefixLen
        guard offset + consumed <= b.count else { return (nil, nil) }

        var layout: LayoutInfo?
        if prefixLen >= 10 {
            layout = LayoutInfo(scaledWidth: readU16(b, offset + 4),
                                scaledHeight: readU16(b, offset + 6),
                                backingWidth: readU16(b, offset + 8),
                                backingHeight: readU16(b, offset + 10))
        }
        return (consumed, layout)
    }

    // MARK: - Big-endian readers (assume the caller-checked bounds)

    private static func readU16(_ b: [UInt8], _ o: Int) -> Int {
        (Int(b[o]) << 8) | Int(b[o + 1])
    }

    private static func readU32(_ b: [UInt8], _ o: Int) -> UInt32 {
        (UInt32(b[o]) << 24) | (UInt32(b[o + 1]) << 16) | (UInt32(b[o + 2]) << 8) | UInt32(b[o + 3])
    }
}
