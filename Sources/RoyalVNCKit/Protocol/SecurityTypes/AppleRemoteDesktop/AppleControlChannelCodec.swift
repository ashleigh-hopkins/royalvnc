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

    /// A `1104` cursor rect surfaced from the walk (crib §7b). `compressed` is EMPTY for a cache-hit
    /// (`comp_size == 0` → re-apply the cached image for `cacheID`); otherwise it's the
    /// `zlib(Z_SYNC_FLUSH)` BGRA pixmap ‖ alpha mask to decode via `decodeCursorPixmap`.
    struct CursorRect: Equatable {
        let hotspotX: Int
        let hotspotY: Int
        let width: Int
        let height: Int
        let cacheID: UInt32
        let compressed: Data
        var isCacheHit: Bool { compressed.isEmpty }
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
        /// The `1104` cursor rects consumed, in wire order (for the caller to decode/cache/deliver).
        let cursors: [CursorRect]

        init(declaredRects: Int, parsedRects: Int, layout: LayoutInfo?, stoppedEarly: Bool, cursors: [CursorRect] = []) {
            self.declaredRects = declaredRects
            self.parsedRects = parsedRects
            self.layout = layout
            self.stoppedEarly = stoppedEarly
            self.cursors = cursors
        }
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
        var cursors: [CursorRect] = []

        for _ in 0..<declaredRects {
            // Rect header: f0,f1,f2,f3 (u16 BE ×4) + encoding (s32 BE) = 12 bytes.
            guard offset + 12 <= b.count else {
                return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: true, cursors: cursors)
            }
            // For a cursor rect these are hotspot_x, hotspot_y, width, height (crib §7b).
            let f0 = readU16(b, offset + 0)
            let f1 = readU16(b, offset + 2)
            let f2 = readU16(b, offset + 4)
            let f3 = readU16(b, offset + 6)
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
            case let e where lengthPrefixedConfigEncodings.contains(e):
                bodyLength = lengthPrefixedBodyLength(b, offset)
            default:
                // Unknown encoding (e.g. 1100/1101) — length unknown; stop and resync on next record.
                return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: true, cursors: cursors)
            }

            guard let bodyLength, offset + bodyLength <= b.count else {
                return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: true, cursors: cursors)
            }

            if encoding == encCursor {
                // Bounds guaranteed by the guard above (bodyLength == 8 + comp_size). cache_id @ offset,
                // comp_size @ offset+4, then comp_size bytes of the zlib pixmap (empty on a cache-hit).
                let cacheID = readU32(b, offset)
                let compSize = Int(readU32(b, offset + 4))
                let compressed = compSize > 0 ? Data(b[(offset + 8)..<(offset + 8 + compSize)]) : Data()
                cursors.append(CursorRect(hotspotX: f0, hotspotY: f1, width: f2, height: f3, cacheID: cacheID, compressed: compressed))
            }

            offset += bodyLength
            parsed += 1
        }

        return FBUWalk(declaredRects: declaredRects, parsedRects: parsed, layout: lastLayout, stoppedEarly: false, cursors: cursors)
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

    // MARK: - Cursor pixmap decode (1104 full rect)

    /// Decode a `1104` cursor pixmap to **RGBA8888** (crib §7b), matching the format the fork's standard
    /// `decodeCursor` produces (R,G,B,A per pixel) so it flows through the same `VNCCursor`/render path.
    /// `compressed` is a `zlib(Z_SYNC_FLUSH)` stream of `w*h*4` BGRA pixels ‖ `w*h` alpha-mask bytes;
    /// alpha is taken from the mask (the pixmap's own 4th byte is ignored, as in the reference). Returns
    /// `nil` on any decompress/size failure (caller treats it as a benign miss — no session teardown).
    static func decodeCursorPixmap(compressed: Data, width: Int, height: Int) -> Data? {
        // Bound the dimensions: cursor w/h come from u16 header fields, so a hostile `65535×65535` with a
        // tiny comp_size would otherwise drive a ~21 GB allocation (the u16 max). Real Apple cursors are
        // ≤ ~256 px even at Retina; 1024 is a generous ceiling that caps the buffer at ~5 MB.
        guard width > 0, height > 0, width <= 1024, height <= 1024 else { return nil }
        let pixmapSize = width * height * 4
        let maskSize = width * height
        let expected = pixmapSize + maskSize

        guard let raw = try? ZlibStream().decompressedData(compressedData: compressed,
                                                           uncompressedSize: UInt(expected)),
              raw.count == expected else { return nil }

        let src = [UInt8](raw)
        var out = [UInt8](repeating: 0, count: pixmapSize)
        for px in 0..<(width * height) {
            let o = px * 4
            out[o]     = src[o + 2]              // R (source is BGRA)
            out[o + 1] = src[o + 1]              // G
            out[o + 2] = src[o]                  // B
            out[o + 3] = src[pixmapSize + px]    // A from the separate mask
        }
        return Data(out)
    }

    // MARK: - Big-endian readers (assume the caller-checked bounds)

    private static func readU16(_ b: [UInt8], _ o: Int) -> Int {
        (Int(b[o]) << 8) | Int(b[o + 1])
    }

    private static func readU32(_ b: [UInt8], _ o: Int) -> UInt32 {
        (UInt32(b[o]) << 24) | (UInt32(b[o + 1]) << 16) | (UInt32(b[o + 2]) << 8) | UInt32(b[o + 3])
    }
}
