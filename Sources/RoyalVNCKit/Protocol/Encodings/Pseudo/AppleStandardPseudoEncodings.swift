#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Tolerant `VNCReceivablePseudoEncoding` adapters for the Apple pseudo-encodings that can interleave
/// with classic ZRLE/Zlib rects on the Apple-Standard tier's STANDARD receive loop (SPECS §5.2). Without
/// these, `FramebufferUpdate.receive` throws `.unsupportedEncoding` the first time the daemon sends a
/// cursor (`1104`), a display-layout change (`0x451`/1105), or a config blob — tearing the whole session
/// down (NFR-TOLERANCE).
///
/// Every adapter delegates its byte-sizing to the SINGLE framing authority, `AppleControlChannelCodec`
/// (`cursorBodyLength`, `lengthPrefixedBodyLength`, `parseDisplayLayoutBody`) — the same authority the HP
/// record-framed control loop (`VNCConnection+AppleControl.swift`) and the pre-rekey plaintext reader
/// (`readAppleRekeyBlob`) already use. NO re-derived framing: a prior agent desynced a live session by
/// inventing a length rule from one sample, which is exactly the failure mode this delegation avoids.

/// `1104` Apple cursor pseudo-encoding, decoded off the STANDARD receive loop. Reuses this connection's
/// existing cursor cache/decode/deliver path (`VNCConnection.applyAppleCursor`, shared with the HP control
/// loop) rather than keeping a second cache — SPECS §5.2: "decode → existing framebuffer.updateCursor,
/// reuse applyAppleCursor".
final class AppleCursorPseudoEncoding: VNCReceivablePseudoEncoding {
    let encodingType = VNCEncodingType(Int32(AppleControlChannelCodec.encCursor))

    /// `unowned`, not `weak`/strong: this instance lives inside `owner.encodings`, a stored property of
    /// `owner` itself — its lifetime is a strict subset of `owner`'s, so `owner` is always valid whenever
    /// `receive(...)` runs (mirrors the existing self-referencing pattern in `VNCConnection.connection`'s
    /// own lazy-var status-handler closure).
    private unowned let owner: VNCConnection

    init(owner: VNCConnection) {
        self.owner = owner
    }

    func receive(_ rectangle: VNCProtocol.Rectangle,
                 framebuffer: VNCFramebuffer,
                 connection: NetworkConnectionReading,
                 logger: VNCLogger) async throws {
        // Rect header fields are hotspot_x, hotspot_y, width, height for this encoding (crib §7b) — the
        // same generic x/y/w/h the RFB rect header always carries.
        let hotspotX = Int(rectangle.region.location.x)
        let hotspotY = Int(rectangle.region.location.y)
        let width = Int(rectangle.region.size.width)
        let height = Int(rectangle.region.size.height)

        let cacheID = try await connection.readUInt32()
        let compSize = try await connection.readUInt32()

        // Delegate the "8 + comp_size" body-length arithmetic to the single framing authority instead of
        // re-deriving it, even though `compSize` is already in hand — see the file-level doc comment.
        let prefixBytes: [UInt8] = [
            UInt8((cacheID >> 24) & 0xFF), UInt8((cacheID >> 16) & 0xFF), UInt8((cacheID >> 8) & 0xFF), UInt8(cacheID & 0xFF),
            UInt8((compSize >> 24) & 0xFF), UInt8((compSize >> 16) & 0xFF), UInt8((compSize >> 8) & 0xFF), UInt8(compSize & 0xFF)
        ]
        guard let bodyLength = AppleControlChannelCodec.cursorBodyLength(prefixBytes, 0) else {
            throw VNCError.protocol(.invalidData)
        }

        let compressed: Data
        let remaining = bodyLength - prefixBytes.count
        if remaining > 0 {
            compressed = try await connection.readBuffered(length: remaining)
        } else {
            compressed = Data()
        }

        let rect = AppleControlChannelCodec.CursorRect(hotspotX: hotspotX, hotspotY: hotspotY,
                                                        width: width, height: height,
                                                        cacheID: cacheID, compressed: compressed)

        owner.applyAppleCursor(rect)
    }
}

/// `0x451`/1105 AppleDisplayLayout pseudo-encoding, decoded off the STANDARD receive loop. Phase 1 is
/// PARSE-ONLY (PLAN W7: "0x451 → parse-only (P1)") — resizing the framebuffer + re-arming AutoFBU on a
/// layout change is Phase-2 work (SPECS §6 `0x451` re-arm, PLAN W16); this adapter's job in Phase 1 is
/// solely to consume the rect by its real length so the connection does not desync or fail.
struct AppleDisplayLayoutPseudoEncoding: VNCReceivablePseudoEncoding {
    let encodingType = VNCEncodingType(Int32(AppleControlChannelCodec.encDisplayLayout))

    func receive(_ rectangle: VNCProtocol.Rectangle,
                 framebuffer: VNCFramebuffer,
                 connection: NetworkConnectionReading,
                 logger: VNCLogger) async throws {
        let prefixLength = try await connection.readUInt16()
        let body = try await connection.readBuffered(length: Int(prefixLength))

        // Reconstruct the `u16 prefix_len ‖ body` shape `AppleControlChannelCodec.parseDisplayLayoutBody`
        // expects (the SAME reconstruction `readAppleRekeyBlob` already performs for the pre-rekey case —
        // reusing the authority's existing public entry point rather than re-deriving field offsets).
        var framed = Data([UInt8(prefixLength >> 8), UInt8(prefixLength & 0xFF)])
        framed.append(body)

        if let layout = AppleControlChannelCodec.parseDisplayLayoutBody(framed) {
            logger.logDebug("[apple-std] 0x451 AppleDisplayLayout scaled=\(layout.scaledWidth)x\(layout.scaledHeight) backing=\(layout.backingWidth)x\(layout.backingHeight) (parse-only in Phase 1 — resize/re-arm is Phase 2, SPECS §6/PLAN W16)")
        } else {
            logger.logDebug("[apple-std] 0x451 AppleDisplayLayout with no geometry (prefix_len=\(prefixLength))")
        }
    }
}

/// Length-prefixed Apple config pseudo-encoding (`1010`/`1011`/`1107`/`1109`/`1110`), decoded off the
/// STANDARD receive loop. This tier never registers a decoder for their payload (SPECS §8 — `1011`'s
/// `u32` primary-DCT framing is future decoder work, not a pre-existing seam) — it only needs to SKIP the
/// body by its real length so the connection survives seeing them (they are non-primary here; SPECS §7
/// fixes the primary to 16/6).
struct AppleConfigSkipPseudoEncoding: VNCReceivablePseudoEncoding {
    let encodingType: VNCEncodingType

    func receive(_ rectangle: VNCProtocol.Rectangle,
                 framebuffer: VNCFramebuffer,
                 connection: NetworkConnectionReading,
                 logger: VNCLogger) async throws {
        let size = try await connection.readUInt16()

        // Delegate the "2 + size" body-length arithmetic to the single framing authority.
        let prefixBytes: [UInt8] = [UInt8(size >> 8), UInt8(size & 0xFF)]
        guard let bodyLength = AppleControlChannelCodec.lengthPrefixedBodyLength(prefixBytes, 0) else {
            throw VNCError.protocol(.invalidData)
        }

        let skipLength = bodyLength - prefixBytes.count
        if skipLength > 0 {
            _ = try await connection.readBuffered(length: skipLength)
        }

        logger.logDebug("[apple-std] skipped config rect encoding=\(encodingType.rawValue) len=\(skipLength)")
    }
}
