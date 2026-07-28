#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure, connection-free bring-up seam for the Apple-Standard (`.appleStandardFramebuffer`) tier (SPECS
/// §11.1). Everything here is deliberately free of `VNCConnection`/socket access so the SetEncodings
/// ordering, the AutoFrameBufferUpdate (`0x09`) byte layout, and the canvas-source decision can all be
/// unit-tested in isolation (`app:docs/PATTERNS/pure-test-seam-value-types.md`).
enum AppleStandardBringUp {
    // MARK: - SetEncodings ordering (SPECS §7, Q4 DECIDED)

    /// ZRLE — the default primary encoding (Q4 DECIDED: near-parity with Zlib, marginally better wire
    /// compression, probe §Results A).
    static let zrle: Int64 = 16

    /// Zlib — the connect-time alternative primary encoding (Q4 DECIDED).
    static let zlib: Int64 = 6

    /// The tier's DEFAULT primary (Q4 DECIDED: ZRLE) — the SINGLE source of truth both
    /// `VNCConnection+Handshake.swift`'s `armAppleRecordLayer()` (plaintext-prelude SetEncodings, the
    /// SPECS §4.2 tier-dependent fix) and `performAppleStandardControlBringUp()` (logging only, since
    /// SetEncodings itself is now sent exactly once, in the prelude) read, so the two sites can never
    /// drift onto different primaries from each other.
    static let defaultPrimary: Int64 = zrle

    /// The two fork-decodable, `screensharingd`-whitelisted frame encodings this tier may lead with
    /// (discovery §5a: `{6,16,1000,1001,1002,1010,1011}` ∩ "has a real `VNCFrameEncoding` decoder" = `{6,16}`).
    static let decodableWhitelistedEncodings: [Int64] = [zrle, zlib]

    /// Other whitelist members this tier still advertises (SPECS §8 — keeps the `0x3f3`/1011 seam open for
    /// a future decoder) in the EXACT order the probe's live-verified configuration used (probe §Method:
    /// `1011, 1002` immediately follow the target/primary encoding). `1010` was never advertised by the
    /// probe and is deliberately NOT re-added here — reordering or extending a proven-live SetEncodings
    /// sequence without a new live measurement is exactly the un-verified risk this tier is built to avoid.
    static let otherWhitelistMembers: [Int64] = [1011, 1002]

    /// Apple pseudo-encodings advertised after the whitelist (cursor `1104`, display-layout `0x451`/1105,
    /// and the length-prefixed config set `1107/1109/1110`) so the daemon knows this client can receive
    /// them — the same trailing order the probe used (probe §Method).
    static let applePseudoEncodings: [Int64] = [1104, 1105, 1107, 1109, 1110]

    /// Orders the SetEncodings list with `primary` FIRST — `screensharingd`'s `HandleSetEncodingsMessage`
    /// primary-codec selector only inspects the FIRST entry that passes its whitelist (discovery
    /// §Background), so ordering — not presence — is what selects the primary codec. `primary` MUST be
    /// `.zrle` (16) or `.zlib` (6); any other value is a caller programming error (SPECS §7 — this tier's
    /// primary is fixed at connect and is never re-derived live).
    ///
    /// For `primary == 16` this reproduces the probe's Config A exactly: `[16, 1011, 1002, 6, 1104, 1105,
    /// 1107, 1109, 1110]`. For `primary == 6` it reproduces Config D exactly: `[6, 1011, 1002, 16, 1104,
    /// 1105, 1107, 1109, 1110]`.
    static func setEncodingsOrder(primary: Int64) -> [Int64] {
        let otherDecodable = (primary == zrle) ? zlib : zrle

        return [primary] + otherWhitelistMembers + [otherDecodable] + applePseudoEncodings
    }

    // MARK: - AutoFrameBufferUpdate (`0x09`) byte layout (SPECS §4.1 step 3 / §6 / §4.4)

    /// Builds the 16-byte AutoFrameBufferUpdate body (T14 finding: `conn[0x2c] = wire[4..7] !=
    /// 0xFFFFFFFF` is what turns on per-viewer continuous full-screen delivery).
    ///
    /// - Parameters:
    ///   - continuous: `true` → `wire[4..7] = 0x00000000` (continuous push ON — this tier's ONLY push
    ///     mechanism, SPECS §4.4/FR-4). `false` → `wire[4..7] = 0xFFFFFFFF` (off; kept for completeness/
    ///     testing — this tier never sends `false` in practice).
    ///   - width/height: the negotiated canvas, landed at `wire[12..15]` (u16 BE each).
    ///
    /// `wire[3] = 0x00` unconditionally (ASSUMPTION A4): the probe's own live-proven builder used `0x00`
    /// here (not the reference/HP default `0x01`, which was never A/B tested for this tier) — this matches
    /// the ONLY configuration with live evidence for the classic-push behaviour (probe §Method).
    static func autoFBUBytes(continuous: Bool, width: UInt16, height: UInt16) -> [UInt8] {
        let flagByte: UInt8 = continuous ? 0x00 : 0xFF

        var bytes: [UInt8] = [
            0x09, 0x00, 0x00, 0x00,
            flagByte, flagByte, flagByte, flagByte,
            0x00, 0x00, 0x00, 0x00,
            0, 0, 0, 0
        ]

        bytes[12] = UInt8(width >> 8)
        bytes[13] = UInt8(width & 0xFF)
        bytes[14] = UInt8(height >> 8)
        bytes[15] = UInt8(height & 0xFF)

        return bytes
    }

    // MARK: - Canvas source resolution (SPECS §6, G1-corrected 2-way rule)

    /// The Apple-Standard tier's half of SPECS §6's 3-way canvas rule — the media-canvas branch
    /// (`negotiatesHighPerformanceMedia`) is unchanged/pre-existing and lives inline at
    /// `VNCConnection+Handshake.swift` (NOT part of this seam, to avoid touching working HP code).
    ///
    /// `requestedBackingWidth`/`requestedBackingHeight` are the OPTIONAL `0x1d` virtual-display backing
    /// (`Settings.highPerformanceDisplay?.pixelWidth/Height`). **`nil` is the NORMAL, shipped-default
    /// case** (G1 correction): this tier reuses the existing shared `HPDisplayPreferences` selector, whose
    /// default is `.hostDisplay` (no `0x1d` request) — this function must therefore size from `serverInit`
    /// in that case, NOT hardcode a canvas or treat `nil` as an error. Only a well-formed positive request
    /// within `UInt16` range overrides `serverInit`.
    static func resolveCanvasSize(requestedBackingWidth: Int?,
                                  requestedBackingHeight: Int?,
                                  serverInit: (width: UInt16, height: UInt16)) -> (width: UInt16, height: UInt16) {
        if let width = requestedBackingWidth,
           let height = requestedBackingHeight,
           width > 0, height > 0,
           width <= Int(UInt16.max), height <= Int(UInt16.max) {
            return (UInt16(width), UInt16(height))
        }

        return serverInit
    }
}
