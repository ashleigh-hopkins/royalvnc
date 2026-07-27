#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure builder for the Apple RFB **`0x1d` SetDisplayConfiguration** message (a.k.a. "VirtualDisplay").
///
/// Sending this asks `screensharingd` to create a **SkyLight virtual display** of the requested geometry and
/// encode THAT instead of the host's physical panel — which is how Apple's own client streams a sensible
/// resolution instead of a 5120×1440 ultrawide. NOT sending it is what makes the daemon stream the raw
/// physical display. The same message mid-session is a dynamic-resolution resize request (the server answers
/// with `0x451`); this fork only sends it at connect time, before the `0x1c` media offer, so the FIRST
/// `0x1c` answer already carries the reduced canvas (no `0x451` dance, no `0x1c` re-offer).
///
/// ⚠️ **Host side effect:** the daemon flips into virtual-framebuffer mode and engages the **curtain** — the
/// Mac's physical screen stops showing the desktop for the duration of the session, and creating a display of
/// a different geometry reflows the user's windows (which persists after disconnect). Therefore this is
/// **opt-in only**: `Settings.highPerformanceDisplay == nil` (the default) sends nothing and keeps today's
/// behaviour byte-for-byte.
///
/// ⚠️ **hidpi trap (the whole point of storing PIXELS):** the wire's `width`/`height` are LOGICAL POINTS and
/// each mode entry carries the PIXEL (backing) dims = points × `hidpiScale`. The negotiated `0x1c` canvas —
/// i.e. what the encoder actually produces and we must decode — is the BACKING size. So advertising
/// "1920×1080" with the reference's default `hidpi_scale = 2` yields a **3840×2160** backing = 8.29 Mpx,
/// which is MORE pixels than a 5120×1440 panel (7.37 Mpx) — the opposite of the intended fix. Callers state
/// the desired BACKING pixels and a scale; the logical points are derived (`pixels / scale`).
///
/// Wire layout (all multi-byte fields BIG-ENDIAN, tightly packed, no alignment padding). Clean-room: written
/// from the confirmed byte layout (offsets/sizes/endianness/values), no reference code copied.
///
/// ```
/// message (12 B header + one displayInfo):
///   +0x00 u8   msgType   = 0x1d
///   +0x01 u8   pad       = 0
///   +0x02 u16  msgSize   = 8 + displayInfoSize   (byte count following this field)
///   +0x04 u16  msgVersion    = 1
///   +0x06 u16  descriptorCount = 1
///   +0x08 u32  reserved  = 0
/// displayInfo (D = +0x0C), size 0x9C + 28 * modeCount:
///   D+0x00 u16  displayInfoSize
///   D+0x02 [120] UTF-8 display name, truncated to 119 bytes, NUL-padded, NO length prefix
///   D+0x7A u32  displayFlags = 0x01  (DYNAMIC_RESOLUTION)
///   D+0x7E u32  displayType  = 4     (virtual display)
///   D+0x82 f32  physicalWidthMM      (MacBook Pro panel, from a native capture)
///   D+0x86 f32  physicalHeightMM
///   D+0x8A u32  maxWidth  = 3840  ── the daemon CAPS the virtual display at this backing size;
///   D+0x8E u32  maxHeight = 2160  ── a larger request hits a server-side "safe minimum" fallback
///   D+0x92 u16  currentModeIndex   = 0
///   D+0x94 u16  preferredModeIndex = 0
///   D+0x96 u32  rotations = 7
///   D+0x9A u16  modeCount
///   D+0x9C + 28*i  mode entry (stride 0x1C):
///       +0x00 u32 pixelWidth   (= pointWidth  * hidpiScale)
///       +0x04 u32 pixelHeight  (= pointHeight * hidpiScale)
///       +0x08 u32 pointWidth
///       +0x0C u32 pointHeight
///       +0x10 f64 refreshHz = 60.0
///       +0x18 u32 modeFlags  = 1 iff HDR else 0
/// ```
/// With the native `modeCount = 5` the message is exactly **308 bytes** (`msgSize = 304`).
///
/// The requested resolution never appears as a standalone field: it is expressed through the mode table.
/// Mode 0's POINT dims come out exactly equal to the requested logical size; the other four are Apple's
/// heterogeneous "kModes" template scaled by `sx = logicalWidth/1920`, `sy = logicalHeight/1080`.
enum Apple0x1dSetDisplayConfiguration {
	static let msgType: UInt8 = 0x1d
	/// The daemon's virtual-display cap (backing pixels). Requests above this trigger a server-side fallback.
	static let maxBackingWidth: UInt32 = 3840
	static let maxBackingHeight: UInt32 = 2160
	static let displayFlagsDynamicResolution: UInt32 = 0x01
	static let displayTypeVirtual: UInt32 = 4
	static let rotations: UInt32 = 7
	static let refreshHz: Double = 60.0
	/// Physical panel dimensions in mm, from a native Screen Sharing capture (MacBook Pro panel).
	static let physicalWidthMM: Float = 369.454_559_326_171_9
	static let physicalHeightMM: Float = 207.818_176_269_531_25
	static let defaultDisplayName = "Screen Sharing Virtual Display"

	/// Big-endian bytes of a `UInt64` (the shared `Data.append(_:bigEndian:)` family has no 64-bit overload;
	/// kept local rather than widening the shared extension).
	private static func bigEndianBytes(_ value: UInt64) -> [UInt8] {
		(0..<8).map { UInt8(truncatingIfNeeded: value >> (56 - 8 * $0)) }
	}

	/// Apple's heterogeneous mode-table template, as LOGICAL POINT dims. Entry 0 is replaced by the caller's
	/// requested logical size (scaling entry 0 by `sx`/`sy` reproduces it exactly, since it IS 1920×1080).
	static let modeTemplatePoints: [(w: Int, h: Int)] = [
		(1920, 1080), (1440, 900), (1920, 1080), (1440, 810), (1312, 848),
	]

	/// Build the `0x1d` message.
	///
	/// - Parameters:
	///   - logicalWidth:  requested width in POINTS (wire semantics). Mode 0 carries this verbatim.
	///   - logicalHeight: requested height in POINTS.
	///   - hidpiScale:    backing:point ratio the mode table advertises. **1 = flat** (backing == points;
	///                    what you want to REDUCE decode load); 2 = Retina (backing = 2× points).
	///   - hdr:           sets `modeFlags = 1` on every mode entry.
	///   - displayName:   advertised name (truncated to 119 UTF-8 bytes).
	///   - modeCount:     number of mode entries; native sends 5. Clamped to the template length.
	static func build(logicalWidth: Int,
					  logicalHeight: Int,
					  hidpiScale: Int = 1,
					  hdr: Bool = false,
					  displayName: String = defaultDisplayName,
					  modeCount: Int = 5) -> Data {
		let scale = max(1, hidpiScale)
		let modes = min(max(1, modeCount), modeTemplatePoints.count)

		// Scale Apple's template to the target. Entry 0 reproduces the request exactly.
		let sx = Double(logicalWidth) / 1920.0
		let sy = Double(logicalHeight) / 1080.0
		let modeEntries: [(pw: UInt32, ph: UInt32, ptw: UInt32, pth: UInt32)] = (0..<modes).map { i in
			let t = modeTemplatePoints[i]
			let ptw = Int((Double(t.w) * sx) + 0.5)
			let pth = Int((Double(t.h) * sy) + 0.5)
			return (pw: UInt32(ptw * scale), ph: UInt32(pth * scale),
					ptw: UInt32(ptw), pth: UInt32(pth))
		}

		let displayInfoSize = 0x9C + 28 * modes

		var d = Data()
		d.reserveCapacity(12 + displayInfoSize)

		// ── 12-byte message header ──
		d.append(msgType)
		d.append(0)                                             // pad
		d.append(UInt16(8 + displayInfoSize), bigEndian: true)   // msgSize
		d.append(UInt16(1), bigEndian: true)                    // msgVersion
		d.append(UInt16(1), bigEndian: true)                    // descriptorCount
		d.append(UInt32(0), bigEndian: true)                    // reserved

		// ── displayInfo ──
		d.append(UInt16(displayInfoSize), bigEndian: true)      // D+0x00

		// D+0x02: 120-byte NUL-padded UTF-8 name (no length prefix), truncated to 119 bytes so a NUL remains.
		var nameBytes = Array(displayName.utf8.prefix(119))
		nameBytes.append(contentsOf: [UInt8](repeating: 0, count: 120 - nameBytes.count))
		d.append(contentsOf: nameBytes)

		d.append(displayFlagsDynamicResolution, bigEndian: true)   // D+0x7A
		d.append(displayTypeVirtual, bigEndian: true)              // D+0x7E
		d.append(physicalWidthMM.bitPattern, bigEndian: true)      // D+0x82 (f32 BE)
		d.append(physicalHeightMM.bitPattern, bigEndian: true)     // D+0x86
		d.append(maxBackingWidth, bigEndian: true)                 // D+0x8A
		d.append(maxBackingHeight, bigEndian: true)                // D+0x8E
		d.append(UInt16(0), bigEndian: true)                       // D+0x92 currentModeIndex
		d.append(UInt16(0), bigEndian: true)                       // D+0x94 preferredModeIndex
		d.append(rotations, bigEndian: true)                       // D+0x96
		d.append(UInt16(modes), bigEndian: true)                   // D+0x9A

		let modeFlags: UInt32 = hdr ? 1 : 0
		for m in modeEntries {
			d.append(m.pw, bigEndian: true)
			d.append(m.ph, bigEndian: true)
			d.append(m.ptw, bigEndian: true)
			d.append(m.pth, bigEndian: true)
			d.append(contentsOf: bigEndianBytes(refreshHz.bitPattern))   // f64 BE
			d.append(modeFlags, bigEndian: true)
		}

		return d
	}
}
