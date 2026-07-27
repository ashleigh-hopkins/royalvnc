#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

public extension VNCConnection.Settings {
	/// A requested Apple-HP **virtual-display** geometry (the `0x1d` SetDisplayConfiguration request).
	///
	/// Stored as **BACKING PIXELS** plus a hidpi scale, deliberately, because that is the number that decides
	/// whether the client can keep up: the negotiated `0x1c` canvas — what the encoder produces and the client
	/// must decode — is the backing size, while the `0x1d` wire fields carry LOGICAL POINTS. Advertising
	/// "1920×1080" at the Apple-native `hidpiScale: 2` yields a 3840×2160 backing (8.29 Mpx) — MORE pixels than
	/// a 5120×1440 panel (7.37 Mpx), i.e. the opposite of the intended fix. Expressing the request in pixels
	/// makes that impossible to get wrong by accident: `logicalWidth = pixelWidth / hidpiScale`.
	struct HighPerformanceDisplay: Sendable, Equatable {
		/// Backing pixels the encoder is asked to produce (and we must decode) — the cost-determining number.
		public let pixelWidth: Int
		public let pixelHeight: Int
		/// Logical (point) size that goes on the `0x1d` wire. STORED rather than derived, because the WIRE does
		/// not require the backing:point ratio to be an integer: the mode table carries `pixelWidth/Height` and
		/// `pointWidth/Height` as independent u32 fields, so 1.5 (e.g. 2868 px over 1912 pt) is expressible.
		///
		/// ⚠️ **But the HOST rejects a fractional ratio — do not use one without re-testing live.** Requesting
		/// `backing=994x2160 points=662x1440` (ratio 1.5015) made `screensharingd` discard the geometry entirely
		/// and fall back to its safe minimum, answering `0x451` with `scaled=800x600 backing=1600x1200` (ratio
		/// exactly 2.0) — confirmed host-side. SkyLight validates the mode table against integer backing scale
		/// factors. The fractional capability is retained here because the finding is about the host's
		/// validation rather than our encoding, but callers should pass an integer (the app passes 2).
		public let logicalWidth: Int
		public let logicalHeight: Int

		/// The daemon caps a virtual display at 3840×2160 backing; a larger request hits a server-side
		/// "safe minimum" fallback (i.e. a degenerate canvas), so requests are clamped to the cap instead.
		public static let maxPixelWidth = 3840
		public static let maxPixelHeight = 2160

		/// - Parameters:
		///   - pixelWidth: desired backing width in pixels (clamped to `maxPixelWidth`, min 2).
		///   - pixelHeight: desired backing height in pixels (clamped to `maxPixelHeight`, min 2).
		///   - hidpiScale: backing:point ratio. `1` = flat (backing == points). Values above 1 ask the host to
		///     render Retina-style: the decode cost is unchanged (it is fixed by the PIXEL dims) while the
		///     logical desktop shrinks by the scale. Fractional values are allowed — see `logicalWidth`.
		///
		/// Dimensions are forced EVEN: HEVC chroma/CTU alignment and the 4-way tile split both behave badly on
		/// odd sizes, and the daemon would round anyway. The derived point dims are forced even for the same
		/// reason (a 1.5 scale on an odd point count would otherwise produce a fractional backing).
		public init(pixelWidth: Int, pixelHeight: Int, hidpiScale: Double = 1) {
			let scale = max(1.0, hidpiScale)
			let w = min(max(2, pixelWidth), Self.maxPixelWidth)
			let h = min(max(2, pixelHeight), Self.maxPixelHeight)
			let evenW = w - (w % 2)
			let evenH = h - (h % 2)
			self.pixelWidth = evenW
			self.pixelHeight = evenH

			let pointW = max(2, Int((Double(evenW) / scale).rounded()))
			let pointH = max(2, Int((Double(evenH) / scale).rounded()))
			self.logicalWidth = pointW - (pointW % 2)
			self.logicalHeight = pointH - (pointH % 2)
		}

		/// The realised backing:point ratio (may differ from the requested scale by the even-rounding above).
		public var hidpiScale: Double { Double(pixelWidth) / Double(max(1, logicalWidth)) }

		/// Total backing pixels — the decode-cost proxy. 5120×1440 = 7.37 M saturates an A18 at 4:4:4.
		public var backingPixelCount: Int { pixelWidth * pixelHeight }

		// MARK: - Presets

		/// 1280×720 — smoothest; largest decode headroom.
		public static let hd720 = HighPerformanceDisplay(pixelWidth: 1280, pixelHeight: 720)
		/// 1920×1080 — the recommended default: matches Apple's own advertised primary mode in points and
		/// leaves comfortable A18 decode headroom.
		public static let hd1080 = HighPerformanceDisplay(pixelWidth: 1920, pixelHeight: 1080)
		/// 2560×720 — 32:9, preserves an ultrawide window layout at low decode cost.
		public static let ultrawide720 = HighPerformanceDisplay(pixelWidth: 2560, pixelHeight: 720)
		/// 2560×1440 — QHD; more detail, less headroom.
		public static let qhd1440 = HighPerformanceDisplay(pixelWidth: 2560, pixelHeight: 1440)
		/// 3840×1080 — 32:9 at the daemon's width cap. NOTE: ~4.15 Mpx/frame; because the daemon RAISES the
		/// frame rate when it has fewer pixels to encode (~90 fps observed at a small canvas), this sits close
		/// to the measured A18 ceiling and may not fully resolve slow-motion. Offer it, but not as the default.
		public static let ultrawide1080 = HighPerformanceDisplay(pixelWidth: 3840, pixelHeight: 1080)
	}
}
