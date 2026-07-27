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
		/// Backing:point ratio advertised in the mode table. `1` = flat (backing == points) — the low-decode
		/// choice, and the default here. `2` = Retina (backing = 2× points), which QUADRUPLES decode cost.
		public let hidpiScale: Int

		/// The daemon caps a virtual display at 3840×2160 backing; a larger request hits a server-side
		/// "safe minimum" fallback (i.e. a degenerate canvas), so requests are clamped to the cap instead.
		public static let maxPixelWidth = 3840
		public static let maxPixelHeight = 2160

		/// - Parameters:
		///   - pixelWidth: desired backing width in pixels (clamped to `maxPixelWidth`, min 2).
		///   - pixelHeight: desired backing height in pixels (clamped to `maxPixelHeight`, min 2).
		///   - hidpiScale: backing:point ratio; `1` (default) keeps decode cost at the pixel count stated.
		///
		/// Dimensions are forced EVEN: HEVC chroma/CTU alignment and the 4-way tile split both behave badly on
		/// odd sizes, and the daemon would round anyway.
		public init(pixelWidth: Int, pixelHeight: Int, hidpiScale: Int = 1) {
			let scale = max(1, hidpiScale)
			let w = min(max(2, pixelWidth), Self.maxPixelWidth)
			let h = min(max(2, pixelHeight), Self.maxPixelHeight)
			self.pixelWidth = w - (w % 2)
			self.pixelHeight = h - (h % 2)
			self.hidpiScale = scale
		}

		/// Logical (point) width that goes on the `0x1d` wire.
		public var logicalWidth: Int { max(1, pixelWidth / hidpiScale) }
		/// Logical (point) height that goes on the `0x1d` wire.
		public var logicalHeight: Int { max(1, pixelHeight / hidpiScale) }

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
