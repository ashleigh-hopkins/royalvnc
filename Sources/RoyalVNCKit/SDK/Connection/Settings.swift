#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

public extension VNCConnection {
#if canImport(ObjectiveC)
	@objc(VNCConnectionSettings)
#endif
    final class Settings: NSObjectOrAnyObject {
#if canImport(ObjectiveC)
		@objc
#endif
		public let isDebugLoggingEnabled: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let hostname: String

#if canImport(ObjectiveC)
		@objc
#endif
		public let port: UInt16

#if canImport(ObjectiveC)
		@objc
#endif
		public let isShared: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let isScalingEnabled: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let useDisplayLink: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let inputMode: InputMode

#if canImport(ObjectiveC)
		@objc
#endif
		public let isClipboardRedirectionEnabled: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let colorDepth: ColorDepth

		public let frameEncodings: [VNCFrameEncodingType]

		/// Initial JPEG quality level (Tight encoding) advertised to the server. Runtime-adjustable
		/// via `VNCConnection.updateQuality(jpegQualityLevel:compressionLevel:)`.
		public let jpegQualityLevel: JPEGQualityLevel

		/// Initial compression level advertised to the server. Runtime-adjustable via
		/// `VNCConnection.updateQuality(jpegQualityLevel:compressionLevel:)`.
		public let compressionLevel: CompressionLevel

		/// Whether Continuous Updates should be requested once the server advertises support.
		/// Runtime-adjustable via `VNCConnection.setContinuousUpdatesEnabled(_:)`.
		public let useContinuousUpdates: Bool

		/// Whether to optimistically enable Continuous Updates (T1 Change A) — send
		/// `EnableContinuousUpdates` without waiting for the server to advertise support, to probe a
		/// server (e.g. Apple's Standard server) that never sends `EndOfContinuousUpdates`. Default
		/// `false`; connect-time only. A one-shot watchdog reverts to polling if no frames arrive.
		public let useOptimisticContinuousUpdates: Bool

		/// The session's authentication + pixel-transport tier (SPECS §1/§3.1). Replaces the former
		/// `enableHighPerformance: Bool` (Q1 DECIDED, removed with no shim — SPECS §3.3): a boolean pair
		/// would permit an invalid `standardRFB`-with-Apple-auth state, whereas exactly three tiers are
		/// meaningful. Default `.standardRFB`, byte-for-byte identical to the pre-existing behaviour: the
		/// `RFB 003.889` banner is never sent, Apple security type 33 is never selected even if the server
		/// offers it, and the connection object is a bare `NetworkConnection` (no record-layer decorator).
		/// `.appleStandardFramebuffer` and `.appleHighPerformanceMedia` both authenticate as type 33
		/// (RSA-SRP) and arm the AES-128-CBC control record layer after the `0x44f` rekey; only the latter
		/// additionally negotiates the `0x1c` UDP/SRTP media offer (see `usesAppleControlChannel` /
		/// `negotiatesHighPerformanceMedia` below). Auto-detect is deliberately rejected (it would regress
		/// standard servers that offer `003.889` or type-33-over-TLS). Swift-only (no `@objc` mirror — the
		/// `@objc` convenience init never exposed HP fields either, NFR-COMPAT). Connect-time only.
		public let mode: SessionMode

		/// WHEN `true`, this session authenticates as Apple Remote Desktop (type 33) and arms the
		/// AES-128-CBC record layer — true for BOTH Apple tiers (`.appleStandardFramebuffer` AND
		/// `.appleHighPerformanceMedia`). `false` only for `.standardRFB`.
		var usesAppleControlChannel: Bool { mode != .standardRFB }

		/// WHEN `true`, this session additionally negotiates the `0x1c` UDP/SRTP HEVC media offer — true
		/// only for `.appleHighPerformanceMedia`.
		var negotiatesHighPerformanceMedia: Bool { mode == .appleHighPerformanceMedia }

		/// Requested Apple **virtual-display** geometry, sent as the `0x1d` SetDisplayConfiguration during
		/// the shared Apple plaintext prelude (`armAppleRecordLayer()`). `nil` (the default) sends nothing:
		/// byte-for-byte the pre-existing behaviour, where the daemon streams the host's PHYSICAL display
		/// and the host screen keeps mirroring the session. This is shared by BOTH Apple tiers (SPECS
		/// §6/§9.1, B2): `.appleHighPerformanceMedia` uses it to bound HEVC decode cost;
		/// `.appleStandardFramebuffer` uses the SAME request to size its RFB-rect canvas (fps there is
		/// `pixel_rate / canvas_area`, so a smaller requested canvas is the dominant lever for clearing
		/// 30 fps — SPECS NFR-FPS). `nil` is the NORMAL, shipped-default case for both tiers (G1: no
		/// tier-specific default, no first-run prompt) — sizing then falls back to `ServerInit` (or, for
		/// HP, the negotiated media canvas).
		///
		/// Non-nil asks `screensharingd` to create a SkyLight virtual display of that size and encode it
		/// instead — the mechanism Apple's own client uses so it never has to decode a huge panel. This is the
		/// lever for decode cost: on an A18 a 5120×1440 4:4:4 stream saturates the HW decoder (~4 ms/AU) and
		/// slips into unbounded slow-motion, while ~1920×1080 has ample headroom.
		///
		/// ⚠️ Setting this **curtains the host**: the Mac's physical screen stops showing the desktop for the
		/// session, and creating a differently-shaped display reflows the user's windows (persisting after
		/// disconnect). Therefore it must remain explicitly opt-in, never a silent default. Ignored unless
		/// `usesAppleControlChannel` is `true`. Connect-time only.
		public let highPerformanceDisplay: HighPerformanceDisplay?

		/// Bitrate to request from the host over RTCP **TMMBR** (RFC 5104), in bits per second. `0` disables
		/// the request entirely (nothing extra goes on the wire).
		///
		/// PROBE. `screensharingd` was measured sending roughly the same total bitrate (~15 Mbps) regardless
		/// of canvas size — 1920×1080, 2868×1320 and 3840×2160 all landed within a few Mbps — so a larger
		/// virtual display spreads the same bits over more pixels and the picture goes blocky, worst of all
		/// when zoomed. The client has never expressed a bandwidth preference (RR/SR/FIR/PLI/NACK say nothing
		/// about it), so if AVConference sizes its encoder from receiver-side signalling it has never heard
		/// from us. Ignored unless `negotiatesHighPerformanceMedia` is `true`.
		///
		/// **RESULT: screensharingd IGNORES TMMBR — measured, so this now defaults to 0 (off).** Live probe
		/// on macOS 27: 60 Mbps requested every 2 s for ~78 s while `pktsPerAU` stayed flat at 1.3–2.6 with no
		/// trend or step. The builder and this knob are retained because the negative is worth keeping
		/// reproducible (set a non-zero value to re-run it against a future macOS), but nothing goes on the
		/// wire by default. The remaining bitrate candidate is the unexplored `res`/params fields in the
		/// `0x1c` HEVC bank.
		public let highPerformanceRequestedBitrate: UInt64

		/// EXPERIMENT (T21): if non-zero, prune the `0x1c` offer's `field 9` tier table to rungs at or above
		/// this bitrate (bits/s). `0` (default) sends the captured table verbatim.
		///
		/// `field 9` is a 10-entry table we send in both the video and audio MediaBlobs, inherited from a
		/// capture and labelled a guess ("audio config"). Decoded it looks like a rate ladder — six
		/// `(0, rate, size)` rungs spanning 6–100 Mbps — and the measured ~22–24 Mbps stream ceiling sits next
		/// to its 20 Mbps rung. If the host selects a rung, dropping the low ones should move the ceiling.
		public let highPerformanceMinBandwidthTier: UInt64

		/// Default: **0 — send no TMMBR**, because the host was measured ignoring it (see above). 60 Mbps is
		/// the value the probe used if you want to reproduce that measurement.
		public static let defaultRequestedBitrate: UInt64 = 0

#if canImport(ObjectiveC)
		@objc(frameEncodings)
#endif
		public var _objc_frameEncodings: [Int64] {
			frameEncodings.map({ $0.rawValue.rawValue })
		}

		public init(isDebugLoggingEnabled: Bool,
					hostname: String,
					port: UInt16,
					isShared: Bool,
					isScalingEnabled: Bool,
					useDisplayLink: Bool,
					inputMode: InputMode,
					isClipboardRedirectionEnabled: Bool,
					colorDepth: ColorDepth,
					frameEncodings: [VNCFrameEncodingType],
					jpegQualityLevel: JPEGQualityLevel = .default,
					compressionLevel: CompressionLevel = .default,
					useContinuousUpdates: Bool = false,
					useOptimisticContinuousUpdates: Bool = false,
					mode: SessionMode = .standardRFB,
					highPerformanceDisplay: HighPerformanceDisplay? = nil,
					highPerformanceRequestedBitrate: UInt64 = Settings.defaultRequestedBitrate,
					highPerformanceMinBandwidthTier: UInt64 = 0) {
			self.isDebugLoggingEnabled = isDebugLoggingEnabled

			self.hostname = hostname
			self.port = port

			self.isShared = isShared

			self.isScalingEnabled = isScalingEnabled
			self.useDisplayLink = useDisplayLink

			self.inputMode = inputMode

			self.isClipboardRedirectionEnabled = isClipboardRedirectionEnabled

			self.colorDepth = colorDepth
			self.frameEncodings = frameEncodings

			self.jpegQualityLevel = jpegQualityLevel
			self.compressionLevel = compressionLevel
			self.useContinuousUpdates = useContinuousUpdates
			self.useOptimisticContinuousUpdates = useOptimisticContinuousUpdates
			self.mode = mode
			self.highPerformanceDisplay = highPerformanceDisplay
			self.highPerformanceRequestedBitrate = highPerformanceRequestedBitrate
			self.highPerformanceMinBandwidthTier = highPerformanceMinBandwidthTier
		}

#if canImport(ObjectiveC)
		@objc
#endif
		public convenience init(isDebugLoggingEnabled: Bool,
								hostname: String,
								port: UInt16,
								isShared: Bool,
								isScalingEnabled: Bool,
								useDisplayLink: Bool,
								inputMode: InputMode,
								isClipboardRedirectionEnabled: Bool,
								colorDepth: ColorDepth,
								frameEncodings: [Int64]) {
			let frameEncodingsSwift: [VNCFrameEncodingType] = frameEncodings.compactMap({
				guard let objcFrameEncodingType = _ObjC_VNCFrameEncodingType(rawValue: $0) else { return nil }

				return VNCFrameEncodingType.fromObjCFrameEncodingType(objcFrameEncodingType)
			})

			self.init(isDebugLoggingEnabled: isDebugLoggingEnabled,
					  hostname: hostname,
					  port: port,
					  isShared: isShared,
					  isScalingEnabled: isScalingEnabled,
					  useDisplayLink: useDisplayLink,
					  inputMode: inputMode,
					  isClipboardRedirectionEnabled: isClipboardRedirectionEnabled,
					  colorDepth: colorDepth,
					  frameEncodings: frameEncodingsSwift)
		}
	}
}

public extension VNCConnection.Settings {
	/// The session's authentication + pixel-transport tier (SPECS §1/§3.1). Swift-only — no `@objc`
	/// mirror, matching `mode`'s own doc comment (NFR-COMPAT).
	enum SessionMode: Sendable, Equatable {
		/// RFB 3.8 (or the Apple-DH type-30 handshake over RFB 3.8), plaintext. The pre-existing,
		/// default tier — unaffected by this enum's introduction (AC-5).
		case standardRFB

		/// `003.889` + Apple security type 33 (RSA-SRP) + AES-128-CBC record layer, but NO `0x1c` UDP
		/// media offer: classic RFB rects (ZRLE/Zlib) pushed continuously via AutoFrameBufferUpdate.
		case appleStandardFramebuffer

		/// `003.889` + Apple security type 33 (RSA-SRP) + AES-128-CBC record layer + the `0x1c` UDP/SRTP
		/// HEVC media offer. The pre-existing High-Performance tier — unaffected by this enum's
		/// introduction beyond the mechanical `enableHighPerformance` → `mode` rename (AC-5).
		case appleHighPerformanceMedia
	}
}

public extension VNCConnection.Settings {
#if canImport(ObjectiveC)
	@objc(VNCInputMode)
#endif
	enum InputMode: UInt32 {
		case none

		case forwardKeyboardShortcutsIfNotInUseLocally
		case forwardKeyboardShortcutsEvenIfInUseLocally
		case forwardAllKeyboardShortcutsAndHotKeys
	}

#if canImport(ObjectiveC)
	@objc(VNCColorDepth)
#endif
	enum ColorDepth: UInt8 {
		case depth8Bit = 8   // 256 Colors
		case depth16Bit = 16
		case depth24Bit = 24
	}
}

#if os(macOS)
public extension VNCConnection.Settings.InputMode {
	var requiresAccessibilityPermissions: Bool {
		self == .forwardAllKeyboardShortcutsAndHotKeys
	}
}

#if canImport(ObjectiveC)
@objc(VNCInputModeUtils)
#endif
// swiftlint:disable:next type_name
public final class _ObjC_VNCInputModeUtils: NSObject {
#if canImport(ObjectiveC)
	@objc
#endif
	public static func inputModeRequiresAccessibilityPermissions(_ inputMode: VNCConnection.Settings.InputMode) -> Bool {
		inputMode.requiresAccessibilityPermissions
	}
}
#endif
