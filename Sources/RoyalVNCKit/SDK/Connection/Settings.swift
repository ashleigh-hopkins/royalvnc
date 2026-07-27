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

		/// Opt-in to the Apple High-Performance control path (HP-SPECS §2, Q1). Default `false`.
		///
		/// When `false` (the default) the client is byte-for-byte identical to the standard RFB path:
		/// the `RFB 003.889` banner is never sent, Apple security type 33 is never selected even if the
		/// server offers it, and the connection object is a bare `NetworkConnection` (no record-layer
		/// decorator). When `true` against an Apple Remote Desktop host, the client sends `003.889`,
		/// selects type 33 (RSA-SRP), and arms the AES-128-CBC control record layer after the `0x44f`
		/// rekey. Auto-detect is deliberately rejected (it would regress standard servers that offer
		/// `003.889` or type-33-over-TLS). Connect-time only.
		public let enableHighPerformance: Bool

		/// Requested Apple-HP **virtual-display** geometry, sent as the `0x1d` SetDisplayConfiguration during
		/// the HP plaintext prelude. `nil` (the default) sends nothing: byte-for-byte today's behaviour, where
		/// the daemon streams the host's PHYSICAL display and the host screen keeps mirroring the session.
		///
		/// Non-nil asks `screensharingd` to create a SkyLight virtual display of that size and encode it
		/// instead — the mechanism Apple's own client uses so it never has to decode a huge panel. This is the
		/// lever for decode cost: on an A18 a 5120×1440 4:4:4 stream saturates the HW decoder (~4 ms/AU) and
		/// slips into unbounded slow-motion, while ~1920×1080 has ample headroom.
		///
		/// ⚠️ Setting this **curtains the host**: the Mac's physical screen stops showing the desktop for the
		/// session, and creating a differently-shaped display reflows the user's windows (persisting after
		/// disconnect). Therefore it must remain explicitly opt-in, never a silent default. Ignored unless
		/// `enableHighPerformance` is `true`. Connect-time only.
		public let highPerformanceDisplay: HighPerformanceDisplay?

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
					enableHighPerformance: Bool = false,
					highPerformanceDisplay: HighPerformanceDisplay? = nil) {
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
			self.enableHighPerformance = enableHighPerformance
			self.highPerformanceDisplay = highPerformanceDisplay
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
