#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Quality level value types

public extension VNCConnection.Settings {
	/// JPEG quality level advertised to the server for Tight encoding.
	///
	/// `level0` is the lowest quality (smallest, most lossy), `level9` the highest.
	/// `disabled` advertises no JPEG quality pseudo-encoding, letting the server pick / disabling
	/// lossy JPEG sub-encoding of Tight rectangles (effectively lossless Tight).
	enum JPEGQualityLevel: Int, Sendable, CaseIterable {
		case disabled = -1
		case level0 = 0
		case level1 = 1
		case level2 = 2
		case level3 = 3
		case level4 = 4
		case level5 = 5
		case level6 = 6
		case level7 = 7
		case level8 = 8
		case level9 = 9

		/// Matches the previously hard-coded value, so it is behaviour-preserving by default.
		public static let `default`: JPEGQualityLevel = .level6

		/// The pseudo-encoding to advertise in `SetEncodings`, or `nil` when disabled.
		var pseudoEncodingType: VNCPseudoEncodingType? {
			switch self {
				case .disabled: return nil
				case .level0: return .jpegQualityLevel0
				case .level1: return .jpegQualityLevel1
				case .level2: return .jpegQualityLevel2
				case .level3: return .jpegQualityLevel3
				case .level4: return .jpegQualityLevel4
				case .level5: return .jpegQualityLevel5
				case .level6: return .jpegQualityLevel6
				case .level7: return .jpegQualityLevel7
				case .level8: return .jpegQualityLevel8
				case .level9: return .jpegQualityLevel9
			}
		}
	}

	/// Compression level advertised to the server.
	///
	/// `level1` is the lowest compression (fastest, largest), `level10` the highest.
	/// `disabled` advertises no compression-level pseudo-encoding, letting the server pick.
	enum CompressionLevel: Int, Sendable, CaseIterable {
		case disabled = -1
		case level1 = 1
		case level2 = 2
		case level3 = 3
		case level4 = 4
		case level5 = 5
		case level6 = 6
		case level7 = 7
		case level8 = 8
		case level9 = 9
		case level10 = 10

		/// Matches the previously hard-coded value, so it is behaviour-preserving by default.
		public static let `default`: CompressionLevel = .level6

		/// The pseudo-encoding to advertise in `SetEncodings`, or `nil` when disabled.
		var pseudoEncodingType: VNCPseudoEncodingType? {
			switch self {
				case .disabled: return nil
				case .level1: return .compressionLevel1
				case .level2: return .compressionLevel2
				case .level3: return .compressionLevel3
				case .level4: return .compressionLevel4
				case .level5: return .compressionLevel5
				case .level6: return .compressionLevel6
				case .level7: return .compressionLevel7
				case .level8: return .compressionLevel8
				case .level9: return .compressionLevel9
				case .level10: return .compressionLevel10
			}
		}
	}
}

// MARK: - Runtime-adjustable quality API

public extension VNCConnection {
	/// The JPEG quality level currently advertised to the server. Starts from `Settings.jpegQualityLevel`.
	var jpegQualityLevel: Settings.JPEGQualityLevel { state.jpegQualityLevel }

	/// The compression level currently advertised to the server. Starts from `Settings.compressionLevel`.
	var compressionLevel: Settings.CompressionLevel { state.compressionLevel }

	/// Whether the client has requested Continuous Updates. Starts from `Settings.useContinuousUpdates`.
	var isContinuousUpdatesRequested: Bool { state.wantsContinuousUpdates }

	/// Adjust JPEG quality and/or compression level mid-session.
	///
	/// Re-sends `SetEncodings` with the new pseudo-encoding hints so the server applies the new
	/// quality to subsequent framebuffer updates. Safe to call from any thread (mirrors the input
	/// APIs): the message is enqueued onto the client-to-server message queue and sent by the send
	/// loop. Has no visible effect until a connection is established.
	func updateQuality(jpegQualityLevel: Settings.JPEGQualityLevel? = nil,
					   compressionLevel: Settings.CompressionLevel? = nil,
					   frameEncodings: [VNCFrameEncodingType]? = nil) {
		if let jpegQualityLevel { state.jpegQualityLevel = jpegQualityLevel }
		if let compressionLevel { state.compressionLevel = compressionLevel }
		if let frameEncodings { state.frameEncodings = frameEncodings }

		guard connection.isReady,
			  let encodings = try? orderedEncodingTypes() else { return }

		clientToServerMessageQueue.enqueue(VNCProtocol.SetEncodings(encodingTypes: encodings))
	}

	/// Enable or disable Continuous Updates mid-session (and update the desired setting).
	///
	/// When enabled, the server pushes framebuffer updates without per-frame requests (lower
	/// latency). When disabled, the server sends `EndOfContinuousUpdates` and the SDK resumes the
	/// per-frame request loop. No effect if the server has not advertised Continuous Updates support.
	func setContinuousUpdatesEnabled(_ enabled: Bool) {
		state.wantsContinuousUpdates = enabled

		guard connection.isReady,
			  state.areContinuousUpdatesSupported,
			  let framebuffer else { return }

		let region = VNCRegion(location: .zero, size: framebuffer.size)
		let message = VNCProtocol.EnableContinuousUpdates(enable: enabled,
														  xPosition: region.x,
														  yPosition: region.y,
														  width: region.width,
														  height: region.height)

		clientToServerMessageQueue.enqueue(message)

		// Enabling stops the per-frame request loop immediately (the send guard checks this flag).
		// Disabling is finalized when the server replies with EndOfContinuousUpdates, which resets
		// the flag and resumes the request loop.
		if enabled {
			state.areContinuousUpdatesEnabled = true
		}
	}
}
