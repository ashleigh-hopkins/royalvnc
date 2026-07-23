#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCConnection {
    final class State {
		var disconnectRequested = false

		var serverProtocolVersion: VNCProtocol.ProtocolVersion?
		var agreedProtocolVersion: VNCProtocol.ProtocolVersion?

		var isTightSecurityEnabled = false

		var framebufferWidth: UInt16 = 0
		var framebufferHeight: UInt16 = 0

		var serverPixelFormat: VNCProtocol.PixelFormat?
		var pixelFormat: VNCProtocol.PixelFormat?

		var desktopName: String?

		var incrementalUpdatesEnabled = false

		var areContinuousUpdatesSupported = false
		var areContinuousUpdatesEnabled = false

		// Optimistic Continuous Updates (T1 Change A). Probes whether a server that never advertises CU
		// support (e.g. Apple's Standard server) still honours an unsolicited EnableContinuousUpdates.
		var wantsOptimisticContinuousUpdates = false
		var optimisticCUActive = false
		/// Monotonic count of received FramebufferUpdate messages. Feeds the optimistic-CU watchdog
		/// (no wall/uptime clock needed). Only ever mutated under `stateLock` via noteFramebufferUpdateReceived().
		var framebufferUpdateCount: UInt64 = 0

		// Runtime-adjustable quality state. Seeded from Settings in VNCConnection.init; mutated by
		// the public quality API and read by orderedEncodingTypes()/the Continuous Updates handshake.
		var jpegQualityLevel: VNCConnection.Settings.JPEGQualityLevel = .default
		var compressionLevel: VNCConnection.Settings.CompressionLevel = .default
		var wantsContinuousUpdates = false
		/// Preferred frame encodings. Seeded from Settings.frameEncodings; runtime-adjustable so a
		/// mid-session SetEncodings can change the preferred encoding order.
		var frameEncodings: [VNCFrameEncodingType] = []
	}
}

extension VNCConnection.State {
	var isAppleRemoteDesktop: Bool {
		return serverProtocolVersion?.isAppleRemoteDesktop ?? false
	}
}
