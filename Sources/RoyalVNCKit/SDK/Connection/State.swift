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

		// Runtime-adjustable quality state. Seeded from Settings in VNCConnection.init; mutated by
		// the public quality API and read by orderedEncodingTypes()/the Continuous Updates handshake.
		var jpegQualityLevel: VNCConnection.Settings.JPEGQualityLevel = .default
		var compressionLevel: VNCConnection.Settings.CompressionLevel = .default
		var wantsContinuousUpdates = false
	}
}

extension VNCConnection.State {
	var isAppleRemoteDesktop: Bool {
		return serverProtocolVersion?.isAppleRemoteDesktop ?? false
	}
}
