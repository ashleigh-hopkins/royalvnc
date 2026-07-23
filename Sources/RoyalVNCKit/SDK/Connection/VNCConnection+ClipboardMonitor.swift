#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCConnection {
	func startMonitoringClipboard() {
		guard settings.isClipboardRedirectionEnabled else { return }

#if canImport(UIKit)
		// iOS/tvOS/visionOS/Catalyst: the monitor's only way to detect a local clipboard change is to
		// read UIPasteboard's CONTENT (`.string`), which triggers the system "Allow Paste" prompt on
		// every poll. Auto-polling therefore spams the prompt and wedges the UI. Clients on these
		// platforms send the clipboard EXPLICITLY (user-initiated, via `sendClientCutText`) instead;
		// the server -> client receive path (didReceiveServerCutText) is unaffected. See the app's
		// VNCSessionController.sendLocalClipboardToRemote.
		_ = clipboardMonitor   // keep the property referenced; no auto-poll on this platform
#else
		clipboardMonitor.startMonitoring()
#endif
	}

	func stopMonitoringClipboard() {
		guard settings.isClipboardRedirectionEnabled else { return }

		clipboardMonitor.stopMonitoring()
	}
}

// MARK: - VNCClipboardMonitorDelegate
extension VNCConnection: VNCClipboardMonitorDelegate {
	func clipboardMonitorShouldMonitor(_ clipboardMonitor: VNCClipboardMonitor) -> Bool {
		let isConnected = connectionState.status == .connected

		return isConnected
	}

	func clipboardMonitor(_ clipboardMonitor: VNCClipboardMonitor,
						  didChangeText text: String) {
		logger.logDebug("Clipboard Monitor did change text")

		guard settings.isClipboardRedirectionEnabled else { return }

		enqueueClientCutTextMessage(text)
	}
}
