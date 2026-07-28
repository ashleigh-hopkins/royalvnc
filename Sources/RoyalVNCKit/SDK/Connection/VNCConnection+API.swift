#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Connect/Disconnect
public extension VNCConnection {
#if canImport(ObjectiveC)
	@objc
#endif
	func connect() {
		beginConnecting()
	}

#if canImport(ObjectiveC)
    @objc
#endif
	func disconnect() {
		beginDisconnecting()
	}

	/// Whether the underlying network connection currently has a live socket. Distinct from
	/// `connectionState` (which is updated via the delegate hop and can lag): this reflects the live
	/// transport. Used by the app's foreground-recovery decision (T1 Change E) to tell a genuinely
	/// live `.connected` session (repaint) from a stale one whose socket has dropped (reconnect/none).
	var isReady: Bool { connection.isReady }
}

public extension VNCConnection {
#if canImport(ObjectiveC)
    @objc
#endif
	func updateColorDepth(_ colorDepth: Settings.ColorDepth) {
		guard let framebuffer = framebuffer else { return }

		let newPixelFormat = VNCProtocol.PixelFormat(depth: colorDepth.rawValue)

		state.pixelFormat = newPixelFormat

		let sendPixelFormatMessage = VNCProtocol.SetPixelFormat(pixelFormat: newPixelFormat)

		clientToServerMessageQueue.enqueue(sendPixelFormatMessage)

		recreateFramebuffer(size: framebuffer.size,
							screens: framebuffer.screens,
							pixelFormat: newPixelFormat)
	}
}

// MARK: - Mouse Input
public extension VNCConnection {
#if canImport(ObjectiveC)
    @objc
#endif
    func mouseMove(x: UInt16, y: UInt16) {
        enqueueMouseEvent(nonNormalizedX: x,
                          nonNormalizedY: y)
    }

#if canImport(ObjectiveC)
    @objc
#endif
    func mouseButtonDown(_ button: VNCMouseButton,
                         x: UInt16, y: UInt16) {
        updateMouseButtonState(button: button,
                               isDown: true)

        enqueueMouseEvent(nonNormalizedX: x,
                          nonNormalizedY: y)
    }

#if canImport(ObjectiveC)
    @objc
#endif
    func mouseButtonUp(_ button: VNCMouseButton,
                       x: UInt16, y: UInt16) {
        updateMouseButtonState(button: button,
                               isDown: false)

        enqueueMouseEvent(nonNormalizedX: x,
                          nonNormalizedY: y)
    }

#if canImport(ObjectiveC)
    @objc
#endif
    func mouseWheel(_ wheel: VNCMouseWheel,
                    x: UInt16, y: UInt16,
                    steps: UInt32) {
        for _ in 0..<steps {
            updateMouseButtonState(wheel: wheel,
                                   isDown: true)

            enqueueMouseEvent(nonNormalizedX: x,
                              nonNormalizedY: y)

            updateMouseButtonState(wheel: wheel,
                                   isDown: false)
        }
    }
}

extension VNCConnection {
    func updateMouseButtonState(button: VNCMouseButton,
                                isDown: Bool) {
        updateMouseButtonState(mousePointerButton: button.mousePointerButton,
                               isDown: isDown)
    }

    func updateMouseButtonState(wheel: VNCMouseWheel,
                                isDown: Bool) {
        updateMouseButtonState(mousePointerButton: wheel.mousePointerButton,
                               isDown: isDown)
    }

    func updateMouseButtonState(mousePointerButton: VNCProtocol.MousePointerButton,
                                isDown: Bool) {
        if isDown {
            mouseButtonState.insert(mousePointerButton)
        } else {
            mouseButtonState.remove(mousePointerButton)
        }
    }
}

// MARK: - Keyboard Input
public extension VNCConnection {
	func keyDown(_ key: VNCKeyCode) {
		enqueueKeyEvent(key: key,
						isDown: true)
	}

#if canImport(ObjectiveC)
	@objc(keyDown:)
#endif
	func _objc_keyDown(_ key: UInt32) {
		keyDown(.init(key))
	}

	func keyUp(_ key: VNCKeyCode) {
		enqueueKeyEvent(key: key,
						isDown: false)
	}

#if canImport(ObjectiveC)
	@objc(keyUp:)
#endif
	func _objc_keyUp(_ key: UInt32) {
		keyUp(.init(key))
	}
}

// MARK: - Clipboard
public extension VNCConnection {
	// Sends the given text to the server for client -> server clipboard redirection. Enqueues onto the
	// thread-safe client-to-server message queue, so it is safe to call from the main thread like the
	// mouse/keyboard input APIs.
	//
	// T12: on an Apple-authenticated session the standard RFB `ClientCutText` (`0x06`) is a dead end
	// against macOS screensharingd (it only writes the legacy latin-1 scrap). So Apple sessions route to
	// Apple's rich `0x1f` ClipboardSend instead (`sendAppleClipboardText`) — but ONLY when clipboard
	// redirection is actually enabled (Area-3 fix, SPECS §3.2/§5.3, AC-6): the Apple-Standard tier's
	// bring-up intentionally skips the `0x15`/`0x0b` enable-fetch this needs, and that tier's standard
	// receive loop has no tolerance for an unsolicited `0x1f` reply — so with redirection off this falls
	// through to the standard `0x06` (a harmless no-op against screensharingd, per the T12 finding),
	// rather than emitting an un-primed `0x1f` that could tear down a live session on a stray manual-Paste
	// tap. Non-Apple sessions are unaffected. This keeps callers (the app) transport-agnostic — they
	// always call `sendClientCutText`.
#if canImport(ObjectiveC)
	@objc
#endif
	func sendClientCutText(_ text: String) {
		if settings.usesAppleControlChannel, settings.isClipboardRedirectionEnabled {
			sendAppleClipboardText(text)
		} else {
			enqueueClientCutTextMessage(text)
		}
	}
}
