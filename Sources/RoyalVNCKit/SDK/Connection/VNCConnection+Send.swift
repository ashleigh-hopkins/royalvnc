#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Client to Server Messages
extension VNCConnection {
	func startSendLoop() {
        logger.logDebug("Starting send loop")

		// T12: seed the Apple in-protocol clipboard (0x15 enable + prime 0x0b fetch) as the first
		// client→server records. No-op unless HP + clipboard redirection are on (record layer active).
		enqueueAppleClipboardBringUpIfNeeded()

		sendTask = Task(priority: taskPriority) {
			while !state.disconnectRequested,
                  connection.isReady {
				do {
					try await send()
				} catch {
					handleBreakingError(error)
				}
			}
		}
	}

	func sendFramebufferUpdateRequest() async throws {
		// SPECS §4.4/FR-4: the Apple-Standard tier's ONLY per-viewer push mechanism is AutoFBU
		// (wire[4..7]=0), armed once during performAppleStandardControlBringUp(), which also sends the
		// tier's ONE allowed initial FramebufferUpdateRequest directly (not via this zero-arg wrapper).
		// This function is otherwise called both at initial-connect (connectionDidBecomeReady, which
		// already skips it for this tier — see the settings.usesAppleControlChannel branch there) AND,
		// critically, after EVERY decoded update on the standard receive loop
		// (handleFramebufferUpdateMessage()/handleEndOfContinuousUpdatesMessage(), reused unchanged by
		// this tier per SPECS §5.1). Left ungated, that per-update call would re-request on every single
		// frame — exactly the *steady-state* polling FR-4 forbids, and the device-confirmed "Change B"
		// stall (fork note #6): requesting while the daemon is still mid-transmitting makes
		// screensharingd stop answering. `continuousUpdatesEnabledLocked()` cannot substitute for this
		// guard — this tier never enables RFB Continuous Updates, so that flag stays false throughout.
		guard let framebuffer,
              !continuousUpdatesEnabledLocked(),
              !settings.usesAppleControlChannel else {
            return
        }

		let incremental = state.incrementalUpdatesEnabled

		let fullFramebufferRegion = VNCRegion(location: .zero,
											  size: framebuffer.size)

		// Request next update
		try await sendFramebufferUpdateRequest(incremental: incremental,
											   region: fullFramebufferRegion)

		if !incremental {
			state.incrementalUpdatesEnabled = true
		}
	}

	func sendEnableContinuousUpdates() async throws {
		guard let framebuffer,
              state.areContinuousUpdatesSupported,
              !continuousUpdatesEnabledLocked() else {
            return
        }

		let fullFramebufferRegion = VNCRegion(location: .zero,
											  size: framebuffer.size)

		try await sendEnableContinuousUpdates(enable: true,
											  region: fullFramebufferRegion)

		setContinuousUpdatesEnabledLocked(true)
	}

	/// Enable Continuous Updates optimistically — WITHOUT the areContinuousUpdatesSupported guard —
	/// to probe a server (e.g. Apple's Standard server) that never advertises support via
	/// EndOfContinuousUpdates. Deliberately does not send an initial polling request: a compliant
	/// server streams in response to the enable region; a non-compliant one leaves framebufferUpdateCount
	/// at 0, which the watchdog detects. (T1 Change A.)
	func sendOptimisticEnableContinuousUpdates() async throws {
		guard let framebuffer,
              !continuousUpdatesEnabledLocked() else {
            return
        }

		let region = VNCRegion(location: .zero,
							   size: framebuffer.size)

		try await sendEnableContinuousUpdates(enable: true,
											  region: region)

		stateLock.lock()
		state.areContinuousUpdatesEnabled = true
		state.optimisticCUActive = true
		stateLock.unlock()
	}
}

private extension VNCConnection {
	func send() async throws {
		guard !state.disconnectRequested,
              connection.isReady,
			  let message = clientToServerMessageQueue.dequeue() else {
			try await Task.sleep(seconds: 0.01)

			return
		}

		try await sendMessage(message)
	}

	func sendFramebufferUpdateRequest(incremental: Bool,
									  region: VNCRegion) async throws {
		let framebufferUpdateRequest = VNCProtocol.FramebufferUpdateRequest(incremental: incremental,
																			xPosition: region.location.x,
																			yPosition: region.location.y,
																			width: region.size.width,
																			height: region.size.height)

		try await sendMessage(framebufferUpdateRequest)
	}

	func sendEnableContinuousUpdates(enable: Bool,
									 region: VNCRegion) async throws {
		let message = VNCProtocol.EnableContinuousUpdates(enable: enable,
														  xPosition: region.x,
														  yPosition: region.y,
														  width: region.width,
														  height: region.height)

		try await sendMessage(message)
	}

	func sendMessage(_ message: VNCSendableMessage) async throws {
		try await message.send(connection: connection)
	}
}
