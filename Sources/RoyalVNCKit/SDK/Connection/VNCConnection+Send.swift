#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Client to Server Messages
extension VNCConnection {
	func startSendLoop() {
        logger.logDebug("Starting send loop")

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
		guard let framebuffer,
              !continuousUpdatesEnabledLocked() else {
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
