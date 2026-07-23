#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

// MARK: - Server to Client Messages
extension VNCConnection {
	func startReceiveLoop() {
        logger.logDebug("Starting receive loop")

        receiveTask = Task(priority: taskPriority) {
			while !state.disconnectRequested,
                  connection.isReady {
				do {
					try await receive()
				} catch {
					handleBreakingError(error)
				}
			}
		}
	}
}

private extension VNCConnection {
	func receive() async throws {
		guard !state.disconnectRequested else {
			// Just ignore, since disconnect has already been requested
			return
		}

        guard connection.isReady else {
			throw VNCError.connection(.notReady)
		}

		let serverToClientMessage = try await VNCProtocol.ServerToClientMessage.receive(connection: connection)

		try await didReceive(messageType: serverToClientMessage.messageType)
	}

	func didReceive(messageType: UInt8) async throws {
		switch messageType {
			case VNCProtocol.FramebufferUpdate.messageType:
				try await handleFramebufferUpdateMessage()

			case VNCProtocol.SetColourMapEntries.messageType:
				try await handleSetColourMapEntriesMessage()

			case VNCProtocol.ServerCutText.messageType:
				try await handleServerCutTextMessage()

			case VNCProtocol.Bell.messageType:
				try await handleBellMessage()

			case VNCProtocol.EndOfContinuousUpdates.messageType:
				try await handleEndOfContinuousUpdatesMessage()

			default:
				throw VNCError.protocol(.unsupportedServerToClientMessage(messageType: messageType))
		}
	}

	func handleFramebufferUpdateMessage() async throws {
		guard let framebuffer = framebuffer else {
			throw VNCError.protocol(.framebufferUpdateReceivedWithoutFramebuffer)
		}

		noteFramebufferUpdateReceived()   // (A) confirms the stream is live / feeds the CU watchdog

		logger.logDebug("Receiving Framebuffer Update")

		// (C invariant) inflate + pixel-convert + surface-write run serially on this receiveTask: the
		// shared stateful zlib streams (sharedZStream/sharedZRLEZStream) and the in-order byte cursor
		// forbid parallel/out-of-order decode. Render is already off-loop (snapshotRegion memcpy on the
		// connection queue, then main.async Metal upload). Surface double-buffering is rejected
		// (CopyRect/incremental need the persistent previous-frame surface).
		//
		// (B) When Continuous Updates are OFF, put the next request on the wire BEFORE decoding so the
		// decode overlaps the round-trip. Capture the framebuffer identity so a mid-decode resize/format
		// change (which swaps self.framebuffer) is corrected afterwards.
		let willPipeline = !continuousUpdatesEnabledLocked()
		if willPipeline {
			try await sendFramebufferUpdateRequest()
		}

		let framebufferUpdate = try await VNCProtocol.FramebufferUpdate.receive(connection: connection,
																				framebuffer: framebuffer,
																				encodings: encodings,
																				logger: logger)

		logger.logDebug("Received Framebuffer Update: \(framebufferUpdate)")

		/*
		// Write out the framebuffer for testing purposes
		try framebuffer.writeSurface()
		*/

		// Resize/format-change race guard: DesktopSize/ExtendedDesktopSize pseudo-rects (and a client
		// updateColorDepth) call recreateFramebuffer, which resets incrementalUpdatesEnabled=false and
		// SWAPS self.framebuffer. A request pipelined before decode used the OLD geometry + incremental=true.
		// If the framebuffer instance changed, emit a corrective request — recreateFramebuffer already
		// reset incrementalUpdatesEnabled, so it goes out non-incremental full-frame at the NEW geometry.
		let replaced = (self.framebuffer !== framebuffer)
		if !willPipeline || replaced {
			try await sendFramebufferUpdateRequest()
		}
	}

	func handleSetColourMapEntriesMessage() async throws {
		guard let framebuffer = framebuffer else {
			throw VNCError.protocol(.setColourMapEntriesReceivedWithoutFramebuffer)
		}

		logger.logDebug("Receiving Colour Map Entries")

		let colourMapEntries = try await VNCProtocol.SetColourMapEntries.receive(connection: connection,
																				 logger: logger)

		logger.logDebug("Received Colour Map Entries")

		framebuffer.updateColorMap(colourMapEntries)
	}

	func handleServerCutTextMessage() async throws {
		logger.logDebug("Receiving Clipboard Text from Server")

		let serverCutText = try await VNCProtocol.ServerCutText.receive(connection: connection,
																		logger: logger)

		let text = serverCutText.text

		logger.logDebug("Received Clipboard Text from Server")

		guard settings.isClipboardRedirectionEnabled else { return }

		// T1 Change D: do NOT write UIPasteboard.general.string inline — that XPC to pasteboardd can
		// block the frame loop for tens–hundreds of ms and bypasses the app's echo-dedup. The app
		// delegate is the sole pasteboard writer (async on main, with dedup).
		notifyDelegateAboutServerCutText(text)
	}

	func handleBellMessage() async throws {
		logger.logDebug("Receiving Bell Message from Server")

		_ = try await VNCProtocol.Bell.receive(connection: connection,
											   logger: logger)

		logger.logDebug("Received Bell Message from Server")

		// T1 Change D: AudioServicesPlaySystemSound is a synchronous call; run it off the frame loop so
		// a bell never hitches frame delivery. VNCSystemSound is an empty struct (trivially Sendable).
		let sound = systemSound
		DispatchQueue.global(qos: .userInitiated).async { sound.play() }
	}

	func handleEndOfContinuousUpdatesMessage() async throws {
		let first = !state.areContinuousUpdatesSupported

		state.areContinuousUpdatesSupported = true

		stateLock.lock()
		let wasOptimistic = state.optimisticCUActive
		state.optimisticCUActive = false
		state.areContinuousUpdatesEnabled = false
		stateLock.unlock()

		if wasOptimistic {
			// T1 Change A: genuine support just confirmed the optimistic probe. Stop the watchdog and
			// adopt real CU governance so we re-enable below instead of falling back to polling while
			// the server streams. (A deliberate user disable clears optimisticCUActive first, so the
			// disable-confirming EndOfContinuousUpdates there does not spuriously re-enable.)
			cancelContinuousUpdatesWatchdog()
			state.wantsContinuousUpdates = true
		}

		if first {
			logger.logDebug("Continuous Updates supported (server sent EndOfContinuousUpdates)")
		} else {
			logger.logDebug("Disabling Continuous Updates")
		}

		// Honour the requested Continuous Updates setting once the server advertises support.
		// sendEnableContinuousUpdates() no-ops if already enabled or not requested.
		if state.wantsContinuousUpdates {
			try await sendEnableContinuousUpdates()
		}

		try await sendFramebufferUpdateRequest()
	}
}
