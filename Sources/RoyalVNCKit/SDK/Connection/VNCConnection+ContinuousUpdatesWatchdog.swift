#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCConnection {
	/// Probe window after the optimistic enable. Tunable against real Tailscale RTT.
	static let optimisticCUProbeWindow: Double = 4.0

	// MARK: - stateLock accessors (the ONLY access path for these fields)

	func continuousUpdatesEnabledLocked() -> Bool {
		stateLock.lock(); defer { stateLock.unlock() }
		return state.areContinuousUpdatesEnabled
	}

	func setContinuousUpdatesEnabledLocked(_ enabled: Bool) {
		stateLock.lock(); defer { stateLock.unlock() }
		state.areContinuousUpdatesEnabled = enabled
	}

	func noteFramebufferUpdateReceived() {
		stateLock.lock(); defer { stateLock.unlock() }
		state.framebufferUpdateCount &+= 1
	}

	/// Atomically: if the optimistic probe is still active AND no framebuffer update has arrived
	/// since the enable, tear it down and return true. Pure decision + mutation core (unit-test seam;
	/// touches only state + stateLock, never the socket).
	func revertOptimisticCUIfIdle() -> Bool {
		stateLock.lock(); defer { stateLock.unlock() }
		guard state.optimisticCUActive, state.framebufferUpdateCount == 0 else { return false }
		state.areContinuousUpdatesEnabled = false
		state.optimisticCUActive = false
		return true
	}

	// MARK: - Watchdog task (one-shot; lock-guarded task reference)

	func armContinuousUpdatesWatchdog() {
		let task = Task(priority: taskPriority) {
			try? await Task.sleep(seconds: VNCConnection.optimisticCUProbeWindow)
			guard !Task.isCancelled, self.revertOptimisticCUIfIdle() else { return }
			self.logger.logInfo("Optimistic Continuous Updates produced no frames in \(VNCConnection.optimisticCUProbeWindow)s; reverting to polling")
			try? await self.sendFramebufferUpdateRequest()
		}
		stateLock.lock()
		// If a disconnect (or any cancel) already tore the watchdog down while this task was being
		// created, do not store it — cancel it now so it never outlives the connection.
		if continuousUpdatesWatchdogTornDown {
			stateLock.unlock()
			task.cancel()
			return
		}
		continuousUpdatesWatchdogTask = task
		stateLock.unlock()
	}

	func cancelContinuousUpdatesWatchdog() {
		stateLock.lock()
		continuousUpdatesWatchdogTornDown = true
		let task = continuousUpdatesWatchdogTask
		continuousUpdatesWatchdogTask = nil
		stateLock.unlock()
		task?.cancel()
	}
}
