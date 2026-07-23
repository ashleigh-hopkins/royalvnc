import XCTest
@testable import RoyalVNCKit

/// T1 Change A — pure state/decision-core tests. These exercise only `state` + `stateLock` (never the
/// non-injectable NetworkConnection socket): a `VNCConnection` built from `Settings` does not touch
/// `connection` until `beginConnecting()`, so construction and these accessors are hermetic.
final class OptimisticContinuousUpdatesTests: XCTestCase {

    private func makeSettings(useOptimistic: Bool) -> VNCConnection.Settings {
        VNCConnection.Settings(isDebugLoggingEnabled: false,
                               hostname: "127.0.0.1",
                               port: 5900,
                               isShared: true,
                               isScalingEnabled: false,
                               useDisplayLink: false,
                               inputMode: .none,
                               isClipboardRedirectionEnabled: false,
                               colorDepth: .depth24Bit,
                               frameEncodings: [],
                               useOptimisticContinuousUpdates: useOptimistic)
    }

    // Test 1: Settings default + wiring into State.
    func testUseOptimisticContinuousUpdatesDefaultsFalse() {
        let defaulted = VNCConnection.Settings(isDebugLoggingEnabled: false,
                                               hostname: "127.0.0.1",
                                               port: 5900,
                                               isShared: true,
                                               isScalingEnabled: false,
                                               useDisplayLink: false,
                                               inputMode: .none,
                                               isClipboardRedirectionEnabled: false,
                                               colorDepth: .depth24Bit,
                                               frameEncodings: [])
        XCTAssertFalse(defaulted.useOptimisticContinuousUpdates)

        let off = VNCConnection(settings: makeSettings(useOptimistic: false))
        XCTAssertFalse(off.state.wantsOptimisticContinuousUpdates)

        let on = VNCConnection(settings: makeSettings(useOptimistic: true))
        XCTAssertTrue(on.state.wantsOptimisticContinuousUpdates)
    }

    // Test 2: lock accessors.
    func testLockAccessors() {
        let connection = VNCConnection(settings: makeSettings(useOptimistic: true))

        XCTAssertFalse(connection.continuousUpdatesEnabledLocked())
        connection.setContinuousUpdatesEnabledLocked(true)
        XCTAssertTrue(connection.continuousUpdatesEnabledLocked())
        connection.setContinuousUpdatesEnabledLocked(false)
        XCTAssertFalse(connection.continuousUpdatesEnabledLocked())

        XCTAssertEqual(connection.state.framebufferUpdateCount, 0)
        connection.noteFramebufferUpdateReceived()
        connection.noteFramebufferUpdateReceived()
        XCTAssertEqual(connection.state.framebufferUpdateCount, 2)
    }

    // Test 3: revertOptimisticCUIfIdle() truth table — the watchdog's entire decision, without the
    // 4 s sleep or a socket.
    func testRevertOptimisticCUIfIdleTruthTable() {
        // (active=true, count=0) => reverts, clears both flags.
        let idle = VNCConnection(settings: makeSettings(useOptimistic: true))
        idle.state.optimisticCUActive = true
        idle.state.areContinuousUpdatesEnabled = true
        idle.state.framebufferUpdateCount = 0
        XCTAssertTrue(idle.revertOptimisticCUIfIdle())
        XCTAssertFalse(idle.state.optimisticCUActive)
        XCTAssertFalse(idle.state.areContinuousUpdatesEnabled)

        // (active=true, count=1) => no revert, no change.
        let live = VNCConnection(settings: makeSettings(useOptimistic: true))
        live.state.optimisticCUActive = true
        live.state.areContinuousUpdatesEnabled = true
        live.state.framebufferUpdateCount = 1
        XCTAssertFalse(live.revertOptimisticCUIfIdle())
        XCTAssertTrue(live.state.optimisticCUActive)
        XCTAssertTrue(live.state.areContinuousUpdatesEnabled)

        // (active=false) => no revert regardless of count.
        let inactive = VNCConnection(settings: makeSettings(useOptimistic: true))
        inactive.state.optimisticCUActive = false
        inactive.state.framebufferUpdateCount = 0
        XCTAssertFalse(inactive.revertOptimisticCUIfIdle())
    }

    // Fix (adversarial review): a watchdog armed AFTER a cancel/disconnect must not be stored — the
    // tear-down latch guarantees it never outlives the connection regardless of arm/cancel ordering.
    func testArmAfterCancelDoesNotStoreWatchdog() {
        let connection = VNCConnection(settings: makeSettings(useOptimistic: true))

        // Normal order: arm then cancel leaves no task.
        connection.armContinuousUpdatesWatchdog()
        XCTAssertNotNil(connection.continuousUpdatesWatchdogTask)
        connection.cancelContinuousUpdatesWatchdog()
        XCTAssertNil(connection.continuousUpdatesWatchdogTask)

        // Racy order: cancel latches tear-down, so a subsequent arm must NOT store a task.
        connection.armContinuousUpdatesWatchdog()
        XCTAssertNil(connection.continuousUpdatesWatchdogTask,
                     "arm() after tear-down must cancel its task, not store it")
    }
}
