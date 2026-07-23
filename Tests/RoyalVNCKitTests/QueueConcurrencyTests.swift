import XCTest
@testable import RoyalVNCKit

/// T1 — asserts the struct->final class `Queue` conversion (Change E precondition) is race-free.
/// Run under the Thread Sanitizer (`swift test --sanitize=thread`) to catch the pre-existing data
/// race the lock-free struct had between the input APIs' `enqueue` and the send loop's `dequeue`.
final class QueueConcurrencyTests: XCTestCase {

    /// Lock-guarded shared counters for the test scaffolding, so TSan only flags races in `Queue`
    /// itself (the system under test), not in the harness.
    private final class Shared: @unchecked Sendable {
        private let lock = NSLock()
        private var _dequeued = 0
        private var _stop = false

        func incrementDequeued() { lock.lock(); _dequeued += 1; lock.unlock() }
        var dequeued: Int { lock.lock(); defer { lock.unlock() }; return _dequeued }
        func requestStop() { lock.lock(); _stop = true; lock.unlock() }
        var shouldStop: Bool { lock.lock(); defer { lock.unlock() }; return _stop }
    }

    func testConcurrentEnqueueDequeueLosesNothing() {
        let queue = Queue<Int>()
        let shared = Shared()
        let producerCount = 8
        let perProducer = 2_000
        let expectedTotal = producerCount * perProducer

        // One consumer draining concurrently with the producers, then finishing the tail.
        let consumer = Thread {
            while true {
                if queue.dequeue() != nil {
                    shared.incrementDequeued()
                } else if shared.shouldStop, queue.isEmpty {
                    break
                }
            }
        }
        consumer.start()

        DispatchQueue.concurrentPerform(iterations: producerCount) { _ in
            for i in 0..<perProducer { queue.enqueue(i) }
        }

        shared.requestStop()

        // Wait for the consumer to drain the tail.
        let deadline = Date().addingTimeInterval(10)
        while shared.dequeued < expectedTotal, Date() < deadline {
            usleep(1_000)
        }

        XCTAssertEqual(shared.dequeued, expectedTotal)
        XCTAssertTrue(queue.isEmpty)
    }
}
