#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// A lock-guarded FIFO. Converted struct -> final class for T1 (Change E precondition): `enqueue` is
// already called from arbitrary threads (input APIs, updateQuality, setContinuousUpdatesEnabled, and
// E's main-thread refreshFullFramebuffer) while `dequeue` runs on the send loop, which was a data
// race on the lock-free struct. Reference semantics + an internal NSLock make every access atomic.
final class Queue<T> {
	private var list = [T]()
	private let lock = NSLock()

	func enqueue(_ element: T) {
		lock.lock(); defer { lock.unlock() }
		list.append(element)
	}

	func dequeue() -> T? {
		lock.lock(); defer { lock.unlock() }
		guard !list.isEmpty else { return nil }

		return list.removeFirst()
	}

	func clear() {
		lock.lock(); defer { lock.unlock() }
		list.removeAll()
	}

	func peek() -> T? {
		lock.lock(); defer { lock.unlock() }
		return list.first
	}

	var isEmpty: Bool {
		lock.lock(); defer { lock.unlock() }
		return list.isEmpty
	}
}
