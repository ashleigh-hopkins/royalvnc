#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch
@testable import RoyalVNCKit

/// In-memory `NetworkConnection` for offline tests (no socket). Serves scripted `inbound` bytes to
/// reads and captures all writes in `written`. Used to exercise the record-layer decorator and the
/// HP-gated handshake branches without a live server.
///
/// Single-task use only (tests `await` sequentially); it deliberately has no internal locking.
final class MockNetworkConnection: NetworkConnection {
    private var inbound: Data
    private(set) var written = Data()

    init(inbound: Data = Data()) {
        self.inbound = inbound
    }

    init(settings: NetworkConnectionSettings) {
        self.inbound = Data()
    }

    var status: NetworkConnectionStatus = .ready
    var isReady: Bool { true }

    func setStatusUpdateHandler(_ statusUpdateHandler: NetworkConnectionStatusUpdateHandler?) { }
    func cancel() { }
    func start(queue: DispatchQueue) { }

    enum MockError: Error {
        case inboundExhausted
    }
}

extension MockNetworkConnection: NetworkConnectionReading {
    func read(minimumLength: Int,
              maximumLength: Int) async throws -> Data {
        guard minimumLength > 0 else { return Data() }
        guard inbound.count >= minimumLength else {
            throw MockError.inboundExhausted
        }

        let count = min(maximumLength, inbound.count)
        let out = Data(inbound.prefix(count))
        inbound = Data(inbound.dropFirst(count))

        return out
    }
}

extension MockNetworkConnection: NetworkConnectionWriting {
    func write(data: Data) async throws {
        written.append(data)
    }
}
