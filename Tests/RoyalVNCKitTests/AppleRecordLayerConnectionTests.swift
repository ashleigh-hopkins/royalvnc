import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleRecordLayerConnection` — the AES-128-CBC record-layer decorator (HP-SPECS
/// §4.2 / §5.4). Covers passthrough identity while inactive, the active seal→wire→open round-trip,
/// IV chaining + sequence accounting across records, byte-level reads spanning record boundaries, and
/// activation guards. No socket: an in-memory `MockNetworkConnection` is the base.
final class AppleRecordLayerConnectionTests: XCTestCase {
    private let key = Hex.data("000102030405060708090a0b0c0d0e0f")
    private let iv = Hex.data("0f0e0d0c0b0a09080706050403020100")

    // MARK: - Passthrough (inactive == identity)

    func testPassthroughReadIsIdentity() async throws {
        let payload = Data("cleartext handshake bytes".utf8)
        let base = MockNetworkConnection(inbound: payload)
        let decorator = AppleRecordLayerConnection(base: base)

        // Not activated -> reads must return the raw base bytes unchanged.
        let read = try await decorator.readBuffered(length: payload.count)

        XCTAssertEqual(read, payload, "inactive decorator read must be byte-identical to the base")
    }

    func testPassthroughWriteIsIdentity() async throws {
        let payload = Data("RFB 003.008\n".utf8)
        let base = MockNetworkConnection()
        let decorator = AppleRecordLayerConnection(base: base)

        // Not activated -> writes must reach the base unchanged (no record framing).
        try await decorator.write(data: payload)

        XCTAssertEqual(base.written, payload, "inactive decorator write must be byte-identical on the base")
    }

    // MARK: - Active round-trip (seal -> wire -> open)

    func testActiveSingleRecordRoundtrip() async throws {
        let body = Data("SetDisplayConfiguration".utf8)

        // Seal through a write-side decorator.
        let baseSend = MockNetworkConnection()
        let sender = AppleRecordLayerConnection(base: baseSend)
        try sender.activateRecordLayer(contentKey: key, iv: iv)
        try await sender.write(data: body)

        // The base must have received a framed CBC record, NOT the plaintext.
        XCTAssertNotEqual(baseSend.written, body, "an active write must be encrypted, not plaintext")
        XCTAssertGreaterThan(baseSend.written.count, 2, "record = u16 len || ciphertext")

        // Open through a read-side decorator over the same wire bytes (both directions share key/iv).
        let baseRecv = MockNetworkConnection(inbound: baseSend.written)
        let receiver = AppleRecordLayerConnection(base: baseRecv)
        try receiver.activateRecordLayer(contentKey: key, iv: iv)
        let recovered = try await receiver.readBuffered(length: body.count)

        XCTAssertEqual(recovered, body, "seal -> wire -> open recovers the body")
    }

    // MARK: - IV chaining + sequence accounting across records

    func testActiveMultiRecordChainRoundtrip() async throws {
        let bodies = [Data("ViewerInfo".utf8),
                      Data("SetEncodings payload".utf8),
                      Data("FramebufferUpdateRequest".utf8)]

        // Send three records; the decorator threads the CBC IV and increments seq internally.
        let baseSend = MockNetworkConnection()
        let sender = AppleRecordLayerConnection(base: baseSend)
        try sender.activateRecordLayer(contentKey: key, iv: iv)
        for body in bodies {
            try await sender.write(data: body)
        }

        // Receive them back in order; each must decrypt under the SAME chained IV / monotonic seq.
        let baseRecv = MockNetworkConnection(inbound: baseSend.written)
        let receiver = AppleRecordLayerConnection(base: baseRecv)
        try receiver.activateRecordLayer(contentKey: key, iv: iv)
        for expected in bodies {
            let recovered = try await receiver.readBuffered(length: expected.count)
            XCTAssertEqual(recovered, expected, "record body recovered under the chained IV + seq")
        }
    }

    // MARK: - Byte-level reads spanning record boundaries

    func testActiveReadSplitsWithinOneRecord() async throws {
        let body = Data("hello".utf8) // 5 bytes in one record

        let baseSend = MockNetworkConnection()
        let sender = AppleRecordLayerConnection(base: baseSend)
        try sender.activateRecordLayer(contentKey: key, iv: iv)
        try await sender.write(data: body)

        let baseRecv = MockNetworkConnection(inbound: baseSend.written)
        let receiver = AppleRecordLayerConnection(base: baseRecv)
        try receiver.activateRecordLayer(contentKey: key, iv: iv)

        // Two sub-reads served from one decrypted record's buffered plaintext.
        let first = try await receiver.readBuffered(length: 3)
        let second = try await receiver.readBuffered(length: 2)

        XCTAssertEqual(first + second, body, "sub-reads reassemble one record's plaintext")
    }

    func testActiveReadSpansTwoRecords() async throws {
        let body1 = Data("abc".utf8)
        let body2 = Data("def".utf8)

        let baseSend = MockNetworkConnection()
        let sender = AppleRecordLayerConnection(base: baseSend)
        try sender.activateRecordLayer(contentKey: key, iv: iv)
        try await sender.write(data: body1)
        try await sender.write(data: body2)

        let baseRecv = MockNetworkConnection(inbound: baseSend.written)
        let receiver = AppleRecordLayerConnection(base: baseRecv)
        try receiver.activateRecordLayer(contentKey: key, iv: iv)

        // A single 5-byte read must pull from record 0 AND record 1 (refilling across the boundary).
        let spanning = try await receiver.readBuffered(length: 5)
        let remainder = try await receiver.readBuffered(length: 1)

        XCTAssertEqual(spanning + remainder, body1 + body2, "one read spans two records via buffer refill")
    }

    // MARK: - Tamper / integrity

    func testActiveReadRejectsTamperedRecord() async throws {
        let body = Data("input".utf8)

        let baseSend = MockNetworkConnection()
        let sender = AppleRecordLayerConnection(base: baseSend)
        try sender.activateRecordLayer(contentKey: key, iv: iv)
        try await sender.write(data: body)

        var tampered = Array(baseSend.written)
        tampered[tampered.count - 1] ^= 0x01 // flip a ciphertext byte

        let baseRecv = MockNetworkConnection(inbound: Data(tampered))
        let receiver = AppleRecordLayerConnection(base: baseRecv)
        try receiver.activateRecordLayer(contentKey: key, iv: iv)

        do {
            _ = try await receiver.readBuffered(length: body.count)
            XCTFail("a tampered record must fail the SHA-1 trailer check")
        } catch {
            // expected
        }
    }

    // MARK: - Activation guards

    func testActivateRejectsBadKeyOrIVLength() {
        let decorator = AppleRecordLayerConnection(base: MockNetworkConnection())

        XCTAssertThrowsError(try decorator.activateRecordLayer(contentKey: Data(repeating: 0, count: 15),
                                                               iv: iv))
        XCTAssertThrowsError(try decorator.activateRecordLayer(contentKey: key,
                                                               iv: Data(repeating: 0, count: 8)))
    }
}
