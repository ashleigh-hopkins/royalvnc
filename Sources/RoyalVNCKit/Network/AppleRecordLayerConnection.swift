#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

#if canImport(Network)
import Network
#endif

/// A `NetworkConnection` decorator that transparently applies the Apple AES-128-CBC control record
/// layer (HP-SPECS §4.2 / §5.4, dossier §3.3) below all RFB message send/receive and above the base
/// socket.
///
/// Lifecycle:
/// - **Passthrough** (from creation until `activateRecordLayer(contentKey:iv:)`): every read and write
///   forwards to the base connection unchanged. This is the mode used for the whole cleartext prelude
///   (protocol version, security types, auth, `ClientInit`/`ServerInit`). Byte-for-byte identical to a
///   bare connection.
/// - **Active** (after arming on the `0x44f` rekey): each `write(data:)` is sealed as one CBC record
///   and each read is served from the running plaintext of decrypted records. The per-direction CBC IV
///   is chained across records and never reset; the per-direction `u32` sequence is monotonic and
///   never reset (dossier §3.3).
///
/// Insertion is HP-gated: `VNCConnection` only wraps the base in this decorator when
/// `Settings.enableHighPerformance` is on, so the standard-RFB path never carries the decorator
/// (HP-SPECS §4.2, AC-5). Because only the two `NetworkConnection` read/write *primitives*
/// (`read(minimumLength:maximumLength:)`, `write(data:)`) are overridden, every higher-level reader
/// (`readUInt16`, `readBuffered`, …) funnels through them via the protocol's default implementations —
/// so no shared RFB send/receive code is touched (AC-6b).
///
/// Concurrency / resource safety (NFR-7): all record-layer state is value-typed (`Data`/`UInt32`);
/// there is no `CCCryptorRef` to leak. Arming happens during the handshake, strictly before the
/// receive/send loops start (see `VNCConnection.connectionDidBecomeReady`), establishing a
/// happens-before edge. Thereafter the single receive task touches only the `recv*` fields and the
/// single send task touches only the `send*` fields, so there is no concurrent access to any one field.
/// `cancel()` clears the retained key material.
final class AppleRecordLayerConnection: NetworkConnection {
    private let base: any NetworkConnection

    /// `true` once `activateRecordLayer` has run. Set once (before the loops start); read-only after.
    private var active = false

    /// The 16-byte AES-128 content key (both directions share it, dossier §3.3). Cleared on `cancel`.
    private var contentKey = Data()

    // Send direction (send loop / handshake-send only).
    private var sendIV = Data()
    private var sendSeq: UInt32 = 0

    // Receive direction (receive loop / handshake-receive only).
    private var recvIV = Data()
    private var recvSeq: UInt32 = 0
    /// Decrypted record bodies not yet consumed by byte-level reads. The record boundary and the RFB
    /// byte-read granularity differ, so decrypted plaintext is buffered and served on demand.
    private var recvPlaintextBuffer = Data()

    /// Designated initializer: wrap an already-created base connection (the `VNCConnection` HP path).
    init(base: any NetworkConnection) {
        self.base = base
    }

    /// Satisfies the `NetworkConnection` protocol requirement. Builds its own platform base connection
    /// so the decorator is a self-contained `NetworkConnection`. `VNCConnection` uses `init(base:)`
    /// instead so it can share the base-creation site with the standard path.
    convenience init(settings: NetworkConnectionSettings) {
#if canImport(Network)
        let base = NWConnection(settings: settings)
#else
        let base = SocketNetworkConnection(settings: settings)
#endif

        self.init(base: base)
    }

    // MARK: - Arming

    /// Flip the decorator from passthrough into active CBC mode using the key/iv recovered from the
    /// `0x44f` rekey (HP-SPECS §5.3). Both directions start from the same recovered `iv` and `seq 0`.
    ///
    /// Called from the handshake before the receive/send loops start (happens-before the loop tasks).
    func activateRecordLayer(contentKey: Data, iv: Data) throws {
        guard contentKey.count == 16, iv.count == 16 else {
            throw VNCError.protocol(.invalidData)
        }

        self.contentKey = contentKey
        self.sendIV = iv
        self.recvIV = iv
        self.sendSeq = 0
        self.recvSeq = 0
        self.recvPlaintextBuffer = Data()
        self.active = true
    }

    // MARK: - NetworkConnection surface (forwarded to base)

    var status: NetworkConnectionStatus { base.status }

    var isReady: Bool { base.isReady }

    func setStatusUpdateHandler(_ statusUpdateHandler: NetworkConnectionStatusUpdateHandler?) {
        base.setStatusUpdateHandler(statusUpdateHandler)
    }

    func cancel() {
        // Drop retained key material on teardown (NFR-6 / NFR-7).
        active = false
        contentKey = Data()
        sendIV = Data()
        recvIV = Data()
        recvPlaintextBuffer = Data()

        base.cancel()
    }

    func start(queue: DispatchQueue) {
        base.start(queue: queue)
    }
}

// MARK: - Reading
extension AppleRecordLayerConnection: NetworkConnectionReading {
    /// The lowest-level read primitive. Every higher-level reader funnels here through the protocol's
    /// default implementations, so overriding this alone makes decryption transparent.
    func read(minimumLength: Int,
              maximumLength: Int) async throws -> Data {
        guard active else {
            return try await base.read(minimumLength: minimumLength, maximumLength: maximumLength)
        }

        // Refill from whole records until the plaintext buffer can satisfy the minimum.
        while recvPlaintextBuffer.count < minimumLength {
            try await readOneRecordIntoBuffer()
        }

        let count = min(maximumLength, recvPlaintextBuffer.count)
        let out = Data(recvPlaintextBuffer.prefix(count))
        recvPlaintextBuffer = Data(recvPlaintextBuffer.dropFirst(count))

        return out
    }

    /// Read one CBC record off the base (`u16 ciphertext_len || ciphertext`), decrypt + verify it, and
    /// append the recovered body to the plaintext buffer. Advances the receive IV chain and sequence.
    private func readOneRecordIntoBuffer() async throws {
        let lengthPrefix = try await base.readBuffered(length: 2)
        let ciphertextLen = (Int(lengthPrefix[lengthPrefix.startIndex]) << 8)
            | Int(lengthPrefix[lengthPrefix.startIndex + 1])

        guard ciphertextLen != 0, ciphertextLen % 16 == 0 else {
            throw VNCError.protocol(.invalidData)
        }

        let ciphertext = try await base.readBuffered(length: ciphertextLen)

        var record = Data(lengthPrefix)
        record.append(ciphertext)

        // Note: AppleControlRecordCodec.open will throw .invalidData on SHA-1 trailer mismatch.
        // Per HP-SPECS code-review F4, a distinct log event would be valuable here to separate
        // integrity failures from generic parse errors, but no logger is currently threaded into
        // this type. The connection's base logger should be threaded in a future revision.
        let (body, nextIV) = try AppleControlRecordCodec.open(record: record,
                                                              seq: recvSeq,
                                                              iv: recvIV,
                                                              key: contentKey)

        recvIV = nextIV
        recvSeq &+= 1
        recvPlaintextBuffer.append(body)
    }
}

// MARK: - Writing
extension AppleRecordLayerConnection: NetworkConnectionWriting {
    /// Seal `data` as exactly one CBC record when active; passthrough otherwise. RFB messages are each
    /// written with a single `write(data:)` call in this codebase, so one message maps to one record
    /// (dossier §3.3 / HP-SPECS §4.3 step 7). Advances the send IV chain and sequence.
    func write(data: Data) async throws {
        guard active else {
            return try await base.write(data: data)
        }

        let (record, nextIV) = try AppleControlRecordCodec.seal(body: data,
                                                                seq: sendSeq,
                                                                iv: sendIV,
                                                                key: contentKey)

        sendIV = nextIV
        sendSeq &+= 1

        try await base.write(data: record)
    }
}
