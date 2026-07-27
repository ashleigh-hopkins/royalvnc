#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (no I/O, no clock) SSRC→tile-index map for Apple HP's multi-tile video, with SSRC-group-rotation
/// handling. Value-typed and time-injected so it is unit-testable; the owning `MediaReceiver` performs the
/// side effects a rotation implies (rebuild the AU assembler, clear per-tile chain-clean state).
///
/// Tile index = the SSRC's rank in the ascending-sorted set of observed SSRCs (the reference convention).
/// Until all `expectedTileCount` SSRCs have been seen, a lower SSRC observed after a higher one shifts the
/// earlier indices up by one — a self-healing startup transient of at most a frame or two.
///
/// **SSRC-group rotation.** The daemon can retire a group and start a fresh one mid-session — notably right
/// after a `0x1d` virtual display is created, where the reference observes two new groups within ~2 s as the
/// curtain engages. Once the map is full, an unknown SSRC means a NEW GROUP: reset and start over, guarded by
/// a ≥3 s coalescing window (matching the reference) so a burst can't thrash the reset.
///
/// **An unmappable SSRC is DROPPED, never aliased.** Inside the coalescing window the map is full and the new
/// SSRC has no slot. Clamping its index onto the last tile (the previous behaviour) put two different streams
/// in one strip: foreign content flickering in that strip, and its chain-clean/LTR-ACK state keyed to whichever
/// stream wrote last. Dropping is strictly better — the strip holds its last good content for at most the
/// coalescing window, then the next out-of-window unknown SSRC performs a clean reset.
struct AppleTileMap {
    /// What the caller should do with this access unit.
    enum Outcome: Equatable {
        /// Decode it as this tile.
        case index(UInt32)
        /// Decode it as this tile, but FIRST reset per-group decode state (assembler + chain-clean): a new
        /// SSRC group has taken over.
        case indexAfterGroupReset(UInt32)
        /// Drop it: this SSRC has no tile slot.
        case drop
    }

    /// Number of tiles the negotiated canvas has; bounds the map so a rotation can't inflate indices.
    var expectedTileCount: Int

    private(set) var knownSSRCs: [UInt32] = []
    private(set) var unmappedDrops = 0
    private(set) var groupResets = 0
    private var lastGroupResetNs: UInt64 = 0

    /// Coalescing window matching the reference's restart guard.
    static let groupResetCoalescingNs: UInt64 = 3_000_000_000

    init(expectedTileCount: Int = 4) {
        self.expectedTileCount = max(1, expectedTileCount)
    }

    /// Resolve `ssrc` to a tile index. `nowNs` is a monotonic clock reading (injected for determinism).
    mutating func outcome(for ssrc: UInt32, nowNs: UInt64) -> Outcome {
        let expected = max(1, expectedTileCount)
        var didReset = false

        if !knownSSRCs.contains(ssrc) {
            if knownSSRCs.count >= expected {
                let firstEver = lastGroupResetNs == 0
                if firstEver || nowNs &- lastGroupResetNs > Self.groupResetCoalescingNs {
                    lastGroupResetNs = nowNs
                    groupResets += 1
                    knownSSRCs.removeAll(keepingCapacity: true)
                    didReset = true
                } else {
                    unmappedDrops += 1
                    return .drop
                }
            }
            knownSSRCs.append(ssrc)
            knownSSRCs.sort()
        }

        // No clamping: an index past the canvas geometry means the stream cannot be placed, so drop it.
        guard let idx = knownSSRCs.firstIndex(of: ssrc), idx < expected else {
            unmappedDrops += 1
            return .drop
        }
        let tile = UInt32(idx)
        return didReset ? .indexAfterGroupReset(tile) : .index(tile)
    }
}
