import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleTileMap` — the SSRC→tile map for Apple HP multi-tile video. The behaviour that
/// matters most: an SSRC with no tile slot must be DROPPED, never aliased onto an occupied tile (aliasing put
/// two streams in one strip, which showed as foreign content in that strip and mis-keyed its LTR-ACK state).
/// Time is injected, so the 3 s group-reset coalescing window is exercised deterministically.
final class AppleTileMapTests: XCTestCase {

    private let s: UInt64 = 1_000_000_000

    // MARK: - Steady state

    func testAscendingSSRCsMapToTileRank() {
        var map = AppleTileMap(expectedTileCount: 4)
        XCTAssertEqual(map.outcome(for: 100, nowNs: s), .index(0))
        XCTAssertEqual(map.outcome(for: 101, nowNs: s), .index(1))
        XCTAssertEqual(map.outcome(for: 102, nowNs: s), .index(2))
        XCTAssertEqual(map.outcome(for: 103, nowNs: s), .index(3))
        // Stable on repeat.
        XCTAssertEqual(map.outcome(for: 102, nowNs: s), .index(2))
        XCTAssertEqual(map.unmappedDrops, 0)
        XCTAssertEqual(map.groupResets, 0)
    }

    func testLowerSSRCArrivingLateShiftsEarlierIndices() {
        // Documented startup transient: rank is by ascending SSRC, so a lower SSRC seen later shifts others up.
        var map = AppleTileMap(expectedTileCount: 4)
        XCTAssertEqual(map.outcome(for: 200, nowNs: s), .index(0))
        XCTAssertEqual(map.outcome(for: 100, nowNs: s), .index(0))   // 100 sorts first
        XCTAssertEqual(map.outcome(for: 200, nowNs: s), .index(1))   // 200 shifted up
    }

    // MARK: - The aliasing bug (regression)

    func testFifthSSRCInsideCoalescingWindowIsDroppedNotAliasedOntoLastTile() {
        var map = AppleTileMap(expectedTileCount: 4)
        for (i, ssrc) in [UInt32(10), 11, 12, 13].enumerated() {
            XCTAssertEqual(map.outcome(for: ssrc, nowNs: s), .index(UInt32(i)))
        }
        // First unknown SSRC on a full map is a legitimate group rotation (no prior reset) → reset + index 0.
        XCTAssertEqual(map.outcome(for: 20, nowNs: 2 * s), .indexAfterGroupReset(0))
        // A further new SSRC INSIDE the 3 s window has no slot once the fresh group fills up.
        XCTAssertEqual(map.outcome(for: 21, nowNs: 2 * s), .index(1))
        XCTAssertEqual(map.outcome(for: 22, nowNs: 2 * s), .index(2))
        XCTAssertEqual(map.outcome(for: 23, nowNs: 2 * s), .index(3))
        // Map is full again and we are still inside the window → DROP, and specifically NOT .index(3).
        XCTAssertEqual(map.outcome(for: 24, nowNs: 3 * s), .drop)
        XCTAssertNotEqual(map.outcome(for: 24, nowNs: 3 * s), .index(3))
        XCTAssertEqual(map.unmappedDrops, 2)
        // The real tiles keep their mapping while the interloper is dropped.
        XCTAssertEqual(map.outcome(for: 23, nowNs: 3 * s), .index(3))
    }

    func testUnknownSSRCOutsideCoalescingWindowResetsTheGroup() {
        var map = AppleTileMap(expectedTileCount: 4)
        for (i, ssrc) in [UInt32(10), 11, 12, 13].enumerated() {
            XCTAssertEqual(map.outcome(for: ssrc, nowNs: s), .index(UInt32(i)))
        }
        XCTAssertEqual(map.outcome(for: 20, nowNs: 2 * s), .indexAfterGroupReset(0))
        // Fill the replacement group: while the map has room, an unknown SSRC is a legitimate new MEMBER, not
        // a rotation — a late-arriving 2nd/3rd/4th tile is indistinguishable from one, so no reset fires.
        XCTAssertEqual(map.outcome(for: 21, nowNs: 2 * s), .index(1))
        XCTAssertEqual(map.outcome(for: 22, nowNs: 2 * s), .index(2))
        XCTAssertEqual(map.outcome(for: 23, nowNs: 2 * s), .index(3))
        // Now the map is FULL and we are past the window → a genuinely new group is adopted, not dropped.
        let past = 2 * s + AppleTileMap.groupResetCoalescingNs + 1
        XCTAssertEqual(map.outcome(for: 30, nowNs: past), .indexAfterGroupReset(0))
        XCTAssertEqual(map.groupResets, 2)
        // The retired group's SSRCs are gone, so they re-enter as fresh members (not stale indices).
        XCTAssertEqual(map.outcome(for: 31, nowNs: past), .index(1))
    }

    // MARK: - Geometry bound

    func testSingleTileCanvasDropsEverySSRCButTheFirst() {
        var map = AppleTileMap(expectedTileCount: 1)
        XCTAssertEqual(map.outcome(for: 50, nowNs: s), .index(0))
        // Second SSRC on a full 1-tile map: first rotation resets, then further ones inside the window drop.
        XCTAssertEqual(map.outcome(for: 51, nowNs: s), .indexAfterGroupReset(0))
        XCTAssertEqual(map.outcome(for: 52, nowNs: s), .drop)
    }

    func testExpectedTileCountIsClampedToAtLeastOne() {
        var map = AppleTileMap(expectedTileCount: 0)
        XCTAssertEqual(map.expectedTileCount, 1)
        XCTAssertEqual(map.outcome(for: 7, nowNs: s), .index(0))
    }

    func testShrinkingExpectedTileCountDropsNowOutOfRangeTiles() {
        // The canvas can be renegotiated smaller (e.g. a 0x1d virtual display with fewer tiles). An SSRC whose
        // rank now exceeds the geometry must drop, not clamp onto the last tile.
        var map = AppleTileMap(expectedTileCount: 4)
        for (i, ssrc) in [UInt32(10), 11, 12, 13].enumerated() {
            XCTAssertEqual(map.outcome(for: ssrc, nowNs: s), .index(UInt32(i)))
        }
        map.expectedTileCount = 2
        XCTAssertEqual(map.outcome(for: 10, nowNs: s), .index(0))
        XCTAssertEqual(map.outcome(for: 11, nowNs: s), .index(1))
        XCTAssertEqual(map.outcome(for: 12, nowNs: s), .drop)   // rank 2 >= 2
        XCTAssertEqual(map.outcome(for: 13, nowNs: s), .drop)
    }
}
