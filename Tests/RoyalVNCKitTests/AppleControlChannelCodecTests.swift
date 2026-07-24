import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleControlChannelCodec.walkFramebufferUpdate` — the in-memory walker for the Apple
/// HP TCP control channel's `0x00` FramebufferUpdate (cursor 1104 / display-layout 0x451 / config blobs).
///
/// Vectors are hand-built from the confirmed wire layout (crib §7b): rect header = f0,f1,f2,f3 (u16 BE ×4)
/// + encoding (s32 BE); cursor body = `u32 cache_id, u32 comp_size [, comp_size bytes]`; length-prefixed
/// bodies = `u16 size + size bytes`. The walker must consume each rect by its real length and, on an
/// unknown-length encoding or truncation, stop and report `stoppedEarly` so the caller can resync.
final class AppleControlChannelCodecTests: XCTestCase {

    // MARK: - Builders

    private func be16(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
    private func be32(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    /// FBU envelope: `00 00 <u16 nRects> <rectBytes...>`.
    private func fbu(nRects: Int, _ rects: [UInt8]) -> Data {
        var b: [UInt8] = [0x00, 0x00]
        b += be16(nRects)
        b += rects
        return Data(b)
    }

    private func rectHeader(f0: Int, f1: Int, f2: Int, f3: Int, encoding: UInt32) -> [UInt8] {
        be16(f0) + be16(f1) + be16(f2) + be16(f3) + be32(encoding)
    }

    private func cursorRect(w: Int, h: Int, cacheID: UInt32, compSize: Int, payloadFill: UInt8 = 0xAB) -> [UInt8] {
        var r = rectHeader(f0: 0, f1: 0, f2: w, f3: h, encoding: 1104)
        r += be32(cacheID)
        r += be32(UInt32(compSize))
        r += [UInt8](repeating: payloadFill, count: compSize)
        return r
    }

    /// `0x451` layout rect with a `prefix_len`-byte payload; when `prefixLen >= 10` the dims sit at
    /// offsets 4/6/8/10 from the `prefix_len` field (== payload offsets 2/4/6/8), matching the wire
    /// (crib §7b).
    private func layoutRect(prefixLen: Int, scaledW: Int, scaledH: Int, backingW: Int, backingH: Int) -> [UInt8] {
        var payload = [UInt8](repeating: 0, count: prefixLen)
        if prefixLen >= 10 {
            let dims = be16(scaledW) + be16(scaledH) + be16(backingW) + be16(backingH)
            for (i, byte) in dims.enumerated() { payload[2 + i] = byte }   // payload+2 == body+4
        }
        var r = rectHeader(f0: 10, f1: 20, f2: 1920, f3: 1080, encoding: 0x451)
        r += be16(prefixLen)
        r += payload
        return r
    }

    private func configRect(encoding: UInt32, size: Int) -> [UInt8] {
        var r = rectHeader(f0: 0, f1: 0, f2: 0, f3: 0, encoding: encoding)
        r += be16(size)
        r += [UInt8](repeating: 0xCD, count: size)
        return r
    }

    // MARK: - Cursor 1104

    func testCursorCacheHitConsumesEightBytes() {
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 1, cursorRect(w: 24, h: 24, cacheID: 1000, compSize: 0)))
        XCTAssertEqual(walk, .init(declaredRects: 1, parsedRects: 1, layout: nil, stoppedEarly: false))
    }

    func testCursorFullPixmapConsumesEightPlusCompSize() {
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 1, cursorRect(w: 16, h: 16, cacheID: 7, compSize: 40)))
        XCTAssertEqual(walk?.parsedRects, 1)
        XCTAssertEqual(walk?.stoppedEarly, false)
    }

    func testTruncatedCursorBodyStopsEarly() {
        // Claims comp_size=100 but only supplies 3 trailing bytes.
        var r = rectHeader(f0: 0, f1: 0, f2: 16, f3: 16, encoding: 1104)
        r += be32(9)          // cache_id
        r += be32(100)        // comp_size
        r += [0x01, 0x02, 0x03]
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 1, r))
        XCTAssertEqual(walk?.parsedRects, 0)
        XCTAssertEqual(walk?.stoppedEarly, true)
    }

    // MARK: - Display layout 0x451

    func testDisplayLayoutParsesDimsWhenPrefixAtLeastTen() {
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(
            fbu(nRects: 1, layoutRect(prefixLen: 12, scaledW: 1920, scaledH: 1080, backingW: 3840, backingH: 2160)))
        XCTAssertEqual(walk?.parsedRects, 1)
        XCTAssertEqual(walk?.stoppedEarly, false)
        XCTAssertEqual(walk?.layout, .init(scaledWidth: 1920, scaledHeight: 1080, backingWidth: 3840, backingHeight: 2160))
    }

    func testDisplayLayoutShortPrefixConsumesButNoDims() {
        // prefix_len = 4 (< 10) → consumed 2+4, no dims parsed.
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 1, layoutRect(prefixLen: 4, scaledW: 0, scaledH: 0, backingW: 0, backingH: 0)))
        XCTAssertEqual(walk?.parsedRects, 1)
        XCTAssertNil(walk?.layout)
        XCTAssertEqual(walk?.stoppedEarly, false)
    }

    // MARK: - Config blobs (u16 size + payload)

    func testConfigBlobConsumesTwoPlusSize() {
        for enc: UInt32 in [1010, 1011, 1107, 1109, 1110] {
            let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 1, configRect(encoding: enc, size: 33)))
            XCTAssertEqual(walk?.parsedRects, 1, "encoding \(enc)")
            XCTAssertEqual(walk?.stoppedEarly, false, "encoding \(enc)")
        }
    }

    // MARK: - Multi-rect

    func testMultipleRectsAllConsumed() {
        let rects = configRect(encoding: 1010, size: 12) + cursorRect(w: 24, h: 24, cacheID: 5, compSize: 0)
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 2, rects))
        XCTAssertEqual(walk, .init(declaredRects: 2, parsedRects: 2, layout: nil, stoppedEarly: false))
    }

    /// REALIGNMENT REGRESSION (guards the live type-7 desync class): a rect FOLLOWING a 0x451 must land
    /// aligned. Only passes if the layout advanced by exactly `2 + prefix_len`; the historical
    /// ExtendedDesktopSize under-consume (=4) would mis-read the follower's header → stop at 1 rect.
    func testLayoutFollowedByKnownRectStaysAligned() {
        let rects = layoutRect(prefixLen: 12, scaledW: 1920, scaledH: 1080, backingW: 1920, backingH: 1080)
            + cursorRect(w: 24, h: 24, cacheID: 3, compSize: 0)
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 2, rects))
        XCTAssertEqual(walk, .init(declaredRects: 2, parsedRects: 2,
                                   layout: .init(scaledWidth: 1920, scaledHeight: 1080, backingWidth: 1920, backingHeight: 1080),
                                   stoppedEarly: false))
    }

    /// REALIGNMENT REGRESSION: a rect FOLLOWING a nonzero-comp_size cursor must land aligned. Only passes
    /// if the cursor advanced by exactly `8 + comp_size`; any `8 + comp_size ± N` regression mis-reads the
    /// follower's header out of the 0xAB pixmap fill → unknown encoding → stop at 1 rect.
    func testCursorNonzeroCompSizeFollowedByKnownRectStaysAligned() {
        let rects = cursorRect(w: 16, h: 16, cacheID: 7, compSize: 40)
            + configRect(encoding: 1010, size: 12)
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 2, rects))
        XCTAssertEqual(walk, .init(declaredRects: 2, parsedRects: 2, layout: nil, stoppedEarly: false))
    }

    func testLayoutThenUnknownKeepsLayoutAndStopsEarly() {
        // 0x451 (with dims) then 1100 (unknown length) → parse the layout, then stop; tail discarded.
        let rects = layoutRect(prefixLen: 12, scaledW: 1440, scaledH: 900, backingW: 2880, backingH: 1800)
            + rectHeader(f0: 0, f1: 0, f2: 0, f3: 0, encoding: 1100) + [0xDE, 0xAD]
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 2, rects))
        XCTAssertEqual(walk?.parsedRects, 1)
        XCTAssertEqual(walk?.stoppedEarly, true)
        XCTAssertEqual(walk?.layout, .init(scaledWidth: 1440, scaledHeight: 900, backingWidth: 2880, backingHeight: 1800))
    }

    // MARK: - Unknown / truncation / guards

    func testUnknownEncodingStopsImmediately() {
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(
            fbu(nRects: 1, rectHeader(f0: 0, f1: 0, f2: 0, f3: 0, encoding: 1101) + [0x00, 0x01, 0x02]))
        XCTAssertEqual(walk?.parsedRects, 0)
        XCTAssertEqual(walk?.stoppedEarly, true)
    }

    func testTruncatedRectHeaderStopsEarly() {
        // Declares 2 rects but only supplies one full rect + a partial header.
        let rects = configRect(encoding: 1010, size: 4) + [0x00, 0x00, 0x00]   // 3 dangling bytes < 12
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 2, rects))
        XCTAssertEqual(walk?.parsedRects, 1)
        XCTAssertEqual(walk?.stoppedEarly, true)
    }

    func testZeroRectsIsCleanEmptyWalk() {
        let walk = AppleControlChannelCodec.walkFramebufferUpdate(fbu(nRects: 0, []))
        XCTAssertEqual(walk, .init(declaredRects: 0, parsedRects: 0, layout: nil, stoppedEarly: false))
    }

    func testNonFramebufferUpdateReturnsNil() {
        XCTAssertNil(AppleControlChannelCodec.walkFramebufferUpdate(Data([0x14, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02])))
    }

    func testTooShortReturnsNil() {
        XCTAssertNil(AppleControlChannelCodec.walkFramebufferUpdate(Data([0x00, 0x00])))
    }

    // MARK: - 0x1f reassembly (AppleClipboardCodec.completeClipboardSend)

    /// A minimal, self-consistent `0x1f`: 16-B header (compressed=6) + 6 payload bytes. We only test the
    /// reassembly boundary here (decode is covered by AppleClipboardCodecTests' golden vector).
    private func makeSend0x1f(compressedPayload: [UInt8], uncompressed: UInt32 = 99) -> [UInt8] {
        var h: [UInt8] = [0x1f, 0x00, 0x01, 0x00]     // type, pad, promise=1, pad
        h += be32(0)                                   // reserved
        h += be32(uncompressed)                        // uncompressed size
        h += be32(UInt32(compressedPayload.count))     // compressed size
        h += compressedPayload
        return h
    }

    func testReassemblyCompleteInOneRecord() throws {
        let msg = makeSend0x1f(compressedPayload: [1, 2, 3, 4, 5, 6])
        let complete = try AppleClipboardCodec.completeClipboardSend(Data(msg))
        XCTAssertEqual(complete.map { [UInt8]($0) }, msg)
    }

    func testReassemblyWaitsForContinuationRecords() throws {
        let full = makeSend0x1f(compressedPayload: [1, 2, 3, 4, 5, 6])   // 22 bytes total
        // First record: header + 2 of 6 payload bytes → incomplete.
        var acc = Data(full.prefix(18))
        XCTAssertNil(try AppleClipboardCodec.completeClipboardSend(acc))
        // Continuation record delivers the remaining 4 bytes → now complete.
        acc.append(Data(full.suffix(4)))
        let complete = try AppleClipboardCodec.completeClipboardSend(acc)
        XCTAssertEqual(complete.map { [UInt8]($0) }, full)
    }

    func testReassemblyHeaderNotYetPresentReturnsNil() throws {
        // Fewer than 16 header bytes → cannot know the total yet.
        XCTAssertNil(try AppleClipboardCodec.completeClipboardSend(Data([0x1f, 0x00, 0x01, 0x00, 0x00])))
    }

    func testReassemblyExcessTrailingIsTruncatedToDeclaredTotal() throws {
        // If a record carried the 0x1f plus stray trailing bytes, only 16+compressed is returned.
        var msg = makeSend0x1f(compressedPayload: [9, 9, 9])
        let declaredTotal = msg.count
        msg += [0xFF, 0xFF, 0xFF]   // stray tail that must NOT be included
        let complete = try AppleClipboardCodec.completeClipboardSend(Data(msg))
        XCTAssertEqual(complete?.count, declaredTotal)
    }

    func testReassemblyMalformedHeaderThrows() {
        // 16 bytes but first byte isn't 0x1f → header parse fails → throws.
        let bogus = Data([UInt8](repeating: 0x00, count: 16))
        XCTAssertThrowsError(try AppleClipboardCodec.completeClipboardSend(bogus))
    }

    /// Pins the contract the control loop relies on: a `0x1f` whose header `uncompressedSize` disagrees
    /// with the actual inflate length makes `decodeInboundText` THROW. The HP control loop wraps this in
    /// do/catch so such a payload is logged+skipped instead of tearing down the unified session (the
    /// review-confirmed high-severity fix). Here we assert the throw itself.
    func testDecodeInboundTextThrowsOnSizeMismatch() throws {
        var msg = [UInt8](try AppleClipboardCodec.buildClipboardSend(text: "hello world"))
        // Corrupt the uncompressed-size field (bytes [8..12], BE) to a value the inflate can't match.
        msg[8] = 0xFF; msg[9] = 0xFF; msg[10] = 0xFF; msg[11] = 0xF0
        XCTAssertThrowsError(try AppleClipboardCodec.decodeInboundText(Data(msg)))
    }
}
