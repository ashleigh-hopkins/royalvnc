import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `AppleRTCPBuilders` — BE RTCP feedback builders (HP Phase 4, HP-PHASE4-SPECS §5.6 / crib §4f).
///
/// The expected bytes below come from an INDEPENDENT clean-room reimplementation of the wire facts
/// (Python, NOT the AGPL reference) — the same oracle style as the SRTP tests — plus hand-computed
/// edge cases for the NACK BLP coalescing.
final class AppleRTCPBuildersTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }

    private let sender: UInt32 = 0xAABBCCDD
    private let media: UInt32 = 0x11223344

    func testFIRLegacy() {
        // 8 bytes: 0x80, 192, length=1, target.
        XCTAssertEqual(AppleRTCPBuilders.firLegacy(target: media), hex("80c0000111223344"))
    }

    func testFIRAVPF() {
        XCTAssertEqual(AppleRTCPBuilders.firAVPF(sender: sender, target: media, seq: 0x07),
                       hex("84ce0004aabbccdd000000001122334407000000"))
    }

    func testPLI() {
        XCTAssertEqual(AppleRTCPBuilders.pli(sender: sender, media: media),
                       hex("81ce0002aabbccdd11223344"))
    }

    /// NACK with coalescing: [100,101,103,200] → FCI(100, blp=0b101) + FCI(200, 0). length=4.
    func testNACKCoalescing() {
        XCTAssertEqual(AppleRTCPBuilders.nack(sender: sender, media: media, lostSeqs: [100, 101, 103, 200]),
                       hex("81cd0004aabbccdd112233440064000500c80000"))
    }

    /// Two adjacent losses coalesce into one FCI with BLP bit0 set. Hand-computed.
    func testNACKAdjacentPair() {
        // 0x81,0xcd,length=3, sender, media, PID=10(0x000a), BLP=0x0001.
        XCTAssertEqual(AppleRTCPBuilders.nack(sender: sender, media: media, lostSeqs: [10, 11]),
                       hex("81cd0003aabbccdd11223344000a0001"))
    }

    /// De-duplication + ordering: unsorted duplicates collapse to one PID.
    func testNACKSingleDeduped() {
        // [5,5] → PID=5, BLP=0. length=3.
        XCTAssertEqual(AppleRTCPBuilders.nack(sender: sender, media: media, lostSeqs: [5, 5]),
                       hex("81cd0003aabbccdd1122334400050000"))
    }

    func testNACKEmptyIsEmpty() {
        XCTAssertEqual(AppleRTCPBuilders.nack(sender: sender, media: media, lostSeqs: []), Data())
    }

    /// BLP fold boundary: delta == 16 coalesces into the TOP BLP bit (bit 15 = 0x8000). This pins
    /// the `diff <= 16` upper bound + `1 << (diff-1)` shift against the oracle (a `< 16` / `<= 15`
    /// regression would silently pass the other NACK tests).
    func testNACKDelta16CoalescesTopBit() {
        XCTAssertEqual(AppleRTCPBuilders.nack(sender: sender, media: media, lostSeqs: [0, 16]),
                       hex("81cd0003aabbccdd1122334400008000"))
    }

    /// delta == 17 exceeds the BLP window ⇒ a second FCI (PID=17, BLP=0). length=4.
    func testNACKDelta17StartsNewFCI() {
        XCTAssertEqual(AppleRTCPBuilders.nack(sender: sender, media: media, lostSeqs: [0, 17]),
                       hex("81cd0004aabbccdd112233440000000000110000"))
    }

    /// A full window (deltas 1..16) sets every BLP bit ⇒ 0xFFFF in one FCI.
    func testNACKFullBLPWindow() {
        XCTAssertEqual(AppleRTCPBuilders.nack(sender: sender, media: media, lostSeqs: Array(0...16)),
                       hex("81cd0003aabbccdd112233440000ffff"))
    }

    func testAppLtrAck() {
        XCTAssertEqual(AppleRTCPBuilders.appLtrAck(sender: sender, ltrID: 0x42),
                       hex("80cc0003aabbccdd0000000500000042"))
    }

    /// Empty SR with an injected `now` = 1721800000.5 (deterministic NTP/RTP timestamps).
    func testEmptySR() {
        XCTAssertEqual(AppleRTCPBuilders.srEmpty(sender: sender, now: 1721800000.5),
                       hex("80c80006aabbccddea4b13c080000000e6f763c80000000000000000"))
    }

    func testRREmpty() {
        XCTAssertEqual(AppleRTCPBuilders.rrEmpty(sender: sender), hex("80c90001aabbccdd"))
    }

    /// Populated RR with two report blocks; ext_seq = ((roc&0xFFFF)<<16)|maxSeq. length=13.
    func testRRPopulated() {
        let blocks = [
            AppleRTCPBuilders.ReportBlock(ssrc: 0x11223344, roc: 1, maxSeq: 0x00FE,
                                          lsr: 0xDEADBEEF, dlsr: 0x00001234),
            AppleRTCPBuilders.ReportBlock(ssrc: 0x55667788, roc: 0, maxSeq: 0x0007)
        ]
        XCTAssertEqual(AppleRTCPBuilders.rr(sender: sender, blocks: blocks),
                       hex("82c9000daabbccdd1122334400000000000100fe00000000deadbeef00001234"
                           + "556677880000000000000007000000000000000000000000"))
    }

    func testRRWithNoBlocksFallsBackToEmpty() {
        XCTAssertEqual(AppleRTCPBuilders.rr(sender: sender, blocks: []),
                       AppleRTCPBuilders.rrEmpty(sender: sender))
    }

    /// compoundWithRR prefixes an empty RR before the payload (PLI here).
    func testCompoundWithRR() {
        let payload = AppleRTCPBuilders.pli(sender: sender, media: media)
        XCTAssertEqual(AppleRTCPBuilders.compoundWithRR(sender: sender, payload: payload),
                       hex("80c90001aabbccdd81ce0002aabbccdd11223344"))
    }
}
