import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleHEVCDepacketizer` (RTP→NAL depay, Apple 16-bit DONL) and
/// `AppleHEVCAccessUnitAssembler` (group-by-(ssrc,ts), marker flush, wraparound seq sort, gap detect).
/// Vectors are hand-built from the confirmed wire layout (crib §8): single-NAL / AP-48 / FU-49 each with
/// a mandatory 16-bit DONL. NAL header byte0 = type<<1 (forbidden=0); type = (byte0>>1)&0x3F.
final class AppleHEVCDepacketizerTests: XCTestCase {

    // MARK: - Single NAL (type 0..47)

    func testSingleNALStripsDONL() {
        // SPS (type 33 → byte0 0x42), DONL 0x0007, payload AA BB.
        let payload = Data([0x42, 0x01, 0x00, 0x07, 0xAA, 0xBB])
        let nals = AppleHEVCDepacketizer.depacketizeAccessUnit([payload])
        XCTAssertEqual(nals, [Data([0x42, 0x01, 0xAA, 0xBB])])
        XCTAssertEqual(AppleHEVCDepacketizer.nalType(nals[0]), 33)
        XCTAssertTrue(AppleHEVCDepacketizer.nalType(nals[0]).map { $0 == AppleHEVCDepacketizer.nalTypeSPS } ?? false)
    }

    func testSingleNALTooShortSkipped() {
        // 3 bytes: header + 1 DONL byte, no room for full DONL+payload → skipped (needs >= 4).
        XCTAssertEqual(AppleHEVCDepacketizer.depacketizeAccessUnit([Data([0x42, 0x01, 0x00])]), [])
    }

    // MARK: - Aggregation Packet (48)

    func testAggregationPacketSplitsSubNALsAndStripsSingleDONL() {
        // APhdr 0x60,0x01; DONL 0x0003; then {size=3, VPS[0x40,0x01,0xCC]} {size=4, PPS[0x44,0x01,0xDD,0xEE]}.
        let payload = Data([0x60, 0x01, 0x00, 0x03,
                            0x00, 0x03, 0x40, 0x01, 0xCC,
                            0x00, 0x04, 0x44, 0x01, 0xDD, 0xEE])
        let nals = AppleHEVCDepacketizer.depacketizeAccessUnit([payload])
        XCTAssertEqual(nals, [Data([0x40, 0x01, 0xCC]), Data([0x44, 0x01, 0xDD, 0xEE])])
        XCTAssertEqual(nals.map { AppleHEVCDepacketizer.nalType($0) }, [32, 34])   // VPS, PPS
    }

    func testAggregationPacketStopsOnOverrunSize() {
        // Second declared size (99) overruns the buffer → stop after the first sub-NAL.
        let payload = Data([0x60, 0x01, 0x00, 0x03,
                            0x00, 0x02, 0x40, 0x01,
                            0x00, 0x63, 0x44])
        XCTAssertEqual(AppleHEVCDepacketizer.depacketizeAccessUnit([payload]), [Data([0x40, 0x01])])
    }

    // MARK: - Fragmentation Unit (49)

    func testFragmentationUnitReassemblesAcrossThreeFragments() {
        // FUhdr 0x62,0x01; DONL 0x0009 in each. inner_type = 1 (TRAIL_R). S / mid / E.
        let start = Data([0x62, 0x01, 0x81, 0x00, 0x09, 0x11, 0x22])   // S=1, type=1
        let mid   = Data([0x62, 0x01, 0x01, 0x00, 0x09, 0x33])
        let end   = Data([0x62, 0x01, 0x41, 0x00, 0x09, 0x44, 0x55])   // E=1
        let nals = AppleHEVCDepacketizer.depacketizeAccessUnit([start, mid, end])
        // Reconstructed NAL header: byte0 = (0x62 & 0x81) | (1<<1) = 0x02; byte1 = 0x01. type = 1.
        XCTAssertEqual(nals, [Data([0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55])])
        XCTAssertEqual(AppleHEVCDepacketizer.nalType(nals[0]), 1)
    }

    func testFragmentationUnitStartEndOnly() {
        let start = Data([0x62, 0x01, 0x81, 0x00, 0x01, 0xAA])
        let end   = Data([0x62, 0x01, 0x41, 0x00, 0x01, 0xBB])
        XCTAssertEqual(AppleHEVCDepacketizer.depacketizeAccessUnit([start, end]), [Data([0x02, 0x01, 0xAA, 0xBB])])
    }

    func testFragmentWithoutStartIsIgnored() {
        // A mid/end fragment with no preceding start → nothing emitted (no accumulator).
        let end = Data([0x62, 0x01, 0x41, 0x00, 0x01, 0xBB])
        XCTAssertEqual(AppleHEVCDepacketizer.depacketizeAccessUnit([end]), [])
    }

    // MARK: - Mixed AU

    func testMixedAccessUnitSingleThenFU() {
        let sps = Data([0x42, 0x01, 0x00, 0x07, 0xAA])                 // single SPS
        let fuS = Data([0x62, 0x01, 0x81, 0x00, 0x08, 0x11])          // FU start (type 1)
        let fuE = Data([0x62, 0x01, 0x41, 0x00, 0x08, 0x22])          // FU end
        let nals = AppleHEVCDepacketizer.depacketizeAccessUnit([sps, fuS, fuE])
        XCTAssertEqual(nals, [Data([0x42, 0x01, 0xAA]), Data([0x02, 0x01, 0x11, 0x22])])
    }

    // MARK: - VCL / IRAP classification

    func testClassification() {
        XCTAssertTrue(AppleHEVCDepacketizer.isVCL(0))
        XCTAssertTrue(AppleHEVCDepacketizer.isVCL(31))
        XCTAssertFalse(AppleHEVCDepacketizer.isVCL(32))       // VPS
        XCTAssertTrue(AppleHEVCDepacketizer.isIRAP(19))       // IDR_W_RADL
        XCTAssertTrue(AppleHEVCDepacketizer.isIRAP(16))
        XCTAssertTrue(AppleHEVCDepacketizer.isIRAP(21))
        XCTAssertFalse(AppleHEVCDepacketizer.isIRAP(22))
        XCTAssertFalse(AppleHEVCDepacketizer.isIRAP(1))
    }

    // MARK: - firstDONL (LTR-ACK id derivation)

    func testFirstDONLFromAggregationPacket() {
        // AP: DONL is the BE16 at offset 2 (APhdr[2] | DONL[2] | …).
        let ap = Data([0x60, 0x01, 0x00, 0x03, 0x00, 0x03, 0x40, 0x01, 0xCC])
        XCTAssertEqual(AppleHEVCDepacketizer.firstDONL([ap], donl: true), 0x0003)
    }

    func testFirstDONLFromSingleNAL() {
        // Single NAL: DONL is the BE16 at offset 2 (NALhdr[2] | DONL[2] | payload).
        let sps = Data([0x42, 0x01, 0x12, 0x34, 0xAA, 0xBB])
        XCTAssertEqual(AppleHEVCDepacketizer.firstDONL([sps], donl: true), 0x1234)
    }

    func testFirstDONLFromFragmentationUnit() {
        // FU: DONL is the BE16 at offset 3 (FUhdr[2] | FUheader[1] | DONL[2] | fragment).
        let fuStart = Data([0x62, 0x01, 0x81, 0xAB, 0xCD, 0x11, 0x22])
        XCTAssertEqual(AppleHEVCDepacketizer.firstDONL([fuStart], donl: true), 0xABCD)
    }

    func testFirstDONLNilWhenDONLAbsent() {
        let ap = Data([0x60, 0x01, 0x00, 0x03, 0x40, 0x01, 0xCC])
        XCTAssertNil(AppleHEVCDepacketizer.firstDONL([ap], donl: false))
    }

    func testFirstDONLNilWhenEmptyOrTooShort() {
        XCTAssertNil(AppleHEVCDepacketizer.firstDONL([], donl: true))
        // FU header present but no room for a 2-byte DONL at offset 3 (needs >= 5 bytes).
        XCTAssertNil(AppleHEVCDepacketizer.firstDONL([Data([0x62, 0x01, 0x81, 0x00])], donl: true))
        // Single NAL: header only, no DONL room (needs >= 4 bytes).
        XCTAssertNil(AppleHEVCDepacketizer.firstDONL([Data([0x42, 0x01, 0x00])], donl: true))
    }

    // MARK: - Assembler

    func testAssemblerFlushesOnMarkerInSeqOrder() {
        var a = AppleHEVCAccessUnitAssembler()
        XCTAssertNil(a.add(ssrc: 7, timestamp: 100, sequence: 6, marker: false, payload: Data([0xB0])))
        XCTAssertNil(a.add(ssrc: 7, timestamp: 100, sequence: 5, marker: false, payload: Data([0xA0])))
        let au = a.add(ssrc: 7, timestamp: 100, sequence: 7, marker: true, payload: Data([0xC0]))
        XCTAssertEqual(au, .init(ssrc: 7, timestamp: 100,
                                 orderedPayloads: [Data([0xA0]), Data([0xB0]), Data([0xC0])], hasGap: false))
    }

    func testAssemblerWraparoundOrder() {
        var a = AppleHEVCAccessUnitAssembler()
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 0, marker: false, payload: Data([0x00]))
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 65535, marker: false, payload: Data([0xFF]))
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 65534, marker: false, payload: Data([0xFE]))
        let au = a.add(ssrc: 1, timestamp: 1, sequence: 1, marker: true, payload: Data([0x01]))
        // Decode order across the wrap: 65534, 65535, 0, 1.
        XCTAssertEqual(au?.orderedPayloads, [Data([0xFE]), Data([0xFF]), Data([0x00]), Data([0x01])])
        XCTAssertEqual(au?.hasGap, false)
    }

    func testAssemblerDetectsGap() {
        var a = AppleHEVCAccessUnitAssembler()
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 10, marker: false, payload: Data([0x0A]))
        let au = a.add(ssrc: 1, timestamp: 1, sequence: 12, marker: true, payload: Data([0x0C]))   // missing 11
        XCTAssertEqual(au?.hasGap, true)
    }

    func testAssemblerSeparatesGroupsBySSRCAndTimestamp() {
        var a = AppleHEVCAccessUnitAssembler()
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 1, marker: false, payload: Data([0x11]))
        _ = a.add(ssrc: 2, timestamp: 1, sequence: 1, marker: false, payload: Data([0x21]))
        // Marker on ssrc 1 flushes ONLY ssrc 1's group.
        let au1 = a.add(ssrc: 1, timestamp: 1, sequence: 2, marker: true, payload: Data([0x12]))
        XCTAssertEqual(au1?.ssrc, 1)
        XCTAssertEqual(au1?.orderedPayloads, [Data([0x11]), Data([0x12])])
        // ssrc 2 still open; its own marker flushes it independently.
        let au2 = a.add(ssrc: 2, timestamp: 1, sequence: 2, marker: true, payload: Data([0x22]))
        XCTAssertEqual(au2?.ssrc, 2)
        XCTAssertEqual(au2?.orderedPayloads, [Data([0x21]), Data([0x22])])
    }

    func testAssemblerEvictsStaleGroupsWhenBounded() {
        var a = AppleHEVCAccessUnitAssembler(maxOpenGroups: 2)
        // Three never-flushed groups; the first must be evicted (no leak). Its later marker then only
        // returns the packets seen after eviction (proving it was dropped).
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 1, marker: false, payload: Data([0x01]))
        _ = a.add(ssrc: 2, timestamp: 2, sequence: 1, marker: false, payload: Data([0x02]))
        _ = a.add(ssrc: 3, timestamp: 3, sequence: 1, marker: false, payload: Data([0x03]))   // evicts ssrc1
        let au = a.add(ssrc: 1, timestamp: 1, sequence: 2, marker: true, payload: Data([0x99]))
        XCTAssertEqual(au?.orderedPayloads, [Data([0x99])])   // the pre-eviction [0x01] is gone
        XCTAssertEqual(au?.hasGap, true)                      // evicted head → flagged incomplete (drop it)
    }

    func testAssemblerCollapsesDuplicateSequence() {
        // The SRTP layer has no replay window, so a byte-identical wire duplicate reaches the assembler.
        // A duplicate must be collapsed (not appended twice, which would corrupt FU reassembly), and the
        // AU must NOT be flagged as gapped by the duplicate alone.
        var a = AppleHEVCAccessUnitAssembler()
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 5, marker: false, payload: Data([0xAA]))
        _ = a.add(ssrc: 1, timestamp: 1, sequence: 5, marker: false, payload: Data([0xAA]))   // duplicate
        let au = a.add(ssrc: 1, timestamp: 1, sequence: 6, marker: true, payload: Data([0xBB]))
        XCTAssertEqual(au?.orderedPayloads, [Data([0xAA]), Data([0xBB])])
        XCTAssertEqual(au?.hasGap, false)
    }
}
