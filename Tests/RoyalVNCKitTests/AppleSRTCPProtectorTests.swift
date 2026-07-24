import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `AppleSRTCPProtector` — SRTCP protect/unprotect (HP Phase 4, HP-PHASE4-SPECS §5.6-5.7 / crib §3h).
///
/// Byte-exact protect vectors come from an INDEPENDENT clean-room Python SRTCP encrypt (AES-256-CTR
/// + HMAC-SHA1-80, RTCP KDF labels 3/4/5) over the same master blob as the SRTP tests — NOT the
/// AGPL reference. Master blob = master key (00..1f) ‖ master salt (40..4d).
final class AppleSRTCPProtectorTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }

    private var blob: Data {
        hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            + hex("404142434445464748494a4b4c4d")
    }

    private let sender: UInt32 = 0xAABBCCDD
    private let media: UInt32 = 0x11223344

    // Independent Python SRTCP protect vectors over a PLI(sender, media), index 0 then 1.
    private let srtcpPliIdx0 = "81ce0002aabbccdd0724b47880000000b8180c63e3204adb1489"
    private let srtcpPliIdx1 = "81ce0002aabbccdd0beb6a42800000016bb89fa0783ef67b6b09"
    // SRTCP protect over an empty RR (no encrypted body → ciphertext empty), index 0.
    private let srtcpRREmptyIdx0 = "80c90001aabbccdd80000000ba6afe1c01692dbbfcd0"
    // E=0 (unencrypted-flag) SRTCP packet over a PLI, with a valid tag, from the Python oracle:
    // hdr(8) ‖ cleartext body ‖ e_index(bit31 clear) ‖ HMAC-SHA1-80(hdr‖body‖e_index).
    private let srtcpE0Pli = "81ce0002aabbccdd1122334400000000277a7718d4efabe17505"
    private let srtcpE0Plain = "81ce0002aabbccdd11223344"

    // MARK: - Byte-exact protect (independent oracle) + index increment

    func testProtectByteExactAndIndexIncrement() throws {
        let p = try AppleSRTCPProtector(masterBlob: blob)
        XCTAssertEqual(p.txIndex, 0)

        let pli = AppleRTCPBuilders.pli(sender: sender, media: media)
        XCTAssertEqual(try p.protect(pli), hex(srtcpPliIdx0), "protect @ index 0")
        XCTAssertEqual(p.txIndex, 1)
        XCTAssertEqual(try p.protect(pli), hex(srtcpPliIdx1), "protect @ index 1 (incremented)")
        XCTAssertEqual(p.txIndex, 2)
    }

    /// Empty-body RTCP (empty RR): ciphertext is empty, only the E+index trailer + tag are added.
    func testProtectEmptyBody() throws {
        let p = try AppleSRTCPProtector(masterBlob: blob)
        let rr = AppleRTCPBuilders.rrEmpty(sender: sender)
        XCTAssertEqual(try p.protect(rr), hex(srtcpRREmptyIdx0))
    }

    // MARK: - protect → unprotect roundtrip

    func testRoundtripEncryptedBody() throws {
        let enc = try AppleSRTCPProtector(masterBlob: blob)
        let dec = try AppleSRTCPProtector(masterBlob: blob)
        let pli = AppleRTCPBuilders.pli(sender: sender, media: media)
        let protected = try enc.protect(pli)
        XCTAssertEqual(dec.unprotect(protected), pli, "recovers the exact plaintext RTCP")
    }

    func testRoundtripEmptyBody() throws {
        let enc = try AppleSRTCPProtector(masterBlob: blob)
        let dec = try AppleSRTCPProtector(masterBlob: blob)
        let rr = AppleRTCPBuilders.rrEmpty(sender: sender)
        XCTAssertEqual(dec.unprotect(try enc.protect(rr)), rr)
    }

    func testRoundtripAcrossIncrementingIndices() throws {
        let enc = try AppleSRTCPProtector(masterBlob: blob)
        let dec = try AppleSRTCPProtector(masterBlob: blob)
        let pli = AppleRTCPBuilders.pli(sender: sender, media: media)
        // Each protect uses a fresh index; the trailer carries it so unprotect decrypts each.
        for _ in 0..<4 {
            XCTAssertEqual(dec.unprotect(try enc.protect(pli)), pli)
        }
    }

    // MARK: - Auth failures

    func testUnprotectTamperedTagRejected() throws {
        let enc = try AppleSRTCPProtector(masterBlob: blob)
        let dec = try AppleSRTCPProtector(masterBlob: blob)
        var bytes = [UInt8](try enc.protect(AppleRTCPBuilders.pli(sender: sender, media: media)))
        bytes[bytes.count - 1] ^= 0x01
        XCTAssertNil(dec.unprotect(Data(bytes)))
    }

    func testUnprotectTamperedBodyRejected() throws {
        let enc = try AppleSRTCPProtector(masterBlob: blob)
        let dec = try AppleSRTCPProtector(masterBlob: blob)
        var bytes = [UInt8](try enc.protect(AppleRTCPBuilders.pli(sender: sender, media: media)))
        bytes[8] ^= 0x01   // flip a ciphertext byte
        XCTAssertNil(dec.unprotect(Data(bytes)))
    }

    /// E=0 (unencrypted-flag) path: unprotect must return `hdr ‖ body` verbatim, with NO AES-CTR
    /// (the E-flag bit is clear). protect() always sets E=1, so this branch is otherwise uncovered.
    func testUnprotectUnencryptedE0Passthrough() throws {
        let dec = try AppleSRTCPProtector(masterBlob: blob)
        XCTAssertEqual(dec.unprotect(hex(srtcpE0Pli)), hex(srtcpE0Plain))
    }

    func testUnprotectTooShortRejected() throws {
        let dec = try AppleSRTCPProtector(masterBlob: blob)
        XCTAssertNil(dec.unprotect(Data(repeating: 0, count: 21)))   // < 8 + 4 + 10
    }

    func testProtectRejectsShortRTCP() throws {
        let p = try AppleSRTCPProtector(masterBlob: blob)
        XCTAssertThrowsError(try p.protect(Data(repeating: 0, count: 7)))  // < 8-byte clear header
    }

    // MARK: - parseSRArrivals (plaintext RTCP walk)

    func testParseSRArrivals() {
        // Compound: empty SR (PT=200) followed by a PLI (PT=206, skipped).
        let sr = AppleRTCPBuilders.srEmpty(sender: sender, now: 1721800000.5)
        let pli = AppleRTCPBuilders.pli(sender: sender, media: media)
        let arrivals = AppleSRTCPProtector.parseSRArrivals(sr + pli)
        XCTAssertEqual(arrivals.count, 1)
        XCTAssertEqual(arrivals.first?.ssrc, sender)
        // mid32 = ((ntpSec&0xFFFF)<<16) | ((ntpFrac>>16)&0xFFFF); ntpSec=0xEA4B13C0, ntpFrac=0x80000000.
        XCTAssertEqual(arrivals.first?.ntpMid32, 0x13C08000)
    }

    /// A leading RR (PT=201) must be walked past to find the SR behind it.
    func testParseSRArrivalsWalksPastRR() {
        let rr = AppleRTCPBuilders.rrEmpty(sender: sender)
        let sr = AppleRTCPBuilders.srEmpty(sender: 0x01020304, now: 1721800000.5)
        let arrivals = AppleSRTCPProtector.parseSRArrivals(rr + sr)
        XCTAssertEqual(arrivals.map { $0.ssrc }, [0x01020304])
    }

    func testParseSRArrivalsNoSR() {
        let arrivals = AppleSRTCPProtector.parseSRArrivals(AppleRTCPBuilders.pli(sender: sender, media: media))
        XCTAssertTrue(arrivals.isEmpty)
    }
}
