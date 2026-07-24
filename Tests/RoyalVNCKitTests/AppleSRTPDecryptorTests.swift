import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `AppleSRTPDecryptor` — per-packet SRTP receive (HP Phase 4, HP-PHASE4-SPECS §5.4 / crib §3c–§3g).
///
/// The byte-exact packets below were produced by an INDEPENDENT clean-room RFC-3711 SRTP encrypt
/// (Python `cryptography`: AES-256-CTR + HMAC-SHA1-80, same KDF as `AppleSRTPKeyScheduleTests` whose
/// AES-256 primitive is FIPS-197 cross-checked) — NOT the AGPL reference. This pins the decryptor's
/// KDF + IV construction + cipher + auth end-to-end against a non-Swift oracle.
///
/// Master blob = master key (00..1f) ‖ master salt (40..4d). All packets encrypted under it.
final class AppleSRTPDecryptorTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }

    private var blob: Data {
        hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") // MK 00..1f
            + hex("404142434445464748494a4b4c4d")                                // MS 40..4d
    }

    // Independent clean-room SRTP vectors (PKT / expected header fields / expected payload).
    // A: ssrc 0x11223344, seq 0x1234, roc 0, PT 100, payload 00..0f
    private let aPKT = "80641234aabbccdd11223344b5ff684e3b161b7b897a57bdebc8aa67e35721c8333d58ae28e4"
    private let aPAY = "000102030405060708090a0b0c0d0e0f"
    // B_hi: same ssrc, higher seq 0x1240, roc 0, payload aa*8
    private let bPKT = "80641240aabbccde1122334446d787ea7ad6e7254d960e84f373155561f7"
    private let bPAY = "aaaaaaaaaaaaaaaa"
    // C_ssrc: ssrc 0x55667788, seq 0x0001, roc 0, PT 123, payload ff*16
    private let cPKT = "807b000101020304556677884788e986cfe9700f522a69f42511ded92788a35786ce36427587"
    private let cPAY = "ffffffffffffffffffffffffffffffff"
    // D_wrap: ssrc 0x99AABBCC, seq 0xFFF0, roc 0
    private let dPKT = "8064fff01000000099aabbccd6f11c842c15c3761f72b8f67486"
    private let dPAY = "11223344"
    // E_wrap: same ssrc, seq 0x0002, roc 1 (wrap → ROC increment)
    private let ePKT = "806400021000010099aabbcc2ff6b41b6210629db3a2c9728b46"
    private let ePAY = "55667788"
    // F_empty: ssrc 0x0A0B0C0D, seq 0x0007, roc 0, PT 101, empty payload
    private let fPKT = "80650007006800000a0b0c0d4d735e22b6fcaa984a0a"

    // MARK: - Byte-exact decrypt (independent oracle)

    func testDecryptByteExact() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        let r = dec.decrypt(packet: hex(aPKT))
        XCTAssertNotNil(r)
        XCTAssertEqual(r?.payload, hex(aPAY), "recovered plaintext matches the independent oracle")
        XCTAssertEqual(r?.header.payloadType, 100)
        XCTAssertEqual(r?.header.ssrc, 0x11223344)
        XCTAssertEqual(r?.header.sequenceNumber, 0x1234)
        XCTAssertEqual(r?.header.timestamp, 0xAABBCCDD)
        // State recorded on success.
        XCTAssertEqual(dec.states[0x11223344], .init(roc: 0, maxSeq: 0x1234))
    }

    func testDecryptEmptyPayload() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        let r = dec.decrypt(packet: hex(fPKT))
        XCTAssertNotNil(r)
        XCTAssertEqual(r?.payload, Data())
        XCTAssertEqual(r?.header.payloadType, 101)
    }

    // MARK: - Multi-SSRC independence

    func testMultiSSRCIndependence() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        XCTAssertEqual(dec.decrypt(packet: hex(aPKT))?.payload, hex(aPAY))
        XCTAssertEqual(dec.decrypt(packet: hex(cPKT))?.payload, hex(cPAY))
        XCTAssertEqual(dec.states[0x11223344], .init(roc: 0, maxSeq: 0x1234))
        XCTAssertEqual(dec.states[0x55667788], .init(roc: 0, maxSeq: 0x0001))
        XCTAssertEqual(dec.states.count, 2)
    }

    // MARK: - State update: highest 48-bit index only

    func testStateUpdatesToHighestIndexOnly() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        XCTAssertNotNil(dec.decrypt(packet: hex(aPKT)))   // seq 0x1234
        XCTAssertNotNil(dec.decrypt(packet: hex(bPKT)))   // seq 0x1240 (higher)
        XCTAssertEqual(dec.states[0x11223344], .init(roc: 0, maxSeq: 0x1240))

        // Re-deliver the lower-seq packet: it still authenticates, but must NOT downgrade state.
        XCTAssertEqual(dec.decrypt(packet: hex(aPKT))?.payload, hex(aPAY))
        XCTAssertEqual(dec.states[0x11223344], .init(roc: 0, maxSeq: 0x1240))
    }

    // MARK: - Wrap-triggered ROC increment (end-to-end)

    func testROCIncrementAcrossWrap() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        // Establish a high max_seq at roc 0.
        XCTAssertEqual(dec.decrypt(packet: hex(dPKT))?.payload, hex(dPAY))
        XCTAssertEqual(dec.states[0x99AABBCC], .init(roc: 0, maxSeq: 0xFFF0))
        // Next packet wrapped to seq 0x0002, encrypted under roc 1 — must decode via the +1 candidate.
        XCTAssertEqual(dec.decrypt(packet: hex(ePKT))?.payload, hex(ePAY))
        XCTAssertEqual(dec.states[0x99AABBCC], .init(roc: 1, maxSeq: 0x0002))
    }

    // MARK: - Auth failures (silent drop, no state change)

    func testTamperedTagRejected() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        var bytes = [UInt8](hex(aPKT))
        bytes[bytes.count - 1] ^= 0x01               // flip a tag byte
        XCTAssertNil(dec.decrypt(packet: Data(bytes)))
        XCTAssertTrue(dec.states.isEmpty, "no state update on auth failure")
    }

    func testTamperedBodyRejected() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        var bytes = [UInt8](hex(aPKT))
        bytes[12] ^= 0x01                            // flip the first ciphertext byte
        XCTAssertNil(dec.decrypt(packet: Data(bytes)))
        XCTAssertTrue(dec.states.isEmpty, "no state update on auth failure")
    }

    // MARK: - Min-gate

    func testMinGateDrop() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        // 21 bytes < 12 + 10.
        XCTAssertNil(dec.decrypt(packet: Data(repeating: 0, count: 21)))
        // Exactly the header (12) with no room for a 10-byte tag beyond it is 12 < 22.
        XCTAssertNil(dec.decrypt(packet: hex("80641234aabbccdd11223344")))
    }

    // MARK: - ROC guess boundaries (crib §3e)

    func testGuessROCFirstPacket() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        XCTAssertEqual(dec.guessROC(seq: 0x1234, state: nil), 0, "first packet per SSRC ⇒ 0")
    }

    func testGuessROCWithinWindow() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        let st = AppleSRTPDecryptor.SsrcState(roc: 5, maxSeq: 0x1234)
        XCTAssertEqual(dec.guessROC(seq: 0x1240, state: st), 5, "small forward delta keeps roc")
    }

    func testGuessROCBackwardBigDeltaDecrements() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        // diff = seq - maxSeq > 0x7FFF ⇒ max(0, roc-1).
        let st = AppleSRTPDecryptor.SsrcState(roc: 5, maxSeq: 0x0000)
        XCTAssertEqual(dec.guessROC(seq: 0x8001, state: st), 4)
        // roc 0 floors at 0.
        let st0 = AppleSRTPDecryptor.SsrcState(roc: 0, maxSeq: 0x0000)
        XCTAssertEqual(dec.guessROC(seq: 0x8001, state: st0), 0)
    }

    func testGuessROCForwardWrapIncrements() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        // diff < -0x7FFF ⇒ roc+1.
        let st = AppleSRTPDecryptor.SsrcState(roc: 5, maxSeq: 0xFFFF)
        XCTAssertEqual(dec.guessROC(seq: 0x0001, state: st), 6)
    }

    // MARK: - Candidate list order + dedup (crib §3e)

    func testCandidateListOrderAndDedup() throws {
        let dec = try AppleSRTPDecryptor(masterBlob: blob)
        // [roc_guess, state.roc, roc_guess+1, max(0,roc_guess-1)]
        XCTAssertEqual(dec.candidateROCs(rocGuess: 3, stateROC: 7), [3, 7, 4, 2])
        // dedup when state.roc == roc_guess.
        XCTAssertEqual(dec.candidateROCs(rocGuess: 5, stateROC: 5), [5, 6, 4])
        // roc_guess 0: max(0,-1)=0 dedups with the leading 0.
        XCTAssertEqual(dec.candidateROCs(rocGuess: 0, stateROC: 0), [0, 1])
    }
}
