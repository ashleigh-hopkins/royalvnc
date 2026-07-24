import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `AppleSRTPKeySchedule` — the RFC-3711 AES-256-CM KDF (HP Phase 4, HP-PHASE4-SPECS §5.4 / §7).
///
/// The known-answer vector below was produced by an INDEPENDENT clean-room RFC-3711 KDF (Python
/// `cryptography` AES-256-ECB + a hand-rolled counter — NOT the AGPL reference), whose AES-256-ECB
/// primitive was cross-checked against the FIPS-197 AES-256 vector
/// (`8ea2b7ca516745bfeafc49904b496089`). This byte-exactly pins the Swift KDF against RFC-3711.
final class AppleSRTPKeyScheduleTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }

    // Fixed inputs: master key = 00..1f (32 B), master salt = 40..4d (14 B).
    private var masterKey: Data { hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") }
    private var masterSalt: Data { hex("404142434445464748494a4b4c4d") }
    private var blob: Data { masterKey + masterSalt }

    // Independent RFC-3711 AES-256-CM KDF outputs for the above inputs.
    private let expEnc  = "7e6ff674d9f1ee76dc02b1ec7e22cd659da070a8df697f449c41c848d1a72481"
    private let expAuth = "73d0787d3c78cc1f41995fab24cf17c9052cc2ef"
    private let expSalt = "c0208b4ba76d4aef1e6053765591"

    func testSplit() throws {
        XCTAssertEqual(blob.count, AppleSRTPKeySchedule.blobLen)
        let (k, s) = try AppleSRTPKeySchedule.split(blob: blob)
        XCTAssertEqual(k, masterKey, "master key = blob[0:32]")
        XCTAssertEqual(s, masterSalt, "master salt = blob[32:46]")
    }

    func testSplitRejectsWrongLength() {
        XCTAssertThrowsError(try AppleSRTPKeySchedule.split(blob: Data(repeating: 0, count: 45)))
        XCTAssertThrowsError(try AppleSRTPKeySchedule.split(blob: Data(repeating: 0, count: 47)))
    }

    /// Byte-exact KAT vs the independent RFC-3711 KDF.
    func testKDFKnownAnswer() throws {
        let keys = try AppleSRTPKeySchedule.deriveRTPSessionKeys(blob: blob)
        XCTAssertEqual(keys.encryption, hex(expEnc), "KDF label 0 (enc, 32 B)")
        XCTAssertEqual(keys.authentication, hex(expAuth), "KDF label 1 (auth, 20 B)")
        XCTAssertEqual(keys.salt, hex(expSalt), "KDF label 2 (salt, 14 B)")
    }

    func testSessionKeySizes() throws {
        let keys = try AppleSRTPKeySchedule.deriveRTPSessionKeys(blob: blob)
        XCTAssertEqual(keys.encryption.count, 32)
        XCTAssertEqual(keys.authentication.count, 20)
        XCTAssertEqual(keys.salt.count, 14)
    }

    func testLabelsProduceDistinctKeys() throws {
        let keys = try AppleSRTPKeySchedule.deriveRTPSessionKeys(blob: blob)
        // enc/auth share a 20-byte prefix length only by coincidence of truncation; assert distinct.
        XCTAssertNotEqual(keys.encryption.prefix(20), keys.authentication, "label 0 vs 1 differ")
        XCTAssertNotEqual(Data(keys.encryption.prefix(14)), keys.salt, "label 0 vs 2 differ")
    }

    func testDeterministic() throws {
        let a = try AppleSRTPKeySchedule.deriveRTPSessionKeys(blob: blob)
        let b = try AppleSRTPKeySchedule.deriveRTPSessionKeys(blob: blob)
        XCTAssertEqual(a.encryption, b.encryption)
        XCTAssertEqual(a.authentication, b.authentication)
        XCTAssertEqual(a.salt, b.salt)
    }

    func testSaltIV16() throws {
        let iv = try AppleSRTPKeySchedule.saltIV16(sessionSalt: hex(expSalt))
        XCTAssertEqual(iv.count, 16)
        XCTAssertEqual(iv, hex(expSalt) + Data([0x00, 0x00]), "salt_int = salt(14) ‖ 0x0000")
    }

    func testKDFRawLabelMatchesEnum() throws {
        let (k, s) = try AppleSRTPKeySchedule.split(blob: blob)
        let viaEnum = try AppleSRTPKeySchedule.kdf(masterKey: k, masterSalt: s, label: .rtpEncryption, outLen: 32)
        let viaRaw = try AppleSRTPKeySchedule.kdf(masterKey: k, masterSalt: s, label: 0, outLen: 32)
        XCTAssertEqual(viaEnum, viaRaw)
    }

    // Independent RFC-3711 AES-256-CM KDF outputs for the RTCP labels 3/4/5 (same master blob).
    private let expRtcpEnc  = "b4ccd705fe68c18c06e02a7ce98c4af24784ebe5a2ae870227cccc8306be4d6a"
    private let expRtcpAuth = "605e45efed987830de49b9db3c075ec577bab3d7"
    private let expRtcpSalt = "c2ecbb95c52ed3823e9db3d22616"

    /// Byte-exact KAT for the RTCP session keys (KDF labels 3/4/5) vs the independent Python KDF.
    func testRTCPKDFKnownAnswer() throws {
        let keys = try AppleSRTPKeySchedule.deriveRTCPSessionKeys(blob: blob)
        XCTAssertEqual(keys.encryption, hex(expRtcpEnc), "KDF label 3 (RTCP enc, 32 B)")
        XCTAssertEqual(keys.authentication, hex(expRtcpAuth), "KDF label 4 (RTCP auth, 20 B)")
        XCTAssertEqual(keys.salt, hex(expRtcpSalt), "KDF label 5 (RTCP salt, 14 B)")
    }

    func testRTPvsRTCPKeysDiffer() throws {
        let rtp = try AppleSRTPKeySchedule.deriveRTPSessionKeys(blob: blob)
        let rtcp = try AppleSRTPKeySchedule.deriveRTCPSessionKeys(blob: blob)
        XCTAssertNotEqual(rtp.encryption, rtcp.encryption, "labels 0 vs 3 differ")
        XCTAssertNotEqual(rtp.authentication, rtcp.authentication, "labels 1 vs 4 differ")
        XCTAssertNotEqual(rtp.salt, rtcp.salt, "labels 2 vs 5 differ")
    }

    /// The shared AES-CTR counter block: `IV = salt_int ^ (ssrc<<64) ^ (index<<16)`. With a zero
    /// salt, ssrc=1 lands in byte 7 and index=1 lands in byte 13 (both `<<16`/`<<64` exact).
    func testCounterBlockZeroSalt() {
        let iv = AppleSRTPKeySchedule.counterBlock(saltIV16: [UInt8](repeating: 0, count: 16),
                                                   ssrc: 0x0000_0001, index: 0x0000_0001)
        XCTAssertEqual(Data(iv), hex("00000000000000010000000000010000"))
    }
}
