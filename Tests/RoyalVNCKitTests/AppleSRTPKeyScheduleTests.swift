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
}
