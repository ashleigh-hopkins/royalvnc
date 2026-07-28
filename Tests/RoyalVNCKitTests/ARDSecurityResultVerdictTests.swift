import XCTest
@testable import RoyalVNCKit

/// Unit tests for the pure type-33 final-message verdict seam
/// (`VNCProtocol.ARDRSASRPAuthentication.classify(m2Length:securityResult:)`).
///
/// Why this seam exists: `SecurityResult != 0` is ambiguous on the wire. Apple's `screensharingd`
/// returns it both when it rejects the SRP proof (wrong credential) and when it accepts the proof and
/// then refuses the session for its own reasons — a distinction the app needs, because only the second
/// case is worth retrying. No socket and no SRP math here: the classifier is a pure function of the two
/// numbers read off the wire.
final class ARDSecurityResultVerdictTests: XCTestCase {

    private typealias Auth = VNCProtocol.ARDRSASRPAuthentication
    private typealias Verdict = Auth.SecurityResultVerdict

    // MARK: - The two live-captured samples (2026-07-28, macOS 27 screensharingd)

    func testSuccessSampleIsAuthenticated() {
        // Captured success: m2Len=98, SecurityResult=0 (`srp_server_mech_step: 0` → `valid admin`).
        XCTAssertEqual(Auth.classify(m2Length: 98, securityResult: 0), Verdict.authenticated)
    }

    func testWrongCredentialSampleIsProofRejected() {
        // Captured rejection: m2Len=6, SecurityResult=1 (`srp_server_mech_step: -13`).
        XCTAssertEqual(Auth.classify(m2Length: 6, securityResult: 1), Verdict.proofRejected)
    }

    func testRefusedAfterProofSampleIsDistinguishedFromAWrongCredential() {
        // Captured refusal: m2Len=98 (the SAME success-shaped M2) yet SecurityResult=1, because the
        // daemon's post-SRP OpenDirectory check resolved `p level 0` → `not valid admin`.
        // This is the whole point of the seam: same result code, different meaning.
        XCTAssertEqual(Auth.classify(m2Length: 98, securityResult: 1), Verdict.sessionRefusedAfterProof)
    }

    // MARK: - The heuristic boundary

    func testBoundaryAtMinimumProofLength() {
        XCTAssertEqual(Auth.minimumProofM2Length, 64)

        // Exactly one SHA-512 digest is still a plausible proof.
        XCTAssertEqual(Auth.classify(m2Length: 64, securityResult: 1), Verdict.sessionRefusedAfterProof)
        // One byte short of a digest cannot be.
        XCTAssertEqual(Auth.classify(m2Length: 63, securityResult: 1), Verdict.proofRejected)
    }

    func testZeroLengthNonZeroResultIsProofRejected() {
        // `authenticate(...)` rejects m2Len == 0 as invalid framing before classifying, but the pure
        // function must still be total and must never call an absent proof "accepted".
        XCTAssertEqual(Auth.classify(m2Length: 0, securityResult: 1), Verdict.proofRejected)
    }

    // MARK: - Result code dominates length

    func testSecurityResultZeroIsAuthenticatedRegardlessOfProofLength() {
        // A granted session is granted; the length heuristic must not second-guess a zero result.
        XCTAssertEqual(Auth.classify(m2Length: 0, securityResult: 0), Verdict.authenticated)
        XCTAssertEqual(Auth.classify(m2Length: 6, securityResult: 0), Verdict.authenticated)
        XCTAssertEqual(Auth.classify(m2Length: 4096, securityResult: 0), Verdict.authenticated)
    }

    func testAnyNonZeroResultCodeIsAFailure() {
        // The wire carries a u32; only 0 means success. Every other value must fail, never fall through.
        for result in [UInt32(1), 2, 255, 0xFFFF_FFFF] {
            XCTAssertNotEqual(Auth.classify(m2Length: 98, securityResult: result), Verdict.authenticated)
            XCTAssertNotEqual(Auth.classify(m2Length: 6, securityResult: result), Verdict.authenticated)
        }
    }
}
