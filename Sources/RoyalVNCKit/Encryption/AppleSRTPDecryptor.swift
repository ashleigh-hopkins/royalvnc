#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

/// Pure (Foundation + CryptoSwift, no socket) per-packet SRTP receive path for the Apple HP media
/// path (HP-PHASE4-SPECS §5.4 / crib §3c–§3g). AES-256-CTR cipher + HMAC-SHA1-80 auth.
///
/// The viewer decrypts video with the `vks` (server→viewer) 46-byte master blob. Session keys are
/// derived **once** (`kdr = 0`, no rekey) via `AppleSRTPKeySchedule.deriveRTPSessionKeys`.
///
/// Per packet (crib §3e), **AUTH THEN DECRYPT** across an ordered/deduped ROC candidate list:
/// `body_len = len - 10`; HMAC-SHA1 over `pkt[:body_len] ‖ roc.bigEndian(4)`, compare the first
/// 10 bytes against the trailing tag in constant time; on match, AES-256-CTR-decrypt
/// `pkt[hdrLen:body_len]` with `IV = salt_int XOR (ssrc<<64) XOR (index<<16)`,
/// `index = (roc<<16) | seq`. Returns `(header, payload)` or `nil` (silent drop — no replay window).
/// Per-SSRC ROC/max-seq state is updated on SUCCESS only, keeping the highest 48-bit index.
///
/// Security (NFR-6): never log the session keys, `salt_int`, or per-packet IVs. Instantiated only
/// on the HP path (no gating needed here).
final class AppleSRTPDecryptor {
    /// Truncated HMAC-SHA1-80 tag length (`_AUTH_TAG_LEN`).
    static let authTagLen = 10
    /// Minimum accepted packet length: fixed RTP header (12) + auth tag (10).
    static let minPacketLength = AppleRTPHeader.fixedHeaderLength + authTagLen

    /// Per-SSRC rollover-counter state (crib §3e). Apple uses independent seq spaces per SSRC.
    struct SsrcState: Equatable {
        var roc: UInt32
        var maxSeq: UInt16
    }

    private let sessionKeys: AppleSRTPKeySchedule.SessionKeys
    private let saltIV: [UInt8]   // 16-byte salt_int base (salt(14) ‖ 0x0000)

    /// Per-SSRC state, exposed read-only for assertion. Absent key ⇒ SSRC not yet seen.
    private(set) var states: [UInt32: SsrcState] = [:]

    /// Build a decryptor from a 46-byte SRTP master blob (the `vks` blob for video).
    init(masterBlob: Data) throws {
        self.sessionKeys = try AppleSRTPKeySchedule.deriveRTPSessionKeys(blob: masterBlob)
        self.saltIV = [UInt8](try AppleSRTPKeySchedule.saltIV16(sessionSalt: sessionKeys.salt))
    }

    /// Authenticate + decrypt one SRTP datagram. Returns the parsed RTP header and the decrypted
    /// payload, or `nil` on any failure (too short, malformed, or no candidate ROC authenticates).
    func decrypt(packet: Data) -> (header: AppleRTPHeader, payload: Data)? {
        // Min gate (crib §3e): len >= 12 + 10.
        guard packet.count >= Self.minPacketLength else { return nil }
        guard let header = AppleRTPHeader.parse(packet) else { return nil }

        let bytes = [UInt8](packet)
        let bodyLen = bytes.count - Self.authTagLen
        // The header (incl. CSRC/extension) must fit within the authenticated body.
        guard header.headerLength <= bodyLen else { return nil }

        let ssrc = header.ssrc
        let seq = header.sequenceNumber
        let state = states[ssrc]
        let rocGuess = guessROC(seq: seq, state: state)
        let candidates = candidateROCs(rocGuess: rocGuess, stateROC: state?.roc ?? 0)

        let authInputBody = Array(bytes[0..<bodyLen])
        let receivedTag = Array(bytes[bodyLen..<bytes.count])

        for roc in candidates {
            var authInput = authInputBody
            authInput.append(contentsOf: bigEndian32(roc))

            guard let digest = try? HMAC(key: Array(sessionKeys.authentication), variant: .sha1)
                .authenticate(authInput) else { continue }
            let computedTag = Array(digest.prefix(Self.authTagLen))

            // Constant-time compare (reuse the Phase-3 pattern — no early-exit `==`).
            guard AppleSRPClient.constantTimeEquals(Data(computedTag), Data(receivedTag)) else {
                continue
            }

            guard let payload = decryptBody(bytes: bytes,
                                            hdrLen: header.headerLength,
                                            bodyLen: bodyLen,
                                            ssrc: ssrc,
                                            seq: seq,
                                            roc: roc) else {
                // Authenticated but the cipher errored — drop (do not try weaker candidates).
                return nil
            }

            updateState(ssrc: ssrc, roc: roc, seq: seq)
            return (header, payload)
        }

        return nil
    }

    // MARK: - ROC handling (crib §3e)

    /// ROC guess from the seq delta. First packet per SSRC ⇒ 0.
    func guessROC(seq: UInt16, state: SsrcState?) -> UInt32 {
        guard let state else { return 0 }
        let roc = state.roc
        let diff = Int(seq) - Int(state.maxSeq)
        if diff > 0x7FFF { return roc == 0 ? 0 : roc &- 1 }   // max(0, roc-1)
        if diff < -0x7FFF { return roc &+ 1 }
        return roc
    }

    /// Ordered, deduped candidate list: `[roc_guess, state.roc(or 0), roc_guess+1, max(0, roc_guess-1)]`.
    func candidateROCs(rocGuess: UInt32, stateROC: UInt32) -> [UInt32] {
        let raw = [rocGuess, stateROC, rocGuess &+ 1, rocGuess == 0 ? 0 : rocGuess &- 1]
        var seen = Set<UInt32>()
        var out = [UInt32]()
        out.reserveCapacity(raw.count)
        for r in raw where seen.insert(r).inserted {
            out.append(r)
        }
        return out
    }

    /// Update per-SSRC state on success, keeping the highest 48-bit index `(roc<<16)|seq`.
    private func updateState(ssrc: UInt32, roc: UInt32, seq: UInt16) {
        let newIndex = (UInt64(roc) << 16) | UInt64(seq)
        if let st = states[ssrc] {
            let curIndex = (UInt64(st.roc) << 16) | UInt64(st.maxSeq)
            guard newIndex > curIndex else { return }
        }
        states[ssrc] = SsrcState(roc: roc, maxSeq: seq)
    }

    // MARK: - Cipher

    /// AES-256-CTR decrypt `pkt[hdrLen:bodyLen]` with the constructed 128-bit initial counter.
    private func decryptBody(bytes: [UInt8], hdrLen: Int, bodyLen: Int,
                             ssrc: UInt32, seq: UInt16, roc: UInt32) -> Data? {
        let cipherBody = Array(bytes[hdrLen..<bodyLen])
        // Empty payload (hdrLen == bodyLen): no keystream to apply. CryptoSwift's CTR rejects
        // empty input, so short-circuit rather than construct a cipher over nothing.
        guard !cipherBody.isEmpty else { return Data() }

        // RTP packet index is 48-bit: (roc<<16) | seq.
        let index = (UInt64(roc) << 16) | UInt64(seq)
        let iv = AppleSRTPKeySchedule.counterBlock(saltIV16: saltIV, ssrc: ssrc, index: index)
        do {
            let aes = try AES(key: Array(sessionKeys.encryption),
                              blockMode: CTR(iv: iv),
                              padding: .noPadding)
            return Data(try aes.decrypt(cipherBody))
        } catch {
            return nil
        }
    }

    // MARK: - Byte helpers

    private func bigEndian32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24 & 0xFF), UInt8(value >> 16 & 0xFF),
         UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
    }
}
