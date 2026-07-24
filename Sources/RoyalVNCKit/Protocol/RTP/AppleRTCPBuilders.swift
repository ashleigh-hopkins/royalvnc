#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) RTCP feedback packet builders for the Apple HP media path
/// (HP-PHASE4-SPECS §5.6 / crib §4f / §3i). All multibyte fields are **BIG-ENDIAN** (via the
/// module's `Data.append(_:bigEndian:)`); the RTCP `length` field is always "32-bit words minus one".
///
/// These are the receiver-side packets the HP client emits to keep AVConference streaming: an
/// empty RR + legacy FIR (PT=192) are the liveness essentials (D1 Must), with AVPF-FIR/PLI/NACK/
/// empty-SR/APP-LTR-ACK available for the fuller RTCP set (Should). Each builder returns the
/// **plaintext** RTCP packet; `AppleSRTCPProtector.protect` wraps it for the wire.
///
/// Byte-exact against the reference `rtcp.py` (cross-checked 2026-07-24). Time-dependent fields
/// (empty-SR NTP/RTP timestamps) are injected via `now` so the builders stay deterministic (NFR-3).
enum AppleRTCPBuilders {
    /// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
    static let ntpEpochDelta: UInt32 = 2_208_988_800
    /// RTCP payload types.
    static let ptSenderReport: UInt8 = 200
    static let ptReceiverReport: UInt8 = 201
    static let ptApp: UInt8 = 204
    static let ptTransportFeedback: UInt8 = 205   // NACK = FMT 1
    static let ptPayloadFeedback: UInt8 = 206     // PLI = FMT 1, FIR = FMT 4
    static let ptFIRLegacy: UInt8 = 192           // RFC 2032

    // MARK: - Feedback (PT=206 / 205)

    /// Legacy Full-INTRA Request (RFC 2032, PT=192). 8 bytes — the keyframe request the native
    /// viewer sends; screensharingd answers it with a fresh IDR (crib §4f).
    static func firLegacy(target: UInt32) -> Data {
        var d = Data()
        d.append(0x80)
        d.append(ptFIRLegacy)
        d.append(UInt16(1), bigEndian: true)    // length = 2 words - 1
        d.append(target, bigEndian: true)
        return d
    }

    /// AVPF Full-INTRA Request (RFC 5104 §4.3.1.1, PT=206 FMT=4). 20 bytes (crib §4f).
    static func firAVPF(sender: UInt32, target: UInt32, seq: UInt8) -> Data {
        var d = Data()
        d.append(0x80 | 4)                      // V=2, FMT=4
        d.append(ptPayloadFeedback)
        d.append(UInt16(4), bigEndian: true)    // length = 5 words - 1
        d.append(sender, bigEndian: true)
        d.append(UInt32(0), bigEndian: true)    // media source = 0 for FIR
        d.append(target, bigEndian: true)       // FCI: SSRC to refresh
        d.append(seq)                           // FCI: FIR sequence number
        d.append(contentsOf: [0, 0, 0])         // 3 pad bytes
        return d
    }

    /// Picture Loss Indication (RFC 4585 §6.3.1, PT=206 FMT=1). 12 bytes (crib §4f).
    static func pli(sender: UInt32, media: UInt32) -> Data {
        var d = Data()
        d.append(0x80 | 1)                      // V=2, FMT=1
        d.append(ptPayloadFeedback)
        d.append(UInt16(2), bigEndian: true)    // length = 3 words - 1
        d.append(sender, bigEndian: true)
        d.append(media, bigEndian: true)
        return d
    }

    /// Generic NACK (RFC 4585 §6.2.1, PT=205 FMT=1). Coalesces consecutive losses into BLP
    /// entries exactly as the reference (crib §3i): sort unique `seq&0xFFFF`; for each PID fold the
    /// following seqs with `1..16` delta into `blp |= 1<<(delta-1)`. Empty input ⇒ empty `Data`.
    static func nack(sender: UInt32, media: UInt32, lostSeqs: [UInt16]) -> Data {
        let seqs = Array(Set(lostSeqs)).sorted()
        guard !seqs.isEmpty else { return Data() }

        var fcis = Data()
        var i = 0
        while i < seqs.count {
            let pid = seqs[i]
            var blp: UInt16 = 0
            var j = i + 1
            while j < seqs.count {
                let diff = seqs[j] &- pid              // wraparound via UInt16 subtraction
                if diff >= 1 && diff <= 16 {
                    blp |= UInt16(1) << (diff - 1)
                    j += 1
                } else {
                    break
                }
            }
            fcis.append(pid, bigEndian: true)
            fcis.append(blp, bigEndian: true)
            i = j
        }

        let nFcis = fcis.count / 4
        var d = Data()
        d.append(0x80 | 1)                          // V=2, FMT=1
        d.append(ptTransportFeedback)
        d.append(UInt16(2 + nFcis), bigEndian: true)   // length = sender + media + FCIs, words - 1
        d.append(sender, bigEndian: true)
        d.append(media, bigEndian: true)
        d.append(fcis)
        return d
    }

    /// Apple RTCP_APP_LTRP — long-term reference picture acknowledgment (PT=204, subtype 5).
    /// 16 bytes (crib §4f / §3i).
    static func appLtrAck(sender: UInt32, ltrID: UInt32) -> Data {
        var d = Data()
        d.append(0x80)
        d.append(ptApp)
        d.append(UInt16(3), bigEndian: true)    // length = 4 words - 1
        d.append(sender, bigEndian: true)
        d.append(UInt32(5), bigEndian: true)    // APP subtype "5"
        d.append(ltrID, bigEndian: true)
        return d
    }

    // MARK: - Reports (PT=200 / 201)

    /// Empty Sender Report (PT=200) so AVConference accepts us as a live sender (crib §3i).
    /// `now` is Unix seconds; the NTP/RTP timestamps derive from it (deterministic for tests).
    static func srEmpty(sender: UInt32, now: Double) -> Data {
        let nowInt = now.rounded(.down)
        let ntpSec = UInt32(truncatingIfNeeded: Int64(nowInt)) &+ ntpEpochDelta
        let ntpFrac = UInt32(truncatingIfNeeded: Int64((now - nowInt) * 4_294_967_296.0)) // *2^32
        let rtpTs = UInt32(truncatingIfNeeded: Int64(now * 90_000.0))
        var d = Data()
        d.append(0x80)
        d.append(ptSenderReport)
        d.append(UInt16(6), bigEndian: true)    // length = 7 words - 1
        d.append(sender, bigEndian: true)
        d.append(ntpSec, bigEndian: true)
        d.append(ntpFrac, bigEndian: true)
        d.append(rtpTs, bigEndian: true)
        d.append(UInt32(0), bigEndian: true)    // sender's packet count
        d.append(UInt32(0), bigEndian: true)    // sender's octet count
        return d
    }

    /// One RTCP RR report block. Fraction-lost / cumulative-lost / interarrival-jitter are always
    /// zero (receiver-side, matching the reference); `lsr`/`dlsr` default 0 unless SR-arrival data
    /// is available (crib §3i).
    struct ReportBlock: Equatable {
        let ssrc: UInt32
        let roc: UInt32
        let maxSeq: UInt16
        let lsr: UInt32
        let dlsr: UInt32

        init(ssrc: UInt32, roc: UInt32, maxSeq: UInt16, lsr: UInt32 = 0, dlsr: UInt32 = 0) {
            self.ssrc = ssrc
            self.roc = roc
            self.maxSeq = maxSeq
            self.lsr = lsr
            self.dlsr = dlsr
        }
    }

    /// Empty Receiver Report (PT=201) — a 1-word RR. 8 bytes (crib §4f).
    static func rrEmpty(sender: UInt32) -> Data {
        var d = Data()
        d.append(0x80)
        d.append(ptReceiverReport)
        d.append(UInt16(1), bigEndian: true)    // length = 2 words - 1
        d.append(sender, bigEndian: true)
        return d
    }

    /// Populated Receiver Report (PT=201). Up to 31 report blocks; `ext_seq = ((roc&0xFFFF)<<16) |
    /// (maxSeq&0xFFFF)` (crib §3i). No blocks ⇒ falls back to `rrEmpty`.
    static func rr(sender: UInt32, blocks: [ReportBlock]) -> Data {
        guard !blocks.isEmpty else { return rrEmpty(sender: sender) }

        let rc = min(blocks.count, 31)
        var d = Data()
        d.append(0x80 | UInt8(rc))
        d.append(ptReceiverReport)
        d.append(UInt16(1 + rc * 6), bigEndian: true)   // length = ssrc + rc*(6-word block), words - 1
        d.append(sender, bigEndian: true)
        for block in blocks.prefix(rc) {
            let extSeq = ((block.roc & 0xFFFF) << 16) | UInt32(block.maxSeq)
            d.append(block.ssrc, bigEndian: true)
            d.append(UInt32(0), bigEndian: true)        // fraction lost (8) | cumulative lost (24)
            d.append(extSeq, bigEndian: true)
            d.append(UInt32(0), bigEndian: true)        // interarrival jitter
            d.append(block.lsr, bigEndian: true)
            d.append(block.dlsr, bigEndian: true)
        }
        return d
    }

    /// Prefix `payload` with an empty RR — peers reject feedback not starting with SR/RR (crib §4f).
    static func compoundWithRR(sender: UInt32, payload: Data) -> Data {
        rrEmpty(sender: sender) + payload
    }
}
