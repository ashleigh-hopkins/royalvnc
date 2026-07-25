#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Pure (Foundation-only, no socket) Apple HP HEVC RTP depayloader + access-unit assembler (crib §8).
///
/// Apple's HEVC RTP payload deviates from RFC 7798: a **16-bit big-endian DONL is ALWAYS present** — once
/// per Aggregation Packet (no per-NAL DOND) and repeated in EVERY Fragmentation Unit fragment. A stock
/// RFC-7798 depayloader misaligns on this. These helpers reconstruct clean Annex-B-less NAL units (each
/// still carrying its 2-byte HEVC NAL header) ready to be length-prefixed and fed to VideoToolbox.
///
/// Clean-room: reimplemented from the confirmed byte layout (offsets/sizes/endianness), no reference code.
enum AppleHEVCDepacketizer {
    static let nalTypeAggregationPacket = 48   // AP
    static let nalTypeFragmentationUnit = 49   // FU

    /// HEVC NAL unit type from a 2-byte NAL header: `(byte0 >> 1) & 0x3F` (H.265 §7.4.2).
    static func nalType(_ nal: Data) -> Int? {
        guard let first = nal.first else { return nil }
        return Int((first >> 1) & 0x3F)
    }

    static let nalTypeVPS = 32
    static let nalTypeSPS = 33
    static let nalTypePPS = 34
    /// VCL (coded-slice) NAL types are 0…31; these are the only NALs fed to the decoder as samples.
    static func isVCL(_ type: Int) -> Bool { type <= 31 }
    /// IRAP/IDR range (16…21) — a tile-0 rect in this range re-roots the shared decoder context.
    static func isIRAP(_ type: Int) -> Bool { type >= 16 && type <= 21 }

    /// Depacketize one access unit's RTP payloads (already ordered by sequence number) into complete NAL
    /// units. Handles single-NAL (type 0…47), Aggregation Packets (48), and Fragmentation Units (49),
    /// stripping Apple's 16-bit DONL. Each returned `Data` begins with the reconstructed 2-byte NAL header.
    static func depacketizeAccessUnit(_ orderedPayloads: [Data]) -> [Data] {
        var nals: [Data] = []
        var fuAccumulator: Data?   // in-progress reassembled FU NAL (nil unless mid-fragment)

        for payload in orderedPayloads {
            let b = [UInt8](payload)
            guard b.count >= 2, let type = nalType(payload) else { continue }

            switch type {
            case nalTypeAggregationPacket:
                // APhdr[2] | DONL[2] | { size[2 BE] | NAL bytes }…  — no per-NAL DOND.
                var offset = 4
                while offset + 2 <= b.count {
                    let size = (Int(b[offset]) << 8) | Int(b[offset + 1])
                    offset += 2
                    if size == 0 || offset + size > b.count { break }
                    nals.append(Data(b[offset..<offset + size]))
                    offset += size
                }

            case nalTypeFragmentationUnit:
                // FUhdr[2] | FUheader[1] | DONL[2] | fragment… — DONL in every fragment.
                guard b.count >= 6 else { continue }
                let fuHeader = b[2]
                let isStart = (fuHeader & 0x80) != 0
                let isEnd = (fuHeader & 0x40) != 0
                let innerType = fuHeader & 0x3F

                if isStart {
                    // Reconstruct the inner NAL header: keep forbidden bit + high layer-id from byte0,
                    // substitute the real type; byte1 unchanged. Then the fragment payload after DONL.
                    let byte0 = (b[0] & 0x81) | (innerType << 1)
                    var nal = Data([byte0, b[1]])
                    nal.append(contentsOf: b[5...])
                    fuAccumulator = nal
                } else if fuAccumulator != nil {
                    fuAccumulator!.append(contentsOf: b[5...])
                }

                if isEnd, let done = fuAccumulator {
                    nals.append(done)
                    fuAccumulator = nil
                }

            default:
                // Single NAL (type 0…47): NALhdr[2] | DONL[2] | payload.
                guard b.count >= 4 else { continue }
                var nal = Data(b[0..<2])
                nal.append(contentsOf: b[4...])
                nals.append(nal)
            }
        }

        return nals
    }
}

/// Streaming assembler that groups decrypted RTP payloads into access units by `(ssrc, rtp_timestamp)`
/// and emits a completed AU when the marker bit is seen (crib §8/§2). Intra-AU ordering is sequence-number
/// sorted (wraparound-aware); a sequence gap flags the AU incomplete so the caller can drop it (feeding a
/// partial AU wedges VideoToolbox). Bounded: stale groups (a lost marker) are evicted oldest-first so a
/// dropped final packet can't leak memory. Value-typed, no I/O — unit-testable.
struct AppleHEVCAccessUnitAssembler {
    /// A completed access unit for one tile (one SSRC), ready to depacketize.
    struct CompletedAccessUnit: Equatable {
        let ssrc: UInt32
        let timestamp: UInt32
        /// Payloads in decode (sequence) order.
        let orderedPayloads: [Data]
        /// `true` if a sequence gap was detected — the AU is incomplete and should be dropped (params
        /// may still be harvested from whatever NALs are present before dropping).
        let hasGap: Bool
    }

    private struct Key: Hashable { let ssrc: UInt32; let timestamp: UInt32 }
    private struct Packet { let sequence: UInt16; let payload: Data }

    private var groups: [Key: [Packet]] = [:]
    private var order: [Key] = []              // insertion order of live keys, for FIFO eviction
    private var evictedKeys: [Key] = []        // recently FIFO-evicted keys (bounded), for gap flagging
    private var evictedKeySet: Set<Key> = []
    private let maxOpenGroups: Int
    private let maxEvictedTracked: Int

    init(maxOpenGroups: Int = 64) {
        self.maxOpenGroups = max(1, maxOpenGroups)
        self.maxEvictedTracked = max(1, maxOpenGroups) * 2
    }

    /// Add one decrypted RTP payload. Returns a `CompletedAccessUnit` when this packet's marker bit
    /// closes its `(ssrc, timestamp)` group, else `nil`. Duplicate sequence numbers (the SRTP layer has
    /// no replay window, so a wire duplicate reaches here) are collapsed on flush; an AU that completes on
    /// a group whose head was FIFO-evicted (a lost marker filled the table) is flagged `hasGap` so the
    /// caller drops the truncated remnant instead of feeding a partial AU.
    mutating func add(ssrc: UInt32,
                      timestamp: UInt32,
                      sequence: UInt16,
                      marker: Bool,
                      payload: Data) -> CompletedAccessUnit? {
        let key = Key(ssrc: ssrc, timestamp: timestamp)

        if groups[key] == nil {
            order.append(key)
            evictIfNeeded()
        }
        groups[key, default: []].append(Packet(sequence: sequence, payload: payload))

        guard marker else { return nil }

        let packets = groups.removeValue(forKey: key) ?? []
        order.removeAll { $0 == key }
        let wasEvicted = evictedKeySet.remove(key) != nil
        if wasEvicted { evictedKeys.removeAll { $0 == key } }

        let sorted = Self.dedupeBySequence(Self.sortWraparoundAware(packets))
        let hasGap = wasEvicted || Self.detectGap(sorted.map { $0.sequence })
        return CompletedAccessUnit(ssrc: ssrc,
                                   timestamp: timestamp,
                                   orderedPayloads: sorted.map { $0.payload },
                                   hasGap: hasGap)
    }

    private mutating func evictIfNeeded() {
        while order.count > maxOpenGroups {
            let oldest = order.removeFirst()
            groups.removeValue(forKey: oldest)
            recordEvicted(oldest)
        }
    }

    /// Remember a FIFO-evicted key (bounded ring) so a later marker on it can be flagged as gapped.
    private mutating func recordEvicted(_ key: Key) {
        guard evictedKeySet.insert(key).inserted else { return }
        evictedKeys.append(key)
        while evictedKeys.count > maxEvictedTracked {
            evictedKeySet.remove(evictedKeys.removeFirst())
        }
    }

    /// Collapse adjacent packets with equal sequence numbers (duplicates), keeping the first. Input must
    /// already be sequence-sorted.
    private static func dedupeBySequence(_ sorted: [Packet]) -> [Packet] {
        var out: [Packet] = []
        out.reserveCapacity(sorted.count)
        for packet in sorted where out.last?.sequence != packet.sequence {
            out.append(packet)
        }
        return out
    }

    /// Sort packets by sequence number, handling a 16-bit wraparound within the AU. An AU spans only a few
    /// contiguous sequence numbers, so a raw spread > 0x8000 means the window straddles the 65535→0 wrap;
    /// rebase the post-wrap (small) values above the pre-wrap ones so decode order is preserved
    /// (e.g. 65534, 65535, 0, 1). Otherwise plain ascending.
    private static func sortWraparoundAware(_ packets: [Packet]) -> [Packet] {
        guard packets.count > 1 else { return packets }
        let seqs = packets.map { Int($0.sequence) }
        if seqs.max()! - seqs.min()! > 0x8000 {
            func key(_ s: UInt16) -> Int { let v = Int(s); return v < 0x8000 ? v + 0x10000 : v }
            return packets.sorted { key($0.sequence) < key($1.sequence) }
        }
        return packets.sorted { $0.sequence < $1.sequence }
    }

    /// After sorting, detect any adjacent gap `> 1` (mod 2^16). diff 0 = duplicate, diff 1 = contiguous,
    /// diff > 1 = a lost fragment → incomplete AU.
    private static func detectGap(_ sortedSequences: [UInt16]) -> Bool {
        guard sortedSequences.count > 1 else { return false }
        for i in 0..<(sortedSequences.count - 1) {
            let diff = (Int(sortedSequences[i + 1]) &- Int(sortedSequences[i])) & 0xFFFF
            if diff > 1 { return true }
        }
        return false
    }
}
