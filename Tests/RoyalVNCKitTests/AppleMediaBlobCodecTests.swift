import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `AppleMediaBlobCodec` — the AVCMediaStreamNegotiator MediaBlob protobuf
/// (HP Phase 4, HP-PHASE4-SPECS §5.2 / crib §1c).
///
/// The expected MediaBlob bytes come from an INDEPENDENT clean-room reimplementation of the wire
/// facts (Python, NOT the AGPL reference), with fixed injected inputs:
/// video sessionID=0x11223344, audio sessionID=0x55667788, timestamp=0x0102030405060708,
/// productString="iShareScreen 9.9.9", tilesPerFrame=4.
final class AppleMediaBlobCodecTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }

    private let videoSID: UInt32 = 0x11223344
    private let audioSID: UInt32 = 0x55667788
    private let ts: UInt64 = 0x0102030405060708
    private let product = "iShareScreen 9.9.9"

    private func cfg(codec: AppleMediaBlobCodec.VideoCodec = .both,
                     tiles: Int = 4, ltrp: Bool = true) -> AppleMediaBlobCodec.Config {
        .init(tilesPerFrame: tiles, codec: codec, ltrpEnabled: ltrp, productString: product)
    }

    // Independent oracle vectors.
    private let videoBothLTR = "080110012afc0108c4e688890110011a670864120a0801100118c387032000120a0801100218c3870320001a49464c533b4d533a2d313b4c463a2d313b4c54523b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200e1a7f087b120a0801100118c387032000120a0801100218c387032000120a0801100118c387032000120a0801100218c3870320001a49464c533b4d533a2d313b4c463a2d313b4c54523b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200130043801403f48016001321269536861726553637265656e20392e392e3940004a0a08001080b489131880604a0b080010809bee02188080084a0908ea1f1000188080014a0508101084204a0b080010c0d1e123188080204a0b08001080dac409188080064a05080410e4324a0b080010808ece1c188080104a05080110ab024a0b08001080c2d72f1880804068888e98a8c0e08081017002800100900101"
    private let videoHevcLTR = "080110012a7b08c4e688890110011a670864120a0801100118c387032000120a0801100218c3870320001a49464c533b4d533a2d313b4c463a2d313b4c54523b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200e30043801403f48016001321269536861726553637265656e20392e392e3940004a0a08001080b489131880604a0b080010809bee02188080084a0908ea1f1000188080014a0508101084204a0b080010c0d1e123188080204a0b08001080dac409188080064a05080410e4324a0b080010808ece1c188080104a05080110ab024a0b08001080c2d72f1880804068888e98a8c0e08081017002800100900101"
    private let videoAvcLTR = "080110012a930108c4e688890110011a7f087b120a0801100118c387032000120a0801100218c387032000120a0801100118c387032000120a0801100218c3870320001a49464c533b4d533a2d313b4c463a2d313b4c54523b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200130043801403f48016001321269536861726553637265656e20392e392e3940004a0a08001080b489131880604a0b080010809bee02188080084a0908ea1f1000188080014a0508101084204a0b080010c0d1e123188080204a0b08001080dac409188080064a05080410e4324a0b080010808ece1c188080104a05080110ab024a0b08001080c2d72f1880804068888e98a8c0e08081017002800100900101"
    private let videoBothNoLTRt1 = "080110012af80108c4e688890110001a630864120a0801100118c387032000120a0801100218c3870320001a45464c533b4d533a2d313b4c463a2d313b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200e1a7f087b120a0801100118c387032000120a0801100218c387032000120a0801100118c387032000120a0801100218c3870320001a49464c533b4d533a2d313b4c463a2d313b4c54523b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200130013800403f48016001321269536861726553637265656e20392e392e3940004a0a08001080b489131880604a0b080010809bee02188080084a0908ea1f1000188080014a0508101084204a0b080010c0d1e123188080204a0b08001080dac409188080064a05080410e4324a0b080010808ece1c188080104a05080110ab024a0b08001080c2d72f1880804068888e98a8c0e08081017002800100900101"
    private let audioBlob = "080110011a120888ef99ab051000180020ffbc0128003000321269536861726553637265656e20392e392e3940004a0a08001080b489131880604a0b080010809bee02188080084a0908ea1f1000188080014a0508101084204a0b080010c0d1e123188080204a0b08001080dac409188080064a05080410e4324a0b080010808ece1c188080104a05080110ab024a0b08001080c2d72f1880804068888e98a8c0e08081017002800100900101"

    // MARK: - Byte-exact MediaBlob (independent oracle)

    func testVideoMediaBlobBothLTR() {
        XCTAssertEqual(AppleMediaBlobCodec.buildVideoMediaBlob(sessionID: videoSID, timestamp: ts, config: cfg()),
                       hex(videoBothLTR))
    }

    func testVideoMediaBlobHevcOnly() {
        XCTAssertEqual(AppleMediaBlobCodec.buildVideoMediaBlob(sessionID: videoSID, timestamp: ts, config: cfg(codec: .hevc)),
                       hex(videoHevcLTR))
    }

    func testVideoMediaBlobAvcOnly() {
        XCTAssertEqual(AppleMediaBlobCodec.buildVideoMediaBlob(sessionID: videoSID, timestamp: ts, config: cfg(codec: .avc)),
                       hex(videoAvcLTR))
    }

    /// Codec=both, LTRP off, tilesPerFrame=1 — exercises the no-LTR HEVC feature string + f2/f7=0 + f6=1.
    func testVideoMediaBlobBothNoLTRTiles1() {
        XCTAssertEqual(AppleMediaBlobCodec.buildVideoMediaBlob(sessionID: videoSID, timestamp: ts,
                                                               config: cfg(tiles: 1, ltrp: false)),
                       hex(videoBothNoLTRt1))
    }

    func testAudioMediaBlob() {
        XCTAssertEqual(AppleMediaBlobCodec.buildAudioMediaBlob(sessionID: audioSID, timestamp: ts, config: cfg()),
                       hex(audioBlob))
    }

    // MARK: - Send-SSRC harvest

    func testExtractVideoSSRC() {
        XCTAssertEqual(AppleMediaBlobCodec.extractVideoSSRC(mediaBlob: hex(videoBothLTR)), videoSID)
    }

    func testExtractAudioSSRC() {
        XCTAssertEqual(AppleMediaBlobCodec.extractAudioSSRC(mediaBlob: hex(audioBlob)), audioSID)
    }

    /// The video blob has no field-3 descriptor; the audio blob has no field-5. Wrong-field lookups
    /// return nil rather than a bogus SSRC.
    func testExtractSSRCWrongFieldReturnsNil() {
        XCTAssertNil(AppleMediaBlobCodec.extractAudioSSRC(mediaBlob: hex(videoBothLTR)))
        XCTAssertNil(AppleMediaBlobCodec.extractVideoSSRC(mediaBlob: hex(audioBlob)))
    }

    /// SSRC harvested from a freshly-built blob round-trips to the sessionID we put in.
    func testExtractSSRCRoundtrip() {
        let blob = AppleMediaBlobCodec.buildVideoMediaBlob(sessionID: 0xDEADBEEF, timestamp: ts, config: cfg())
        XCTAssertEqual(AppleMediaBlobCodec.extractVideoSSRC(mediaBlob: blob), 0xDEADBEEF)
    }

    // MARK: - protobuf primitives

    func testVarintEncoding() {
        XCTAssertEqual(AppleMediaBlobCodec.varint(0), [0x00])
        XCTAssertEqual(AppleMediaBlobCodec.varint(127), [0x7F])
        XCTAssertEqual(AppleMediaBlobCodec.varint(128), [0x80, 0x01])
        XCTAssertEqual(AppleMediaBlobCodec.varint(300), [0xAC, 0x02])
        XCTAssertEqual(AppleMediaBlobCodec.varint(24191), [0xFF, 0xBC, 0x01])
    }

    func testReadVarintRoundtrip() {
        for v: UInt64 in [0, 1, 127, 128, 300, 24191, 0x0102030405060708, UInt64(UInt32.max)] {
            let enc = AppleMediaBlobCodec.varint(v)
            let r = AppleMediaBlobCodec.readVarint(enc, 0)
            XCTAssertEqual(r?.value, v)
            XCTAssertEqual(r?.next, enc.count)
        }
    }

    func testReadVarintTruncatedReturnsNil() {
        // Continuation bit set but no following byte.
        XCTAssertNil(AppleMediaBlobCodec.readVarint([0x80], 0))
        XCTAssertNil(AppleMediaBlobCodec.readVarint([], 0))
    }

    /// RemoteEndpointInfo protobuf: f1=0, f2=1, f3=hwModel, f4=avcVersion, f5=osBuild (hand-computed).
    func testRemoteEndpointInfo() {
        let rei = AppleMediaBlobCodec.buildRemoteEndpointInfo(hwModel: "Generic", avcVersion: "1.0.0", osBuild: "0")
        XCTAssertEqual(rei, hex("080010011a0747656e657269632205312e302e302a0130"))
    }

    func testFieldEncoders() {
        // field 16, varint 0 → tag 128 (0x80 0x01) ‖ 0x00.
        XCTAssertEqual(AppleMediaBlobCodec.fieldVarint(16, 0), [0x80, 0x01, 0x00])
        // field 18, varint 1 → tag 144 (0x90 0x01) ‖ 0x01.
        XCTAssertEqual(AppleMediaBlobCodec.fieldVarint(18, 1), [0x90, 0x01, 0x01])
        // field 6, bytes "ab" → tag (6<<3|2=50=0x32) ‖ len 2 ‖ "ab".
        XCTAssertEqual(AppleMediaBlobCodec.fieldBytes(6, [0x61, 0x62]), [0x32, 0x02, 0x61, 0x62])
    }
}
