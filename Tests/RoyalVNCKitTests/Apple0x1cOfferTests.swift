import XCTest
@testable import RoyalVNCKit

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Unit tests for `Apple0x1cOffer` — the `0x1c` MediaStreamConfiguration offer builder
/// (HP Phase 4, HP-PHASE4-SPECS §5.1 / crib §1a-§1d).
///
/// The offer's compressed MediaBlob need not byte-match Python (D4), so the assembly is validated
/// structurally: header fields (BE), the 6-byte gap, the four 46-byte blobs at their offsets, and
/// by decompressing each embedded plist's MediaBlob and checking it equals the byte-exact protobuf
/// the codec produces (which is itself pinned against an independent Python oracle). This also
/// round-trips the vendored zlib.
final class Apple0x1cOfferTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let n = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<n], radix: 16)!); i = n
        }
        return Data(out)
    }
    private func key(_ start: UInt8) -> Data { Data((0..<46).map { UInt8(start &+ UInt8($0)) }) }

    private let videoSID: UInt32 = 0x11223344
    private let audioSID: UInt32 = 0x55667788
    private let ts: UInt64 = 0x0102030405060708
    // Byte-exact protobufs the codec produces for these inputs (from AppleMediaBlobCodecTests oracle).
    private let videoBothLTR = "080110012afc0108c4e688890110011a670864120a0801100118c387032000120a0801100218c3870320001a49464c533b4d533a2d313b4c463a2d313b4c54523b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200e1a7f087b120a0801100118c387032000120a0801100218c387032000120a0801100118c387032000120a0801100218c3870320001a49464c533b4d533a2d313b4c463a2d313b4c54523b43414241433b504f533a303b454f443a313b4854533a323b52523a333b41523a31362f392c352f383b58523a31362f392c352f383b200130043801403f48016001321269536861726553637265656e20392e392e3940004a0a08001080b489131880604a0b080010809bee02188080084a0908ea1f1000188080014a0508101084204a0b080010c0d1e123188080204a0b08001080dac409188080064a05080410e4324a0b080010808ece1c188080104a05080110ab024a0b08001080c2d72f1880804068888e98a8c0e08081017002800100900101"
    private let audioBlob = "080110011a120888ef99ab051000180020ffbc0128003000321269536861726553637265656e20392e392e3940004a0a08001080b489131880604a0b080010809bee02188080084a0908ea1f1000188080014a0508101084204a0b080010c0d1e123188080204a0b08001080dac409188080064a05080410e4324a0b080010808ece1c188080104a05080110ab024a0b08001080c2d72f1880804068888e98a8c0e08081017002800100900101"

    private func params() -> Apple0x1cOffer.Params {
        .init(outerCallID: UUID(uuidString: "11223344-5566-7788-99AA-BBCCDDEEFF00")!,
              audioKeyV: key(0x00), audioKeyS: key(0x30), videoKeyV: key(0x60), videoKeyS: key(0x90),
              videoSessionID: videoSID, videoTimestamp: ts,
              videoPlistCallID: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
              audioSessionID: audioSID, audioTimestamp: ts,
              audioPlistCallID: UUID(uuidString: "12121212-3434-5656-7878-9A9A9A9A9A9A")!)
    }

    private func config(flags: Apple0x1cOffer.ConfigFlags = .standard) -> Apple0x1cOffer.Config {
        .init(flags: flags,
              blob: .init(tilesPerFrame: 4, codec: .both, ltrpEnabled: true, productString: "iShareScreen 9.9.9"),
              remoteEndpointInfo: AppleMediaBlobCodec.buildRemoteEndpointInfo(hwModel: "Generic", avcVersion: "1.0.0", osBuild: "0"))
    }

    // MARK: - Header + structure

    func testOfferHeaderAndOffsets() throws {
        let buf = [UInt8](try Apple0x1cOffer.build(config: config(), params: params()))

        XCTAssertEqual(buf[0], 0x1C, "message type")
        XCTAssertEqual(buf[1], 0x00, "pad")
        // version @4 BE = 3
        XCTAssertEqual(UInt16(buf[4]) << 8 | UInt16(buf[5]), 3)
        // config_flags @6 BE u32 = 00 00 00 07 (standard) — regression guard against LE.
        XCTAssertEqual(Array(buf[6..<10]), [0x00, 0x00, 0x00, 0x07])

        let ms = Int(buf[2]) << 8 | Int(buf[3])
        let asz = Int(buf[10]) << 8 | Int(buf[11])
        let vsz = Int(buf[12]) << 8 | Int(buf[13])
        XCTAssertEqual(ms, asz + vsz + 0xD8, "MS = AS + VS + 0xD8")
        XCTAssertEqual(buf.count, ms + 4, "buffer length = MS + 4")

        // 6-byte gap @0x0E stays zero.
        XCTAssertEqual(Array(buf[0x0E..<0x14]), [UInt8](repeating: 0, count: 6))
        // Outer CallID raw bytes @0x14.
        XCTAssertEqual(Array(buf[0x14..<0x24]),
                       [0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00])
        // The four master blobs at their fixed offsets.
        XCTAssertEqual(Data(buf[0x24..<0x52]), key(0x00), "akv @0x24")
        XCTAssertEqual(Data(buf[0x52..<0x80]), key(0x30), "aks @0x52")
        let vo = 0x80 + asz
        XCTAssertEqual(Data(buf[vo..<(vo + 0x2E)]), key(0x60), "vkv @vo")
        XCTAssertEqual(Data(buf[(vo + 0x2E)..<(vo + 0x5C)]), key(0x90), "vks @vo+0x2E")
    }

    func testConfigFlagsVariants() throws {
        let alt = [UInt8](try Apple0x1cOffer.build(config: config(flags: .altSession), params: params()))
        XCTAssertEqual(Array(alt[6..<10]), [0x00, 0x00, 0x00, 0x05], "alt_session = 5")
        let legacy = [UInt8](try Apple0x1cOffer.build(config: config(flags: .legacyCursor), params: params()))
        XCTAssertEqual(Array(legacy[6..<10]), [0x00, 0x00, 0x00, 0x03], "legacy cursor = 3")
    }

    // MARK: - Embedded plists decompress to the byte-exact protobuf

    func testEmbeddedMediaBlobsRoundtrip() throws {
        let buf = try Apple0x1cOffer.build(config: config(), params: params())
        let bytes = [UInt8](buf)
        let asz = Int(bytes[10]) << 8 | Int(bytes[11])
        let vsz = Int(bytes[12]) << 8 | Int(bytes[13])
        let vo = 0x80 + asz

        let audioPlist = buf.subdata(in: 0x80..<(0x80 + asz))
        let videoPlist = buf.subdata(in: (vo + 0x5C)..<(vo + 0x5C + vsz))

        for (plist, expected) in [(audioPlist, audioBlob), (videoPlist, videoBothLTR)] {
            let obj = try PropertyListSerialization.propertyList(from: plist, options: [], format: nil)
            let dict = try XCTUnwrap(obj as? [String: Any])
            let compressed = try XCTUnwrap(dict["avcMediaStreamNegotiatorMediaBlob"] as? Data)
            let blob = try ZlibStream().decompressedData(compressedData: compressed)
            XCTAssertEqual(blob, hex(expected), "decompressed MediaBlob matches the byte-exact protobuf")
        }
    }

    // MARK: - Send-SSRC harvest

    func testHarvestSendSSRCs() throws {
        let buf = try Apple0x1cOffer.build(config: config(), params: params())
        let ssrcs = try XCTUnwrap(Apple0x1cOffer.harvestSendSSRCs(offer: buf))
        XCTAssertEqual(ssrcs.video, videoSID)
        XCTAssertEqual(ssrcs.audio, audioSID)
    }

    // MARK: - Validation

    func testBuildRejectsWrongKeyLength() {
        var p = params()
        p.videoKeyS = Data(repeating: 0, count: 45)   // not 46
        XCTAssertThrowsError(try Apple0x1cOffer.build(config: config(), params: p))
    }

    // MARK: - zlib round-trip (vendored zlib, RFC-1950 .finish)

    func testZlibRoundtrip() throws {
        let original = hex(videoBothLTR)
        let compressed = try ZlibDeflateStream().compressedData(data: original, flush: .finish)
        XCTAssertEqual(try ZlibStream().decompressedData(compressedData: compressed), original)
    }
}
