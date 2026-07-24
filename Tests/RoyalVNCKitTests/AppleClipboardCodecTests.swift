import XCTest
@testable import RoyalVNCKit

/// Unit tests for `AppleClipboardCodec` — the Apple in-protocol clipboard message quartet
/// (`0x15`/`0x0b`/`0x14`/`0x1f`) that rides the type-33 control-record channel.
///
/// Golden vectors are REAL bytes captured live from macOS 27 / RFB 003.889 (Experiment 1,
/// `plans/t12-clipboard-perf/T12-EXP1-GOLDEN-FINDINGS.md`): a `0x1f` ClipboardSend and its
/// decompressed 3-flavor pasteboard archive for the text below.
final class AppleClipboardCodecTests: XCTestCase {

    /// Real inbound `0x1f` (274 B): 16-B header (uncompressed=511, compressed=258, promise=0)
    /// + a `78 da` `Z_SYNC_FLUSH` zlib stream. Captured from screensharingd on macOS 27.
    private let goldenSend0x1f = Hex.data(
        "1f00000000000000000001ff0000010278da94503d6bc33014bc7efc80d0a169f7767c2e0921144a870c5e4a5" +
        "20cf6d05591655b204b425642fbeffbeca464483c5402e9ddbd43a777006e00dcfbddd66899ec62f54ade086d" +
        "29aaef88c3ea1513e9da44786f54e2baf8e31573b7bd9cefe9a9673bbf7522947494dc7de6790cdad6d9401707" +
        "7672b46b75abfe940fbde1cbe0fd261b113a15dff97dea0d9ef3d5265ba7543b532a4bda564644457b25a30bd4" +
        "28631c2de62c7c3afd240651eaa89d15865a21cfa7ba1a9baa48bf8aff984e4fe1cd96e73ed7e3e90d9a4b613c" +
        "8e84315b72f3033956d820c31a2908351c0c4a2858469acf8ab1406486b0e75372ed1018358c0c6fc7f502f35f" +
        "000000ffff")

    /// The decompressed inner archive (511 B) of `goldenSend0x1f`: 3 flavors.
    private let goldenArchive = Hex.data(
        "00000003000000167075626c69632e757466382d706c61696e2d74657874000000000000000300000010636f6d" +
        "2e6170706c652e6f7374797065000000047574663800000017636f6d2e6170706c652e6e7370626f6172642d747" +
        "97065000000124e53537472696e6750626f61726454797065000000107075626c69632e6d696d652d747970650" +
        "0000018746578742f706c61696e3b636861727365743d7574662d380000002553414d504c452d676f6c64656e2d" +
        "696e666c6174652d766563746f722d68656c6c6f2d343200000024636f6d2e6170706c652e747261646974696f6" +
        "e616c2d6d61632d706c61696e2d74657874000000000000000100000010636f6d2e6170706c652e6f7374797065" +
        "00000004544558540000002553414d504c452d676f6c64656e2d696e666c6174652d766563746f722d68656c6c6" +
        "f2d3432000000177075626c69632e75746631362d706c61696e2d74657874000000000000000200000010636f6d" +
        "2e6170706c652e6f73747970650000000475747874000000107075626c69632e6d696d652d747970650000001974" +
        "6578742f706c61696e3b636861727365743d7574662d31360000004a00530041004d0050004c0045002d0067006f" +
        "006c00640065006e002d0069006e0066006c006100740065002d0076006500630074006f0072002d00680065006c" +
        "006c006f002d00340032")

    private let goldenText = "SAMPLE-golden-inflate-vector-hello-42"

    // MARK: - Outbound builders (exact bytes)

    func testBuildAutoPasteboardEnable() {
        let msg = AppleClipboardCodec.buildAutoPasteboardEnable()
        XCTAssertEqual(msg, Hex.data("1500000100000000"), "0x15 enable is mode=1, 8 bytes")
        XCTAssertEqual(msg.count, 8, "enable MUST be exactly 8 bytes")
    }

    func testBuildClipboardFetchIsExactlyEightBytes() {
        let fetch = AppleClipboardCodec.buildClipboardFetch()
        XCTAssertEqual(fetch, Hex.data("0b00000000000000"), "0x0b full fetch, promise byte 0")
        XCTAssertEqual(fetch.count, 8, "0x0b MUST be exactly 8 bytes — 9 desyncs the daemon parser")

        let poll = AppleClipboardCodec.buildClipboardFetch(promiseOnly: true)
        XCTAssertEqual(poll, Hex.data("0b01000000000000"), "promise-only poll sets byte[1]=1")
        XCTAssertEqual(poll.count, 8)
    }

    // MARK: - Inbound header parse (golden)

    func testParseSendHeaderGolden() {
        let header = AppleClipboardCodec.parseSendHeader(goldenSend0x1f)
        XCTAssertEqual(header, AppleClipboardCodec.SendHeader(promise: 0,
                                                             reserved: 0,
                                                             uncompressedSize: 511,
                                                             compressedSize: 258))
    }

    func testParseSendHeaderRejectsShortOrWrongType() {
        XCTAssertNil(AppleClipboardCodec.parseSendHeader(Data([0x1f, 0, 0])), "too short")
        XCTAssertNil(AppleClipboardCodec.parseSendHeader(Hex.data("14000000000000000000000000000000")),
                     "not a 0x1f")
    }

    // MARK: - Inner archive parse (golden 3-flavor)

    func testParseGoldenArchiveFlavors() {
        let items = AppleClipboardCodec.parseItems(goldenArchive)
        XCTAssertEqual(items.count, 3, "utf8 + traditional-mac + utf16")

        XCTAssertEqual(items[0].primaryUTI, "public.utf8-plain-text")
        XCTAssertEqual(String(decoding: items[0].primaryData, as: UTF8.self), goldenText)
        XCTAssertEqual(items[0].aliases.map { $0.name },
                       ["com.apple.ostype", "com.apple.nspboard-type", "public.mime-type"])
        XCTAssertEqual(items[0].aliases.first { $0.name == "com.apple.ostype" }?.value,
                       Data("utf8".utf8))

        XCTAssertEqual(items[1].primaryUTI, "com.apple.traditional-mac-plain-text")
        XCTAssertEqual(items[1].aliases.first?.value, Data("TEXT".utf8))

        XCTAssertEqual(items[2].primaryUTI, "public.utf16-plain-text")
        XCTAssertEqual(String(data: items[2].primaryData, encoding: .utf16BigEndian), goldenText,
                       "public.utf16-plain-text is big-endian on the wire")
    }

    func testTextFromItemsPrefersUTF8() {
        let items = AppleClipboardCodec.parseItems(goldenArchive)
        XCTAssertEqual(AppleClipboardCodec.text(from: items), goldenText)
    }

    func testParseItemsToleratesEmptyAndShort() {
        XCTAssertEqual(AppleClipboardCodec.parseItems(Data()), [])
        XCTAssertEqual(AppleClipboardCodec.parseItems(Hex.data("000000")), [], "< 4 bytes → no items")
        XCTAssertEqual(AppleClipboardCodec.parseItems(Hex.data("00000000")), [], "item_count 0 → no items")
    }

    // MARK: - Full inbound decode (real 78da Z_SYNC_FLUSH stream)

    func testDecodeInboundGoldenText() throws {
        let text = try AppleClipboardCodec.decodeInboundText(goldenSend0x1f)
        XCTAssertEqual(text, goldenText, "inflate the daemon's real Z_SYNC_FLUSH stream + parse")
    }

    func testDecodeInboundEmptyClipboardIsNil() throws {
        // uncompressed_size == 0 → empty clipboard, decode short-circuits to nil.
        var header = Data([0x1f, 0, 0, 0])
        header.append(Data([0, 0, 0, 0]))          // reserved
        header.append(Data([0, 0, 0, 0]))          // uncompressed = 0
        header.append(Data([0, 0, 0, 7]))          // compressed = 7 (empty deflate)
        header.append(Hex.data("789c030000000001")) // any 7+ payload bytes; not inflated
        XCTAssertNil(try AppleClipboardCodec.decodeInboundText(header))
    }

    // MARK: - Outbound round-trip (deflate → inflate) + promise-byte fix

    func testBuildClipboardSendSetsPromiseByteAndRoundTrips() throws {
        let original = "Hello, T12! — paste into the Mac ✅"
        let msg = try AppleClipboardCodec.buildClipboardSend(text: original)

        let bytes = [UInt8](msg)
        XCTAssertEqual(bytes[0], 0x1f, "message type")
        XCTAssertEqual(bytes[2], 1, "OUTBOUND promise byte MUST be 1 (macOS-27 landing fix)")

        let header = AppleClipboardCodec.parseSendHeader(msg)
        XCTAssertEqual(header?.promise, 1)

        // Round-trip through our own inflate + parser.
        XCTAssertEqual(try AppleClipboardCodec.decodeInboundText(msg), original)
    }

    func testBuildClipboardSendSingleItemArchiveShape() throws {
        let inner = AppleClipboardCodec.buildSingleItemArchive(text: "hi")
        let items = AppleClipboardCodec.parseItems(inner)
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].primaryUTI, "public.utf8-plain-text")
        XCTAssertTrue(items[0].aliases.isEmpty, "outbound needs no aliases")
        XCTAssertEqual(String(decoding: items[0].primaryData, as: UTF8.self), "hi")
    }

    // MARK: - MiscStatus (0x14)

    func testMiscStatusCommandParsing() {
        XCTAssertEqual(AppleClipboardCodec.miscStatusCommand(Hex.data("1400000400010002")), 2)
        XCTAssertTrue(AppleClipboardCodec.isRemoteClipboardChanged(Hex.data("1400000400010002")))

        XCTAssertEqual(AppleClipboardCodec.miscStatusCommand(Hex.data("1400000400010004")), 4,
                       "steady heartbeat on macOS 27 is cmd=4")
        XCTAssertFalse(AppleClipboardCodec.isRemoteClipboardChanged(Hex.data("1400000400010004")))

        XCTAssertNil(AppleClipboardCodec.miscStatusCommand(Data([0x1f, 0])), "not a 0x14")
        XCTAssertNil(AppleClipboardCodec.miscStatusCommand(Hex.data("140000")), "too short")
    }
}
