import XCTest
@testable import RoyalVNCKit

/// Unit tests for the Apple-Standard tier's tolerant pseudo-encoding adapters (TYPE33-STANDARD-SPECS
/// §5.2/§11.1): each adapter's byte consumption must equal `AppleControlChannelCodec`'s framing exactly —
/// no more, no less — so the standard receive loop never desyncs on an interleaved Apple rect. Verified
/// here by appending a trailing marker after the scripted rect body and asserting the marker (and nothing
/// else) remains unconsumed.
final class AppleStandardPseudoEncodingsTests: XCTestCase {
    private func makeFramebuffer() throws -> VNCFramebuffer {
        try VNCFramebuffer(logger: VNCPrintLogger(),
                           size: VNCSize(width: 16, height: 16),
                           screens: [],
                           pixelFormat: VNCProtocol.PixelFormat(depth: 24),
                           allocator: nil)
    }

    private func makeConnection(mode: VNCConnection.Settings.SessionMode = .appleStandardFramebuffer) -> VNCConnection {
        let settings = VNCConnection.Settings(isDebugLoggingEnabled: false,
                                              hostname: "localhost",
                                              port: 5900,
                                              isShared: true,
                                              isScalingEnabled: false,
                                              useDisplayLink: false,
                                              inputMode: .none,
                                              isClipboardRedirectionEnabled: false,
                                              colorDepth: .depth24Bit,
                                              frameEncodings: [],
                                              mode: mode)

        return VNCConnection(settings: settings)
    }

    // MARK: - AppleCursorPseudoEncoding (1104)

    func testCursorAdapterConsumesExactlyCacheIDPlusCompSizeBytesOnCacheMiss() async throws {
        let connection = makeConnection()
        let framebuffer = try makeFramebuffer()
        connection.framebuffer = framebuffer

        let adapter = AppleCursorPseudoEncoding(owner: connection)
        let rectangle = VNCProtocol.Rectangle(xPosition: 0, yPosition: 0, width: 0, height: 0,
                                              encodingType: Int32(AppleControlChannelCodec.encCursor))

        var inbound = Data()
        inbound.append(contentsOf: [0x00, 0x00, 0x00, 0x2A])   // cache_id = 42, BE
        inbound.append(contentsOf: [0x00, 0x00, 0x00, 0x00])   // comp_size = 0 (cache-miss on unknown id)
        let marker: [UInt8] = [0xDE, 0xAD]
        inbound.append(contentsOf: marker)

        let mock = MockNetworkConnection(inbound: inbound)

        try await adapter.receive(rectangle, framebuffer: framebuffer, connection: mock, logger: VNCPrintLogger())

        let remaining = try await mock.readBuffered(length: marker.count)
        XCTAssertEqual(Array(remaining), marker,
                       "must consume EXACTLY 8 bytes (cache_id + comp_size) on comp_size==0 — matching AppleControlChannelCodec.cursorBodyLength's '8 + comp_size' formula")
    }

    func testCursorAdapterConsumesExactlyCacheIDPlusCompSizePlusPayloadBytes() async throws {
        let connection = makeConnection()
        let framebuffer = try makeFramebuffer()
        connection.framebuffer = framebuffer

        let adapter = AppleCursorPseudoEncoding(owner: connection)
        let rectangle = VNCProtocol.Rectangle(xPosition: 0, yPosition: 0, width: 4, height: 4,
                                              encodingType: Int32(AppleControlChannelCodec.encCursor))

        let payload: [UInt8] = Array(repeating: 0xAB, count: 10)   // not valid zlib — decode failure is
                                                                   // tolerated by applyAppleCursor (logged,
                                                                   // never fatal), so this only exercises
                                                                   // the FRAMING, not the pixel decode.
        var inbound = Data()
        inbound.append(contentsOf: [0x00, 0x00, 0x00, 0x01])                    // cache_id = 1
        inbound.append(contentsOf: [0x00, 0x00, 0x00, UInt8(payload.count)])    // comp_size = 10
        inbound.append(contentsOf: payload)
        let marker: [UInt8] = [0xBE, 0xEF]
        inbound.append(contentsOf: marker)

        let mock = MockNetworkConnection(inbound: inbound)

        try await adapter.receive(rectangle, framebuffer: framebuffer, connection: mock, logger: VNCPrintLogger())

        let remaining = try await mock.readBuffered(length: marker.count)
        XCTAssertEqual(Array(remaining), marker,
                       "must consume EXACTLY 8 + comp_size bytes even when the compressed payload fails to decode")
    }

    // MARK: - AppleConfigSkipPseudoEncoding (1010/1011/1107/1109/1110)

    func testConfigSkipAdapterConsumesExactlyTwoPlusSizeBytes() async throws {
        let framebuffer = try makeFramebuffer()
        let adapter = AppleConfigSkipPseudoEncoding(encodingType: VNCEncodingType(Int32(1011)))
        let rectangle = VNCProtocol.Rectangle(xPosition: 0, yPosition: 0, width: 0, height: 0, encodingType: 1011)

        let payload: [UInt8] = Array(repeating: 0x11, count: 6)
        var inbound = Data()
        inbound.append(contentsOf: [0x00, UInt8(payload.count)])   // u16 BE size = 6
        inbound.append(contentsOf: payload)
        let marker: [UInt8] = [0xCA, 0xFE]
        inbound.append(contentsOf: marker)

        let mock = MockNetworkConnection(inbound: inbound)

        try await adapter.receive(rectangle, framebuffer: framebuffer, connection: mock, logger: VNCPrintLogger())

        let remaining = try await mock.readBuffered(length: marker.count)
        XCTAssertEqual(Array(remaining), marker,
                       "must consume EXACTLY 2 + size bytes — matching AppleControlChannelCodec.lengthPrefixedBodyLength")
    }

    func testConfigSkipAdapterHandlesZeroLengthBody() async throws {
        let framebuffer = try makeFramebuffer()
        let adapter = AppleConfigSkipPseudoEncoding(encodingType: VNCEncodingType(Int32(1010)))
        let rectangle = VNCProtocol.Rectangle(xPosition: 0, yPosition: 0, width: 0, height: 0, encodingType: 1010)

        var inbound = Data([0x00, 0x00])   // u16 BE size = 0
        let marker: [UInt8] = [0x01]
        inbound.append(contentsOf: marker)

        let mock = MockNetworkConnection(inbound: inbound)

        try await adapter.receive(rectangle, framebuffer: framebuffer, connection: mock, logger: VNCPrintLogger())

        let remaining = try await mock.readBuffered(length: marker.count)
        XCTAssertEqual(Array(remaining), marker)
    }

    // MARK: - AppleDisplayLayoutPseudoEncoding (0x451 / 1105)

    func testDisplayLayoutAdapterParsesGeometryMatchingCodecAndConsumesExactBytes() async throws {
        let framebuffer = try makeFramebuffer()
        let adapter = AppleDisplayLayoutPseudoEncoding()
        let rectangle = VNCProtocol.Rectangle(xPosition: 0, yPosition: 0, width: 0, height: 0,
                                              encodingType: Int32(AppleControlChannelCodec.encDisplayLayout))

        // prefix_len = 10 (>= 10 → geometry present): the four dims sit at offset+4/6/8/10 measured from
        // the prefix_len field itself (displayLayoutBody), i.e. 2 reserved bytes THEN the four u16 BE
        // fields = 10 body bytes total. Scaled 1712x1112, backing 2868x1320 — the SAME values used by the
        // fork's own `testCanvasFromLayoutUsesBackingDimensionsAndOfferedTiles`.
        var body: [UInt8] = [0x00, 0x00]        // reserved (offset+2..3, unused by this codec)
        body.append(contentsOf: [0x06, 0xB0])   // scaledWidth = 1712
        body.append(contentsOf: [0x04, 0x58])   // scaledHeight = 1112
        body.append(contentsOf: [0x0B, 0x34])   // backingWidth = 2868
        body.append(contentsOf: [0x05, 0x28])   // backingHeight = 1320

        var inbound = Data()
        inbound.append(contentsOf: [0x00, UInt8(body.count)])   // u16 BE prefix_len = 10
        inbound.append(contentsOf: body)
        let marker: [UInt8] = [0x99]
        inbound.append(contentsOf: marker)

        let mock = MockNetworkConnection(inbound: inbound)

        try await adapter.receive(rectangle, framebuffer: framebuffer, connection: mock, logger: VNCPrintLogger())

        let remaining = try await mock.readBuffered(length: marker.count)
        XCTAssertEqual(Array(remaining), marker, "must consume EXACTLY 2 + prefix_len bytes")

        // Cross-check the parsed geometry against the SAME authority function `readAppleRekeyBlob` already
        // uses for the pre-rekey case — one authority, one answer.
        var framed = Data([0x00, UInt8(body.count)])
        framed.append(contentsOf: body)
        let expected = AppleControlChannelCodec.parseDisplayLayoutBody(framed)
        XCTAssertEqual(expected?.scaledWidth, 1712)
        XCTAssertEqual(expected?.scaledHeight, 1112)
        XCTAssertEqual(expected?.backingWidth, 2868)
        XCTAssertEqual(expected?.backingHeight, 1320)
    }

    func testDisplayLayoutAdapterToleratesShortPrefixWithNoGeometry() async throws {
        let framebuffer = try makeFramebuffer()
        let adapter = AppleDisplayLayoutPseudoEncoding()
        let rectangle = VNCProtocol.Rectangle(xPosition: 0, yPosition: 0, width: 0, height: 0,
                                              encodingType: Int32(AppleControlChannelCodec.encDisplayLayout))

        var inbound = Data()
        inbound.append(contentsOf: [0x00, 0x04])   // prefix_len = 4 (< 10 → no geometry)
        inbound.append(contentsOf: [0x01, 0x02, 0x03, 0x04])
        let marker: [UInt8] = [0x77]
        inbound.append(contentsOf: marker)

        let mock = MockNetworkConnection(inbound: inbound)

        try await adapter.receive(rectangle, framebuffer: framebuffer, connection: mock, logger: VNCPrintLogger())

        let remaining = try await mock.readBuffered(length: marker.count)
        XCTAssertEqual(Array(remaining), marker, "must not throw or misparse on a short prefix_len — just no geometry")
    }

    // MARK: - Registry gating (SPECS §5.2, AC-5)

    func testAppleEncodingsAreRegisteredOnlyForAppleAuthenticatedSessions() {
        let standard = makeConnection(mode: .standardRFB)
        let appleStandard = makeConnection(mode: .appleStandardFramebuffer)

        let cursorEncodingType = VNCEncodingType(Int32(AppleControlChannelCodec.encCursor))

        XCTAssertNil(standard.encodings[cursorEncodingType],
                    ".standardRFB must not register Apple pseudo-encodings (AC-5 — byte-for-byte unchanged)")
        XCTAssertNotNil(appleStandard.encodings[cursorEncodingType],
                       ".appleStandardFramebuffer must register the 1104 cursor adapter")
    }
}
