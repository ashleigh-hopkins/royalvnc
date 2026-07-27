import XCTest
@testable import RoyalVNCKit

/// Byte-exactness tests for `Apple0x1dSetDisplayConfiguration` (the `0x1d` SetDisplayConfiguration /
/// virtual-display request).
///
/// The golden vectors are pinned against an **INDEPENDENT oracle**: the AGPL Python reference proxy's own
/// `build_virtual_display` was EXECUTED (not read) for each geometry and its output hexdumped, mirroring the
/// oracle approach used for the SRTP KDF / MediaBlob / 0x1c offer seams. Only the resulting BYTES are pinned
/// here — no reference code was copied.
///
/// Structural invariants under test: 308-byte total at modeCount=5, `msgSize = 304` (the count of bytes
/// following that field), mode 0's POINT dims == the requested logical size, and the hidpi trap (scale
/// multiplies ONLY the pixel/backing dims, so points stay put while backing doubles).
final class Apple0x1dSetDisplayConfigurationTests: XCTestCase {

	private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

	private static let name = "Screen Sharing Virtual Display"

	// MARK: - Golden vectors (reference builder output, byte-for-byte)

	/// Golden vectors: output of the reference proxy's own `build_virtual_display`, EXECUTED per
	/// geometry and hexdumped (independent oracle; bytes only, no code copied). Generated mechanically —
	/// do not hand-edit.
	private static let golden: [String: String] = [
		"p1080_flat": "1d0001300001000100000000012853637265656e2053686172696e67205669727475616c20446973706c6179000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000443b8ba2f434fd17400000f00000008700000000000000007000500000780000004380000078000000438404e00000000000000000000000005a000000384000005a000000384404e0000000000000000000000000780000004380000078000000438404e00000000000000000000000005a00000032a000005a00000032a404e0000000000000000000000000520000003500000052000000350404e00000000000000000000",
		"p1080_retina": "1d0001300001000100000000012853637265656e2053686172696e67205669727475616c20446973706c6179000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000443b8ba2f434fd17400000f00000008700000000000000007000500000f00000008700000078000000438404e0000000000000000000000000b4000000708000005a000000384404e0000000000000000000000000f00000008700000078000000438404e0000000000000000000000000b4000000654000005a00000032a404e0000000000000000000000000a40000006a00000052000000350404e00000000000000000000",
		"uw1080_flat": "1d0001300001000100000000012853637265656e2053686172696e67205669727475616c20446973706c6179000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000443b8ba2f434fd17400000f00000008700000000000000007000500000f000000043800000f0000000438404e0000000000000000000000000b400000038400000b4000000384404e0000000000000000000000000f000000043800000f0000000438404e0000000000000000000000000b400000032a00000b400000032a404e0000000000000000000000000a400000035000000a4000000350404e00000000000000000000",
		"p720_flat": "1d0001300001000100000000012853637265656e2053686172696e67205669727475616c20446973706c6179000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000443b8ba2f434fd17400000f00000008700000000000000007000500000500000002d000000500000002d0404e00000000000000000000000003c000000258000003c000000258404e0000000000000000000000000500000002d000000500000002d0404e00000000000000000000000003c00000021c000003c00000021c404e000000000000000000000000036b000002350000036b00000235404e00000000000000000000",
		"uw720_flat": "1d0001300001000100000000012853637265656e2053686172696e67205669727475616c20446973706c6179000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000443b8ba2f434fd17400000f00000008700000000000000007000500000a00000002d000000a00000002d0404e0000000000000000000000000780000002580000078000000258404e0000000000000000000000000a00000002d000000a00000002d0404e00000000000000000000000007800000021c000007800000021c404e00000000000000000000000006d500000235000006d500000235404e00000000000000000000",
	]

	/// All five geometries must reproduce the reference bytes EXACTLY. This is the test that proves the
	/// builder is wire-correct (the structural tests below prove it stays that way for reasons a human can read).
	func testGoldenVectorsByteExact() {
		let cases: [(key: String, w: Int, h: Int, scale: Int)] = [
			("p1080_flat", 1920, 1080, 1),
			("p1080_retina", 1920, 1080, 2),
			("uw1080_flat", 3840, 1080, 1),
			("p720_flat", 1280, 720, 1),
			("uw720_flat", 2560, 720, 1),
		]
		for c in cases {
			let built = Apple0x1dSetDisplayConfiguration.build(logicalWidth: c.w, logicalHeight: c.h,
															  hidpiScale: c.scale, displayName: Self.name)
			XCTAssertEqual(built.count, 308, "\(c.key): native SDC is 308 bytes")
			XCTAssertEqual(hex(built), Self.golden[c.key], "\(c.key) does not match the reference bytes")
		}
	}

	/// 1920×1080 @2x — THE HIDPI TRAP. Points stay 1920×1080 but the backing (what the encoder produces and
	/// we must decode) becomes 3840×2160 = 8.29 Mpx, MORE than a 5120×1440 panel's 7.37 Mpx. Pinned so a
	/// future change to the default scale is caught by a failing test rather than on-device slow-motion.
	func testGolden1920x1080Retina_backingDoubles() {
		let d = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080,
													  hidpiScale: 2, displayName: Self.name)
		XCTAssertEqual(d.count, 308)
		let m0 = Self.mode(d, 0)
		XCTAssertEqual(m0.pointWidth, 1920)
		XCTAssertEqual(m0.pointHeight, 1080)
		XCTAssertEqual(m0.pixelWidth, 3840, "hidpi 2 must double the BACKING width")
		XCTAssertEqual(m0.pixelHeight, 2160, "hidpi 2 must double the BACKING height")
		// And the flat build must NOT double it.
		let flat = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080,
														 hidpiScale: 1, displayName: Self.name)
		XCTAssertEqual(Self.mode(flat, 0).pixelWidth, 1920)
		XCTAssertEqual(Self.mode(flat, 0).pixelHeight, 1080)
	}

	/// 3840×1080 @1x — the 32:9 ultrawide-preserving preset (at the daemon's 3840 width cap).
	func testGolden3840x1080Flat() {
		let d = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 3840, logicalHeight: 1080,
													  hidpiScale: 1, displayName: Self.name)
		XCTAssertEqual(d.count, 308)
		let m0 = Self.mode(d, 0)
		XCTAssertEqual(m0.pointWidth, 3840)
		XCTAssertEqual(m0.pointHeight, 1080)
		XCTAssertEqual(m0.pixelWidth, 3840)
		XCTAssertEqual(m0.pixelHeight, 1080)
		// Template scaling: mode 1 = (1440,900) * (sx=2.0, sy=1.0) = (2880, 900) = 0xb40, 0x384.
		XCTAssertEqual(Self.mode(d, 1).pointWidth, 2880)
		XCTAssertEqual(Self.mode(d, 1).pointHeight, 900)
	}

	/// 1280×720 @1x and 2560×720 @1x — verifies the round-half-up template scaling, including the awkward
	/// (1312,848) entry: 2560 wide → 1312*1.3333+0.5 = 1749 (0x6d5), 848*0.6667+0.5 = 565 (0x235).
	func testGoldenTemplateScalingRounding() {
		let d720 = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1280, logicalHeight: 720,
														 hidpiScale: 1, displayName: Self.name)
		XCTAssertEqual(Self.mode(d720, 0).pointWidth, 1280)
		XCTAssertEqual(Self.mode(d720, 0).pointHeight, 720)
		XCTAssertEqual(Self.mode(d720, 4).pointWidth, 875)    // 1312 * (1280/1920) + 0.5 = 875.16 -> 875
		XCTAssertEqual(Self.mode(d720, 4).pointHeight, 565)   // 848 * (720/1080) + 0.5 = 565.8 -> 565

		let uw = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 2560, logicalHeight: 720,
														hidpiScale: 1, displayName: Self.name)
		XCTAssertEqual(Self.mode(uw, 4).pointWidth, 1749)     // 0x6d5
		XCTAssertEqual(Self.mode(uw, 4).pointHeight, 565)     // 0x235
	}

	// MARK: - Structure

	func testHeaderStructure() {
		let d = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080)
		let b = [UInt8](d)
		XCTAssertEqual(b[0], 0x1d)                                  // msgType
		XCTAssertEqual(b[1], 0)                                     // pad
		XCTAssertEqual(UInt16(b[2]) << 8 | UInt16(b[3]), 304)       // msgSize = bytes after this field
		XCTAssertEqual(Int(b[2]) << 8 | Int(b[3]), d.count - 4)     // and that equals total - 4
		XCTAssertEqual(UInt16(b[4]) << 8 | UInt16(b[5]), 1)         // msgVersion
		XCTAssertEqual(UInt16(b[6]) << 8 | UInt16(b[7]), 1)         // descriptorCount
		XCTAssertEqual(UInt32(b[8]) << 24 | UInt32(b[9]) << 16 | UInt32(b[10]) << 8 | UInt32(b[11]), 0)
	}

	func testDisplayInfoFixedFields() {
		let d = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080)
		let b = [UInt8](d)
		let D = 12
		func u16(_ o: Int) -> UInt16 { UInt16(b[D + o]) << 8 | UInt16(b[D + o + 1]) }
		func u32(_ o: Int) -> UInt32 {
			UInt32(b[D + o]) << 24 | UInt32(b[D + o + 1]) << 16 | UInt32(b[D + o + 2]) << 8 | UInt32(b[D + o + 3])
		}
		XCTAssertEqual(u16(0x00), 0x128)                 // displayInfoSize = 0x9C + 28*5 = 296
		XCTAssertEqual(u32(0x7A), 0x01)                  // displayFlags = DYNAMIC_RESOLUTION
		XCTAssertEqual(u32(0x7E), 4)                     // displayType = virtual display
		XCTAssertEqual(u32(0x82), 0x43b8ba2f)            // physical width mm (f32 BE, native capture)
		XCTAssertEqual(u32(0x86), 0x434fd174)            // physical height mm
		XCTAssertEqual(u32(0x8A), 3840)                  // maxWidth cap
		XCTAssertEqual(u32(0x8E), 2160)                  // maxHeight cap
		XCTAssertEqual(u16(0x92), 0)                     // currentModeIndex
		XCTAssertEqual(u16(0x94), 0)                     // preferredModeIndex
		XCTAssertEqual(u32(0x96), 7)                     // rotations
		XCTAssertEqual(u16(0x9A), 5)                     // modeCount
	}

	func testModeRefreshAndHDRFlag() {
		let sdr = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080)
		let hdr = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080, hdr: true)
		// refresh = f64 60.0 = 0x404e000000000000 at mode+0x10
		let b = [UInt8](sdr)
		let refreshOffset = 12 + 0x9C + 0x10
		XCTAssertEqual(Array(b[refreshOffset..<refreshOffset + 8]),
					   [0x40, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
		XCTAssertEqual(Self.modeFlags(sdr, 0), 0)
		XCTAssertEqual(Self.modeFlags(hdr, 0), 1)
	}

	/// The display name is a 120-byte NUL-padded region with NO length prefix; an over-long name is truncated
	/// to 119 bytes so at least one terminating NUL survives (and the message length never changes).
	func testDisplayNameTruncatedAndPadded() {
		let long = String(repeating: "A", count: 400)
		let d = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080,
													  displayName: long)
		XCTAssertEqual(d.count, 308, "name length must never change the message size")
		let b = [UInt8](d)
		XCTAssertEqual(b[12 + 0x02], 0x41)
		XCTAssertEqual(b[12 + 0x02 + 118], 0x41)
		XCTAssertEqual(b[12 + 0x02 + 119], 0x00, "byte 120 of the name region must be a NUL terminator")

		let short = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080,
														   displayName: "AB")
		let sb = [UInt8](short)
		XCTAssertEqual(sb[12 + 0x02], 0x41)
		XCTAssertEqual(sb[12 + 0x02 + 1], 0x42)
		XCTAssertEqual(sb[12 + 0x02 + 2], 0x00)
	}

	func testModeCountAffectsLength() {
		let one = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080, modeCount: 1)
		XCTAssertEqual(one.count, 12 + 0x9C + 28)
		let b = [UInt8](one)
		XCTAssertEqual(UInt16(b[2]) << 8 | UInt16(b[3]), UInt16(one.count - 4))
		// Out-of-range counts clamp to the template length rather than reading past it.
		let clamped = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080, modeCount: 99)
		XCTAssertEqual(clamped.count, 308)
	}

	// MARK: - helpers

	private struct Mode { let pixelWidth, pixelHeight, pointWidth, pointHeight: UInt32 }

	private static func mode(_ d: Data, _ index: Int) -> Mode {
		let b = [UInt8](d)
		let o = 12 + 0x9C + 28 * index
		func u32(_ off: Int) -> UInt32 {
			UInt32(b[o + off]) << 24 | UInt32(b[o + off + 1]) << 16 | UInt32(b[o + off + 2]) << 8 | UInt32(b[o + off + 3])
		}
		return Mode(pixelWidth: u32(0), pixelHeight: u32(4), pointWidth: u32(8), pointHeight: u32(0x0C))
	}

	private static func modeFlags(_ d: Data, _ index: Int) -> UInt32 {
		let b = [UInt8](d)
		let o = 12 + 0x9C + 28 * index + 0x18
		return UInt32(b[o]) << 24 | UInt32(b[o + 1]) << 16 | UInt32(b[o + 2]) << 8 | UInt32(b[o + 3])
	}

	// MARK: - Fractional backing:point ratio (explicit pixel+point form)

	/// The wire carries pixel and point dims as INDEPENDENT u32s per mode, so the ratio need not be an
	/// integer. 1.5 is the useful phone setting: 2× Retina fixes text quality but halves the desktop area in
	/// each axis (oversized windows/text), while 1.5 keeps most of the quality at the SAME decode cost.
	func testExplicitPixelAndPointDimsSupportA1Point5Ratio() {
		let d = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1912, logicalHeight: 880,
													  pixelWidth: 2868, pixelHeight: 1320,
													  displayName: Self.name)
		XCTAssertEqual(d.count, 308, "the message layout is unchanged by a fractional ratio")

		let m0 = Self.mode(d, 0)
		XCTAssertEqual(m0.pointWidth, 1912)
		XCTAssertEqual(m0.pointHeight, 880)
		XCTAssertEqual(m0.pixelWidth, 2868, "the requested BACKING must appear verbatim — no rounding")
		XCTAssertEqual(m0.pixelHeight, 1320, "the requested BACKING must appear verbatim — no rounding")
	}

	/// Mode 0 is the request; the remaining template modes must carry the same ratio (not a re-derived
	/// integer one), otherwise the host could pick a sibling mode with a different backing than we budgeted.
	func testTemplateModesInheritTheFractionalRatio() {
		let d = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1912, logicalHeight: 880,
													  pixelWidth: 2868, pixelHeight: 1320,
													  displayName: Self.name)
		for index in 1..<5 {
			let m = Self.mode(d, index)
			guard m.pointWidth > 0, m.pointHeight > 0 else { continue }
			XCTAssertEqual(Double(m.pixelWidth) / Double(m.pointWidth), 1.5, accuracy: 0.01,
						   "mode \(index) width ratio")
			XCTAssertEqual(Double(m.pixelHeight) / Double(m.pointHeight), 1.5, accuracy: 0.01,
						   "mode \(index) height ratio")
		}
	}

	/// The integer-scale entry point is now a wrapper over the explicit form. It must still produce the
	/// reference bytes — the golden vectors above are the real guard, this pins the equivalence directly.
	func testIntegerScaleWrapperMatchesTheExplicitForm() {
		let viaScale = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080,
															 hidpiScale: 2, displayName: Self.name)
		let viaExplicit = Apple0x1dSetDisplayConfiguration.build(logicalWidth: 1920, logicalHeight: 1080,
																pixelWidth: 3840, pixelHeight: 2160,
																displayName: Self.name)
		XCTAssertEqual(viaScale, viaExplicit)
	}

	// MARK: - HighPerformanceDisplay point derivation

	/// The settings value type derives (and stores) the point size from the backing budget and the scale.
	/// A 1.5 scale must keep the backing exactly as requested — that number is the decode cost the user
	/// chose — and land the points on an even number.
	func testHighPerformanceDisplayDerivesEvenPointsAtA1Point5Scale() {
		let display = VNCConnection.Settings.HighPerformanceDisplay(pixelWidth: 2868,
																	pixelHeight: 1320,
																	hidpiScale: 1.5)
		XCTAssertEqual(display.pixelWidth, 2868, "backing is the budget and must not move")
		XCTAssertEqual(display.pixelHeight, 1320)
		XCTAssertEqual(display.logicalWidth, 1912, "2868 / 1.5 = 1912")
		XCTAssertEqual(display.logicalHeight, 880, "1320 / 1.5 = 880")
		XCTAssertEqual(display.logicalWidth % 2, 0)
		XCTAssertEqual(display.logicalHeight % 2, 0)
		XCTAssertEqual(display.hidpiScale, 1.5, accuracy: 0.01)
	}

	/// Flat (1×) and Retina (2×) must keep behaving exactly as before the type gained fractional support.
	func testHighPerformanceDisplayFlatAndRetinaUnchanged() {
		let flat = VNCConnection.Settings.HighPerformanceDisplay(pixelWidth: 1920, pixelHeight: 1080)
		XCTAssertEqual(flat.logicalWidth, 1920)
		XCTAssertEqual(flat.logicalHeight, 1080)

		let retina = VNCConnection.Settings.HighPerformanceDisplay(pixelWidth: 1920, pixelHeight: 1080,
																   hidpiScale: 2)
		XCTAssertEqual(retina.logicalWidth, 960)
		XCTAssertEqual(retina.logicalHeight, 540)
	}
}
