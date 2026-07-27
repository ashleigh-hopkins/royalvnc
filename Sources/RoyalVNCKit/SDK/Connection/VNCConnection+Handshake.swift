#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Entry Point for Handshaking Phase
extension VNCConnection {
	func handshake() async throws {
		try await receiveProtocolVersion()
	}
}

// MARK: - Handshaking Phase Implementation
private extension VNCConnection {
	func receiveProtocolVersion() async throws {
		let protocolVersion: VNCProtocol.ProtocolVersion

		do {
			protocolVersion = try await VNCProtocol.ProtocolVersion.receive(connection: connection)

			logger.logDebug("Received Server Protocol Version: \(protocolVersion.protocolVersion)")

			state.serverProtocolVersion = protocolVersion
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Protocol Version",
																 underlyingError: error)
		}

		try await sendProtocolVersion(serverProtocolVersion: protocolVersion)
	}

	func sendProtocolVersion(serverProtocolVersion: VNCProtocol.ProtocolVersion) async throws {
		do {
			let clientProtocolVersion: VNCProtocol.ProtocolVersion
			let maxSupportedProtocolVersion = maxSupportedProtocolVersion

			// HP-SPECS §5.1: HP-gated 003.889 banner. Only when the HP setting is ON *and* the server
			// is an Apple Remote Desktop host (minor == 889). Otherwise the standard downgrade path
			// below runs unchanged (AC-5).
			if settings.enableHighPerformance,
			   serverProtocolVersion.isAppleRemoteDesktop {
				clientProtocolVersion = .appleRemoteDesktop
			}
			// The max. protocol version we currently support is 3.8, so check if the server is within those limits, otherwise downgrade to 3.8
			else if serverProtocolVersion.majorVersion <= maxSupportedProtocolVersion.majorVersion,
			   serverProtocolVersion.minorVersion <= maxSupportedProtocolVersion.minorVersion {
				// Server reported a protocol version equal or lower to 3.8, use it
				clientProtocolVersion = serverProtocolVersion
			} else {
				// Server reported a protocol version higher than 3.8, so make sure we use 3.8 and not any higher protocol version that the server offered
				clientProtocolVersion = .init(majorVersion: maxSupportedProtocolVersion.majorVersion,
											  minorVersion: maxSupportedProtocolVersion.minorVersion)
			}

			try await VNCProtocol.ProtocolVersion.send(connection: connection,
													   protocolVersion: clientProtocolVersion)

			logger.logDebug("Sent Client Protocol Version: \(clientProtocolVersion.protocolVersion)")

			state.agreedProtocolVersion = clientProtocolVersion
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Protocol Version",
																 underlyingError: error)
		}

		try await receiveNumberOfSecurityTypes()
	}

	func receiveNumberOfSecurityTypes() async throws {
		let number: UInt8

		do {
			let numberOfSecurityTypes = try await VNCProtocol.NumberOfSecurityTypes.receive(connection: connection)
			number = numberOfSecurityTypes.number

			logger.logDebug("Reveived Number of Security Types: \(number)")
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Number of Security Types",
																 underlyingError: error)
		}

		guard number > 0 else {
			let reason = try? await VNCProtocol.NumberOfSecurityTypes.receiveFailureReason(connection: connection)

			throw VNCError.authentication(.serverOfferedNoAuthTypes(reason: reason))
		}

		try await receiveSecurityTypes(number: number)
	}

	func receiveSecurityTypes(number: UInt8) async throws {
		let securityTypes: VNCProtocol.SecurityTypes

		do {
			securityTypes = try await VNCProtocol.SecurityTypes.receive(connection: connection,
																		number: number)

			logger.logDebug("Received Security Types: \(securityTypes.securityTypes.map({ "\($0)" }))")
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Security Types",
																 underlyingError: error)
		}

		try await decideSecurityType(supportedTypes: securityTypes)
	}

	func decideSecurityType(supportedTypes: VNCProtocol.SecurityTypes) async throws {
		let chosenSecurityType: VNCProtocol.SecurityType

		let supportedSecurityTypes = supportedTypes.securityTypes

		// HP-SPECS §5.2 / §4.3: HP-gated Apple type-33 (RSA-SRP) selection, taking priority when the
		// HP setting is ON and the server offers it. When HP is OFF, type 33 is ignored entirely even
		// if offered (AC-5) and the standard selection below runs unchanged.
		if settings.enableHighPerformance,
		   supportedSecurityTypes.contains(.apple33) {
			chosenSecurityType = .apple33
		} else if supportedSecurityTypes.contains(.none) {
			chosenSecurityType = .none
		} else if supportedSecurityTypes.contains(.diffieHellman) {
			chosenSecurityType = .diffieHellman
		} else if supportedSecurityTypes.contains(.ultraVNCMSLogonII) {
			chosenSecurityType = .ultraVNCMSLogonII
		} else if supportedSecurityTypes.contains(.vnc) {
			chosenSecurityType = .vnc
		} else if supportedSecurityTypes.contains(.tight) {
			chosenSecurityType = .tight
		} else {
			chosenSecurityType = .invalid
		}

		guard chosenSecurityType != .invalid,
			  supportedTypes.securityTypes.contains(chosenSecurityType) else {
			throw VNCError.authentication(.clientCouldNotDecideOnSecurityType)
		}

		try await sendAuthenticationData(securityType: chosenSecurityType)
	}

	func sendAuthenticationData(securityType: VNCProtocol.SecurityType) async throws {
		// HP (apple33): Apple screensharingd expects the 0x21 auth-type selector and the RSA1 init to
		// arrive as ONE atomic blob (the reference sends `21 00 00 00 0a 01 00 'RSA1' …` in a single
		// write). Sending 0x21 as a separate write here — as the standard path does — makes the daemon
		// tear the TCP right after the RSA1 init. So for apple33 the coordinator emits the combined
		// selector+init blob; we skip the standalone selector send.
		if !(settings.enableHighPerformance && securityType == .apple33) {
			do {
				try await VNCProtocol.SecurityTypes.send(connection: connection,
														 securityType: securityType.rawValue)
			} catch {
				throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Authentication Data",
																	 underlyingError: error)
			}
		}

		logger.logDebug("Sent Security Type: \(securityType)")

		let shouldRequestSecurityTypeResult: Bool

		switch securityType {
			case .none:
				if let protocolVersion = state.agreedProtocolVersion {
					// Only servers 3.8+ send a security result when no authentication is configured
					shouldRequestSecurityTypeResult = protocolVersion.is3Point8OrHigher
				} else {
					shouldRequestSecurityTypeResult = true
				}
			case .vnc:
				shouldRequestSecurityTypeResult = true

				try await performVNCAuthentication()
			case .diffieHellman:
				shouldRequestSecurityTypeResult = true

				try await performARDAuthentication()
			case .ultraVNCMSLogonII:
				shouldRequestSecurityTypeResult = true

				try await performUltraVNCMSLogonIIAuthentication()
			case .apple33:
				// The RSA-SRP coordinator consumes the M2 proof AND the SecurityResult itself
				// (HP-SPECS §5.2 step 4), so the shared `receiveSecurityTypeResult()` must NOT also run.
				shouldRequestSecurityTypeResult = false

				try await performAppleRSASRPAuthentication()
//			case .tight:
//				shouldRequestSecurityTypeResult = true
//				isTightSecurityEnabled = true
//
//				// TODO: Implement
			default:
				shouldRequestSecurityTypeResult = true
		}

		if shouldRequestSecurityTypeResult {
			try await receiveSecurityTypeResult()
		}

		try await sendClientInit()
	}

	func performVNCAuthentication() async throws {
		let auth = try await VNCProtocol.VNCAuthentication.receive(connection: connection)

		let credential = try await askDelegateForPasswordCredential(authenticationType: auth.authenticationType)

		try await auth.send(connection: connection,
							credential: credential)
	}

	func performARDAuthentication() async throws {
		let auth = try await VNCProtocol.ARDAuthentication.receive(connection: connection)

		let credential = try await askDelegateForUsernamePasswordCredential(authenticationType: auth.authenticationType)

		try await auth.send(connection: connection,
							credential: credential)
	}

	func performUltraVNCMSLogonIIAuthentication() async throws {
		let auth = try await VNCProtocol.UltraVNCMSLogonIIAuthentication.receive(connection: connection)

		let credential = try await askDelegateForUsernamePasswordCredential(authenticationType: auth.authenticationType)

		try await auth.send(connection: connection,
							credential: credential)
	}

	func receiveSecurityTypeResult() async throws {
		let result: VNCProtocol.SecurityResult

		do {
			result = try await VNCProtocol.SecurityResult.receive(connection: connection)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Security Type Result",
																 underlyingError: error)
		}

		guard let actualResult = result.result else {
			throw VNCError.protocol(.invalidData)
		}

		logger.logDebug("Received Security Type Result: \(actualResult)")

		guard actualResult == .ok else {
			let reason: String?

			// Only servers 3.8+ send a reason
			if let protocolVersion = state.agreedProtocolVersion,
			   protocolVersion.is3Point8OrHigher {
				reason = try? await VNCProtocol.SecurityResult.receiveFailureReason(connection: connection)
			} else {
				reason = nil
			}

			throw VNCError.authentication(.securityHandshakingFailed(reason: reason))
		}
	}

	func sendClientInit() async throws {
		let isShared = settings.isShared

		do {
			if settings.enableHighPerformance {
				// HP-SPECS §4.3 step 4 / dossier §3.1: Apple's ClientInit is the single byte 0xC1.
				// ORACLE(O6.5): confirmed byte-exact at the live cleartext-prelude checkpoint.
				try await connection.write(value: 0xC1)
			} else {
				try await VNCProtocol.ClientInit.send(connection: connection,
													  isShared: isShared)
			}
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Client Init",
																 underlyingError: error)
		}

		logger.logDebug("Sent Client Init")

		try await receiveServerInit()
	}

	func receiveServerInit() async throws {
		let serverInit: VNCProtocol.ServerInit

		do {
			if settings.enableHighPerformance {
				// HP: Apple's ServerInit name may not be valid UTF-8 — read leniently, discard the name.
				serverInit = try await receiveAppleServerInit()
			} else {
				serverInit = try await VNCProtocol.ServerInit.receive(connection: connection,
																	  isTightSecurityEnabled: state.isTightSecurityEnabled)
			}
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Server Init",
																 underlyingError: error)
		}

		logger.logDebug("Received Server Init \(serverInit)")

		state.framebufferWidth = serverInit.framebufferWidth
		state.framebufferHeight = serverInit.framebufferHeight
		state.desktopName = serverInit.name

		let serverPixelFormat = serverInit.pixelFormat

		// Force our own pixel format
		let clientPixelFormat = VNCProtocol.PixelFormat(depth: settings.colorDepth.rawValue)

		logger.logDebug("Forcing pixel format: \(clientPixelFormat)")

		// Use server pixel format
//		let clientPixelFormat = serverPixelFormat

		state.serverPixelFormat = serverPixelFormat
		state.pixelFormat = clientPixelFormat

		if settings.enableHighPerformance {
			// HP path: instead of the cleartext SetPixelFormat/SetEncodings, run the HP control
			// bring-up (cleartext prelude → 0x44f rekey → arm the AES-128-CBC record layer). After
			// this returns the record layer is active; the encrypted preface + framebuffer traffic is
			// the immediate live continuation (HP-SPECS §4.3 steps 5-7).
			try await performHighPerformanceControlBringUp()
		} else {
			do {
				try await sendSetPixelFormat(clientPixelFormat)
			} catch {
				throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Set Pixel Format",
																	 underlyingError: error)
			}

			let supportedEncodingTypes = try orderedEncodingTypes()

			do {
				try await sendSetEncodings(supportedEncodingTypes)
			} catch {
				throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Set Encodings",
																	 underlyingError: error)
			}
		}

		var framebufferSize = VNCSize(width: serverInit.framebufferWidth,
									  height: serverInit.framebufferHeight)

		// HP + virtual display: the VIDEO CANVAS is authoritative for geometry, not ServerInit.
		//
		// ServerInit is read before the HP control bring-up (which is where the `0x1d` request and the `0x1c`
		// negotiation happen), so it still describes the host's PHYSICAL display. If we asked for a virtual
		// display of a different size, sizing the framebuffer from ServerInit leaves the decoded video — whose
		// tiles are sized to the canvas — painted into the wrong-shaped buffer: the picture comes out at the
		// wrong resolution and stretched, and pointer mapping (which derives from `framebuffer.size`) is off
		// by the same ratio. Note we cannot `recreateFramebuffer` after negotiating, because negotiation runs
		// INSIDE the bring-up call above and the framebuffer does not exist yet — so create it at the right
		// size in the first place.
		if settings.enableHighPerformance,
		   let canvas = appleHPMediaContext?.canvas,
		   canvas.isReady,
		   canvas.width <= UInt32(UInt16.max), canvas.height <= UInt32(UInt16.max),
		   canvas.width != UInt32(framebufferSize.width) || canvas.height != UInt32(framebufferSize.height) {
			logger.logDebug("[hp-geom] framebuffer sized from the VIDEO CANVAS \(canvas.width)x\(canvas.height) instead of ServerInit \(framebufferSize.width)x\(framebufferSize.height) (virtual display active)")
			framebufferSize = VNCSize(width: UInt16(canvas.width), height: UInt16(canvas.height))
		}

        let newFramebuffer = try VNCFramebuffer(logger: logger,
                                                size: framebufferSize,
                                                screens: [ ],
                                                pixelFormat: clientPixelFormat,
                                                allocator: framebufferAllocator)

		newFramebuffer.delegate = self

		self.framebuffer = newFramebuffer

		clientToServerMessageQueue.clear()

		notifyDelegateAboutFramebufferCreation(newFramebuffer)
	}

	func sendSetPixelFormat(_ pixelFormat: VNCProtocol.PixelFormat) async throws {
		let sendPixelFormatMessage = VNCProtocol.SetPixelFormat(pixelFormat: pixelFormat)

		try await sendPixelFormatMessage.send(connection: connection)
	}

	func sendSetEncodings(_ encodings: [VNCEncodingType]) async throws {
		let setEncodingsMessage = VNCProtocol.SetEncodings(encodingTypes: encodings)

		try await setEncodingsMessage.send(connection: connection)
	}
}

// MARK: - Apple High-Performance (type 33 + AES-128-CBC record layer)
private extension VNCConnection {
	/// Run the RSA-SRP (type 33) exchange via the coordinator and stash the derived record-layer wrap
	/// key for arming after the `0x44f` rekey (HP-SPECS §5.2). `0x21` was already sent as the
	/// security-type selection by `sendAuthenticationData`.
	func performAppleRSASRPAuthentication() async throws {
		let credential = try await askDelegateForUsernamePasswordCredential(authenticationType: .appleRemoteDesktop)

		let coordinator = VNCProtocol.ARDRSASRPAuthentication()

		let success = try await coordinator.authenticate(connection: connection,
														  credential: credential,
														  logger: logger)

		// Held transiently until arming; never logged (NFR-6).
		appleHPWrapKey = success.wrapKey

		logger.logDebug("Apple RSA-SRP authentication succeeded (SecurityResult == 0)")
	}

	/// The HP control bring-up after `ServerInit` (HP-SPECS §4.3 steps 5-7 + §14 live corrections):
	/// plaintext prelude → receive the `1103` rekey as a rect inside a plaintext `FramebufferUpdate`
	/// (0x00) → unwrap → send the plaintext `PostEncryptionToggle` → arm the AES-128-CBC record layer →
	/// exercise one encrypted round-trip (proves `seal()`/`open()` live). Byte layouts are the
	/// live-confirmed values from `agents/TEMP/hp-phase3/post-auth-crib.md`.
	///
	/// NOTE (AC-2): a still-bitmap framebuffer is NOT obtainable here — Apple HP delivers every pixel
	/// over UDP/SRTP HEVC armed by the encrypted `0x1c` media offer (Phase 4). The TCP record layer only
	/// carries control + pseudo-encodings. This bring-up therefore proves the control channel end-to-end
	/// (record layer armed + encrypted round-trip), which is the achievable Phase-3 milestone.
	func performHighPerformanceControlBringUp() async throws {
		guard let wrapKey = appleHPWrapKey else {
			// Arm requires the wrap key from a completed RSA-SRP auth.
			throw VNCError.authentication(.ardAuthenticationFailed)
		}

		// § crib 2 — plaintext prelude (client sends only; reads nothing until the rekey burst).
		// ViewerInfo (0x21, 66B) + Apple 0x12 follow-up (12B) in ONE write.
		let viewerInfoPlus12: [UInt8] = [
			0x21,0x00,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x00,
			0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x03,0x00,0x00,
			0x00,0x00,0xb0,0x00,0x0c,0x03,0x90,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,
			0x12,0x00,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x01
		]
		// SetEncodings (0x02, 56B): count=13, HP_ENCODINGS_FULL. SetDisplayConfiguration 0x1d is sent between
		// the ViewerInfo settle and this, but ONLY when `settings.highPerformanceDisplay` is set (it curtains
		// the host — see below); with the default `nil` this prelude is byte-for-byte unchanged.
		let setEncodings: [UInt8] = [
			0x02,0x00,0x00,0x0d,
			0x00,0x00,0x03,0xf2, 0x00,0x00,0x03,0xf3, 0x00,0x00,0x03,0xea,
			0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x10, 0x00,0x00,0x04,0x50,
			0x00,0x00,0x04,0x4c, 0xff,0xff,0xff,0x21, 0x00,0x00,0x04,0x4d,
			0x00,0x00,0x04,0x51, 0x00,0x00,0x04,0x53, 0x00,0x00,0x04,0x55,
			0x00,0x00,0x04,0x56
		]
		// TIMED (see the [hp-media] negotiation timings): stage durations for the whole HP bring-up, so a
		// slow connect can be attributed from a device log instead of guessed at.
		let bringUpStart = Date()

		do {
			try await connection.write(data: Data(viewerInfoPlus12))
			try await Task.sleep(nanoseconds: 100_000_000)   // _POST_VIEWERINFO_SETTLE_S = 0.1s

			// OPT-IN virtual display (0x1d SetDisplayConfiguration), between ViewerInfo+0x12 and SetEncodings —
			// the ordering the reference uses, and it must go out here while the record layer is still in
			// passthrough (plaintext); `activateRecordLayer()` is not called until after the 1103 rekey below.
			//
			// Why: without 0x1d the daemon encodes the host's PHYSICAL panel. On a 5120×1440 ultrawide that is
			// 7.37 Mpx of 4:4:4 per frame, which saturates the A18 hardware decoder (~4 ms/AU measured,
			// busyFrac 1.00) and degrades into unbounded slow-motion. Asking for a smaller virtual display is
			// how Apple's own client avoids this. Sent BEFORE the 0x1c media offer so the FIRST 0x1c answer
			// already carries the reduced canvas (no 0x451 resize dance, no 0x1c re-offer — neither of which
			// this fork implements).
			//
			// ⚠️ This CURTAINS the host (physical screen stops showing the desktop; window layout reflows and
			// stays reflowed after disconnect), so it is strictly opt-in — `nil` sends nothing.
			if let display = settings.highPerformanceDisplay {
				let sdc = Apple0x1dSetDisplayConfiguration.build(logicalWidth: display.logicalWidth,
																 logicalHeight: display.logicalHeight,
																 hidpiScale: display.hidpiScale)
				try await connection.write(data: sdc)
				logger.logDebug("[hp-vdisp] sent 0x1d SetDisplayConfiguration (\(sdc.count) B) backing=\(display.pixelWidth)x\(display.pixelHeight) points=\(display.logicalWidth)x\(display.logicalHeight) hidpi=\(display.hidpiScale) — HOST IS NOW CURTAINED")
			}

			try await connection.write(data: Data(setEncodings))
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send HP Prelude",
																 underlyingError: error)
		}
		logger.logDebug("[hp] sent plaintext prelude (ViewerInfo+0x12, SetEncodings) in \(Self.hpElapsedMs(since: bringUpStart))ms")

		// § crib 3 — the 36-byte 1103 rekey arrives as a rect inside a plaintext FramebufferUpdate (0x00).
		// TIMED: this read blocks until the daemon sends the rekey burst. When a `0x1d` virtual display was
		// just requested, the host is creating that display first — so if a virtual-display connect is slow
		// before media negotiation even starts, it shows up here rather than in the [hp-media] retry loop.
		let rekeyStart = Date()
		let rekeyBody: Data
		do {
			rekeyBody = try await readAppleRekeyBlob()
			logger.logDebug("[hp] 1103 rekey read in \(Self.hpElapsedMs(since: rekeyStart))ms")
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Read 1103 Rekey",
																 underlyingError: error)
		}

		// Unwrap → CBC content key + iv (do NOT activate yet — the toggle must go out plaintext first).
		let parsed = try AppleRecordKeySchedule.parseRekey(rekeyBody)
		let recovered = try AppleRecordKeySchedule.unwrap((keyWrapped: parsed.keyWrapped,
														   ivWrapped: parsed.ivWrapped),
														  wrapKey: wrapKey)
		guard let recordLayer = connection as? AppleRecordLayerConnection else {
			throw VNCError.authentication(.ardAuthenticationFailed)   // decorator must be present under HP
		}

		// § crib 3 — PostEncryptionToggle (0x12, 8B) is the LAST plaintext byte the client sends. It goes
		// out BEFORE arming so the record layer is still in passthrough (plaintext) for this write.
		do {
			try await connection.write(data: Data([0x12,0x00,0x00,0x02,0x00,0x01,0x00,0x00]))
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send PostEncryptionToggle",
																 underlyingError: error)
		}

		// Arm: both directions flip to encrypted (server already flipped right after the 1103 rect).
		try recordLayer.activateRecordLayer(contentKey: recovered.key, iv: recovered.iv)
		appleHPWrapKey = nil
		logger.logDebug("[hp] AES-128-CBC record layer ARMED (generation \(parsed.gen))")
		try await Task.sleep(nanoseconds: 200_000_000)   // _POST_TOGGLE_SETTLE_S = 0.2s

		// Phase-4 media negotiation over the armed record layer (crib §2b): SetEncodings 0x02 →
		// 0x1c offer → FBU-req 0x03 → read the answer canvas → 0x09. This REPLACES the old 1-byte
		// readUInt8() "round-trip proof", which left the rest of the first FramebufferUpdate buffered
		// and misaligned the standard receive loop by one byte (HP-FBU-MISALIGN-REPORT). The media
		// path drives its own reads via open() and does NOT fall into the standard framebuffer decode
		// loop (which can't handle Apple HP pseudo-encodings like 0x451).
		do {
			try await connection.write(data: Data(setEncodings))   // SetEncodings 0x02 (crib §2b.1)
			// UNIFIED (crib §7): always negotiate media (0x1c/UDP), then the record-framed Apple control
			// loop (started in connectionDidBecomeReady) carries cursor/layout/clipboard on TCP alongside
			// the UDP media stream. The old media-vs-clipboard gate is gone: the control loop now survives
			// Apple pseudo-encodings by record-framing, so both coexist in one HP session. Clipboard
			// bring-up (0x15 + 0x0b) fires at send-loop start regardless (no-op if redirection is off).
			logger.logDebug("[hp] sent SetEncodings (seal() OK); starting media negotiation")
			try await performHighPerformanceMediaOffer()
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "HP media offer",
																 underlyingError: error)
		}

		logger.logDebug("[hp] bring-up total: \(Self.hpElapsedMs(since: bringUpStart))ms (prelude → rekey → arm → media canvas)")
	}

	/// Read the 36-byte `1103` rekey blob, which Apple delivers as a rect inside a plaintext
	/// `FramebufferUpdate` (msg 0x00) — NOT a bespoke message (§ crib 3). Skips an optional leading
	/// `0x14` UserSessionChanged (8B), then walks rects: `1103` → the next fixed 36 bytes are the blob;
	/// config siblings `1010`/`1011` carry a `u16` length prefix (skip `2+size`); any other encoding stops.
	func readAppleRekeyBlob() async throws -> Data {
		var msgType = try await connection.readUInt8()
		while msgType == 0x14 {                       // optional UserSessionChanged notification (8B)
			_ = try await connection.readBuffered(length: 7)
			msgType = try await connection.readUInt8()
		}
		guard msgType == 0x00 else {                  // FramebufferUpdate
			throw VNCError.protocol(.invalidData)
		}
		_ = try await connection.readUInt8()          // 1 pad byte
		let numRects = try await connection.readUInt16()

		for _ in 0..<numRects {
			_ = try await connection.readBuffered(length: 8)   // rect x,y,w,h (4× u16)
			let encoding = try await connection.readUInt32()   // s32 BE encoding (all positive here)
			if encoding == 1103 {
				return try await connection.readBuffered(length: AppleRecordKeySchedule.rekeyLength)
			} else if AppleControlChannelCodec.lengthPrefixedConfigEncodings.contains(Int(encoding))
						|| Int(encoding) == AppleControlChannelCodec.encDisplayLayout {
				// All of these share `u16 size + size bytes` framing (crib §7b). `0x451` AppleDisplayLayout
				// MUST be skipped here, not treated as unknown: requesting a virtual display (0x1d) is a
				// geometry change, and the daemon announces the new geometry with a 0x451 that can land in
				// this same pre-rekey burst. Breaking out on it strands the rest of the burst in the read
				// buffer, and the first AES-128-CBC record then parses that plaintext as ciphertext → a
				// bogus length → a read that never completes = the connection hangs at "connecting".
				let size = try await connection.readUInt16()
				_ = try await connection.readBuffered(length: Int(size))
				logger.logDebug("[hp-rekey] skipped pre-rekey rect encoding=\(encoding) len=\(size)")
			} else if Int(encoding) == AppleControlChannelCodec.encCursor {
				// `1104` cursor: `u32 cache_id, u32 comp_size` then comp_size bytes (0 = cache hit).
				_ = try await connection.readUInt32()
				let compSize = try await connection.readUInt32()
				if compSize > 0 { _ = try await connection.readBuffered(length: Int(compSize)) }
				logger.logDebug("[hp-rekey] skipped pre-rekey cursor rect comp=\(compSize)")
			} else {
				// Unknown length → we cannot skip it without desyncing, so stop. Log the encoding: without
				// it this failure is an opaque `.invalidData` (or a hang) with no way to tell which rect the
				// daemon sent.
				logger.logError("[hp-rekey] UNKNOWN pre-rekey rect encoding=\(encoding) (0x\(String(encoding, radix: 16))) — cannot skip; aborting rekey read")
				break
			}
		}
		throw VNCError.protocol(.invalidData)                  // no 1103 rect found
	}

	/// HP ServerInit read (§ crib 1): Apple 003.889 ServerInit is byte-for-byte standard RFC 6143, but
	/// the desktop-name bytes are NOT guaranteed valid UTF-8 and must be DISCARDED, not validated — the
	/// standard `readString(encoding:.utf8)` throws `.invalidData` on the name. Reads the fixed 24-byte
	/// header (u16 width, u16 height, 16-byte PixelFormat) then `u32` name-length + that many bytes,
	/// decoding the name losslessly (never throws).
	func receiveAppleServerInit() async throws -> VNCProtocol.ServerInit {
		let width = try await connection.readUInt16()
		let height = try await connection.readUInt16()
		let pixelFormat = try await VNCProtocol.PixelFormat.receive(connection: connection)
		let nameLength = try await connection.readUInt32()
		logger.logDebug("[hp] ServerInit: \(width)x\(height) nameLen=\(nameLength)")
		var name = ""
		if nameLength > 0, nameLength <= 4096 {
			let nameData = try await connection.readBuffered(length: Int(nameLength))
			name = String(decoding: nameData, as: UTF8.self)   // lossy — never throws
		}
		return .init(framebufferWidth: width, framebufferHeight: height, pixelFormat: pixelFormat, name: name)
	}
}
