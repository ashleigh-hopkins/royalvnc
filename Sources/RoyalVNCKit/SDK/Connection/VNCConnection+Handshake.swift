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
		do {
			try await VNCProtocol.SecurityTypes.send(connection: connection,
													 securityType: securityType.rawValue)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Authentication Data",
																 underlyingError: error)
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
			serverInit = try await VNCProtocol.ServerInit.receive(connection: connection,
																  isTightSecurityEnabled: state.isTightSecurityEnabled)
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

		let framebufferSize = VNCSize(width: serverInit.framebufferWidth,
									  height: serverInit.framebufferHeight)

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

		logger.logDebug("Apple RSA-SRP authentication succeeded (M2 verified, SecurityResult == 0)")
	}

	/// The HP control bring-up after `ServerInit` (HP-SPECS §4.3 steps 5-6): send the cleartext prelude,
	/// read the `0x44f` rekey, unwrap it, and arm the AES-128-CBC record layer on the connection.
	///
	/// WIRE LAYOUT — ORACLE-GATED (O6.5 prelude, O7 rekey). The prelude message bodies and the `0x44f`
	/// framing are implemented to the dossier's stated layout and confirmed byte-for-byte at the live
	/// checkpoint; they are NOT offline-verifiable. In particular the `ViewerInfo` payload (dossier
	/// names only the `0x21` type) and R6 (the rekey may arrive between `SetEncryption` cmd=1 and cmd=2)
	/// are pinned live. `SetEncryption` cmd=1/cmd=2 use the concrete dossier §3.1 hex.
	func performHighPerformanceControlBringUp() async throws {
		guard let wrapKey = appleHPWrapKey else {
			// Arm requires the wrap key from a completed RSA-SRP auth.
			throw VNCError.authentication(.ardAuthenticationFailed)
		}

		do {
			// ViewerInfo (0x21) — ORACLE(O6.5): payload beyond the type byte is pinned at the live
			// checkpoint (the dossier names only the message type).
			try await connection.write(data: Data([0x21]))

			// SetEncryption cmd=1: 12 00 0001 0001 0001 00000001 (dossier §3.1 step 5).
			try await connection.write(data: Data([0x12, 0x00,
													0x00, 0x01,
													0x00, 0x01,
													0x00, 0x01,
													0x00, 0x00, 0x00, 0x01]))

			// SetEncryption cmd=2: 12 00 0002 0001 0000 (dossier §3.1 step 5).
			try await connection.write(data: Data([0x12, 0x00,
													0x00, 0x02,
													0x00, 0x01,
													0x00, 0x00]))
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send HP Prelude",
																 underlyingError: error)
		}

		// Read the 0x44f rekey. ORACLE(O7): assumes a u16 message-type (0x044f) followed by the 36-byte
		// body; R6 (arrival between cmd=1 and cmd=2) is pinned live.
		let rekeyBody: Data
		do {
			let messageType = try await connection.readUInt16()
			guard messageType == 0x044f else {
				throw VNCError.protocol(.invalidData)
			}
			rekeyBody = try await connection.readBuffered(length: AppleRecordKeySchedule.rekeyLength)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Read 0x44f Rekey",
																 underlyingError: error)
		}

		try armAppleRecordLayer(wrapKey: wrapKey, rekeyBody: rekeyBody)
	}

	/// Unwrap the `0x44f` rekey body under `wrapKey` and flip the connection's record layer into CBC
	/// mode (HP-SPECS §5.3). The recovered key/iv become the CBC content key/iv for both directions.
	/// Clears the retained wrap key afterwards (NFR-6).
	func armAppleRecordLayer(wrapKey: Data, rekeyBody: Data) throws {
		guard let recordLayer = connection as? AppleRecordLayerConnection else {
			// The decorator is always present when HP is on; its absence is a wiring error.
			throw VNCError.authentication(.ardAuthenticationFailed)
		}

		let parsed = try AppleRecordKeySchedule.parseRekey(rekeyBody)
		let recovered = try AppleRecordKeySchedule.unwrap((keyWrapped: parsed.keyWrapped,
														   ivWrapped: parsed.ivWrapped),
														  wrapKey: wrapKey)

		try recordLayer.activateRecordLayer(contentKey: recovered.key, iv: recovered.iv)

		appleHPWrapKey = nil

		logger.logDebug("Apple AES-128-CBC record layer armed (generation \(parsed.gen))")
	}
}
