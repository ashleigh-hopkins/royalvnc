#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

#if canImport(Network)
import Network
#endif

#if canImport(ObjectiveC)
@objc(VNCConnection)
#endif
public final class VNCConnection: NSObjectOrAnyObject {
	// MARK: - Public Properties
#if canImport(ObjectiveC)
	@objc
#endif
	public let settings: Settings

    public let context: UnsafeMutableRawPointer?

#if canImport(ObjectiveC)
	@objc
#endif
	public weak var delegate: VNCConnectionDelegate?

#if canImport(ObjectiveC)
	@objc
#endif
	public var framebuffer: VNCFramebuffer?

#if canImport(ObjectiveC)
	@objc
#endif
	public internal(set) var connectionState = ConnectionState.disconnected

#if canImport(ObjectiveC)
	@objc
#endif
	public let logger: VNCLogger
    
    public let framebufferAllocator: VNCFramebufferAllocator?

	// MARK: - Private Properties
	private let queue = DispatchQueue(label: "com.royalapps.royalvnc.connectionqueue",
									  attributes: .concurrent)

	private let sharedZStream: ZlibStream
    private let sharedZRLEZStream: ZlibStream

	// MARK: - Internal Properties
    let taskPriority = TaskPriority.high

	var receiveTask: Task<(), Error>?
	var sendTask: Task<(), Error>?

	/// HP-only: the Apple control-channel receive loop task (record-framed; replaces the standard
	/// framebuffer receive loop on the HP path). `nil` on the standard path. Exits on the shared
	/// `state.disconnectRequested` flag like `receiveTask`/`sendTask`.
	var appleControlTask: Task<(), Error>?

	/// HP-only: in-progress reassembly buffer for a multi-record `0x1f` clipboard send (crib §7a).
	/// `nil` when no `0x1f` is mid-reassembly. Touched only by the single control-loop task.
	var appleClipboardReassembly: Data?

	/// HP-only: Apple cursor (`1104`) cache — decoded cursors keyed by the daemon's `cache_id` so a
	/// later cache-hit rect (`comp_size == 0`) can re-apply a shape without re-sending pixels (crib §7b).
	/// Touched only by the single control-loop task.
	var appleCursorCache: [UInt32: VNCCursor] = [:]

	/// Insertion order of `appleCursorCache` keys, for deterministic FIFO eviction (Swift dictionary key
	/// order is hash-randomized, so evicting `keys.first` could drop a still-live shape → stale OS arrow).
	var appleCursorCacheOrder: [UInt32] = []

	// T1: guards the fields that Change A/B make genuinely cross-task (the receive loop, the send loop,
	// the main-thread quality API, and the one-shot watchdog task all touch them). This is the SOLE
	// access path for `state.areContinuousUpdatesEnabled`, `state.optimisticCUActive`,
	// `state.framebufferUpdateCount`, and `continuousUpdatesWatchdogTask`
	// (see VNCConnection+ContinuousUpdatesWatchdog.swift for the accessors).
	let stateLock = NSLock()
	var continuousUpdatesWatchdogTask: Task<Void, Never>?
	/// Latched (under stateLock) the first time the watchdog is cancelled — including by
	/// beginDisconnecting. Ensures a watchdog whose arm() loses the race against a concurrent
	/// disconnect (cancel runs before the task is stored) is still torn down, never outliving the
	/// connection. VNCConnection is single-use per connect, so a permanent latch is correct.
	var continuousUpdatesWatchdogTornDown = false

	let maxSupportedProtocolVersion = VNCProtocol.ProtocolVersion(majorVersion: 3,
																  minorVersion: 8)

	let state = State()
	let systemSound = VNCSystemSound()

	let clipboard: VNCClipboard
	let clipboardMonitor: VNCClipboardMonitor

	var clientToServerMessageQueue = Queue<VNCSendableMessage>()

    var mouseButtonState: VNCProtocol.MousePointerButton = [ ]

    // HP-SPECS §4.2: an existential (`any`) rather than an opaque `some`, so the HP path can wrap the
    // base in `AppleRecordLayerConnection` while the standard path stays the bare base type. When HP is
    // OFF the returned object IS the bare base — byte-identical to before (AC-5); the record-layer
    // decorator is never inserted. R5 throughput gate (AC-7, <2% regression) is checked at validation.
    lazy var connection: any NetworkConnection = {
        let connectionSettings = NetworkConnectionSettings(connectionTimeout: 15,
                                                           host: settings.hostname,
                                                           port: settings.port)

        // NOTE: To test SocketNetworkConnection on Darwin (macOS, iOS, etc.), comment out the the #if
#if canImport(Network)
        let base = NWConnection(settings: connectionSettings)
#else
		let base = SocketNetworkConnection(settings: connectionSettings)
#endif

        let connection: any NetworkConnection
        if settings.enableHighPerformance {
            // Wrap in passthrough mode at creation; the handshake flips it to CBC after the 0x44f rekey.
            connection = AppleRecordLayerConnection(base: base)
        } else {
            connection = base
        }

        connection.setStatusUpdateHandler(connectionStatusDidChange)

		return connection
	}()

	/// Transient holder for the record-layer wrap key derived by the HP RSA-SRP auth (HP-SPECS §5.2),
	/// carried from auth to the point where the `0x44f` rekey is read and the record layer is armed.
	/// Cleared immediately after arming (NFR-6). `nil` on the standard path.
	var appleHPWrapKey: Data?

	/// Per-session HP media negotiation state (SRTP master blobs + send-SSRCs + negotiated canvas),
	/// set by `performHighPerformanceMediaOffer` and retained for the SRTP/UDP receive step. Blobs
	/// are never logged (NFR-6). `nil` on the standard path / before media negotiation.
	var appleHPMediaContext: AppleHPMediaContext?

#if canImport(Network)
	/// The background HP media receiver (UDP video → SRTP decrypt → RTP log + RTCP keep-alive),
	/// retained for the life of the connection and torn down in `beginDisconnecting` (NFR-5).
	/// `nil` on the standard path.
	var appleHPMediaReceiver: MediaReceiver?

	/// Whether a background HP media session is active (platform-safe accessor for logging/wiring).
	var appleHPMediaReceiverActive: Bool { appleHPMediaReceiver != nil }
#else
	/// No media receiver on non-Network platforms (control-channel HP still runs).
	var appleHPMediaReceiverActive: Bool { false }
#endif

	lazy var encodings: Encodings = {
		let rawEncoding = VNCProtocol.RawEncoding()
		let hextileEncoding = VNCProtocol.HextileEncoding(rawEncoding: rawEncoding)

		let compressionLevelEncodingType = VNCPseudoEncodingType.compressionLevel6.rawValue
		let compressionLevelEncoding = VNCProtocol.CompressionLevelEncoding(encodingType: compressionLevelEncodingType)

		let jpegQualityLevelEncodingType = VNCPseudoEncodingType.jpegQualityLevel6.rawValue
		let jpegQualityLevelEncoding = VNCProtocol.JPEGQualityLevelEncoding(encodingType: jpegQualityLevelEncodingType)

		var encs: Encodings = [
			// Frame Encodings
			VNCFrameEncodingType.copyRect.rawValue: VNCProtocol.CopyRectEncoding(),
            VNCFrameEncodingType.tight.rawValue: VNCProtocol.TightEncoding(),
            VNCFrameEncodingType.zlib.rawValue: VNCProtocol.ZlibEncoding(zStream: sharedZStream),
			VNCFrameEncodingType.zrle.rawValue: VNCProtocol.ZRLEEncoding(zStream: sharedZRLEZStream),
			VNCFrameEncodingType.hextile.rawValue: hextileEncoding,
			VNCFrameEncodingType.coRRE.rawValue: VNCProtocol.RREEncoding(),
			VNCFrameEncodingType.rre.rawValue: VNCProtocol.RREEncoding(),
			VNCFrameEncodingType.raw.rawValue: rawEncoding,

			// Pseudo Encodings
			VNCPseudoEncodingType.lastRect.rawValue: VNCProtocol.LastRectEncoding(),
			VNCPseudoEncodingType.continuousUpdates.rawValue: VNCProtocol.ContinuousUpdatesEncoding(),
			VNCPseudoEncodingType.extendedDesktopSize.rawValue: VNCProtocol.ExtendedDesktopSizeEncoding(),
			VNCPseudoEncodingType.desktopSize.rawValue: VNCProtocol.DesktopSizeEncoding(),
			VNCPseudoEncodingType.desktopName.rawValue: VNCProtocol.DesktopNameEncoding(),
			VNCPseudoEncodingType.cursor.rawValue: VNCProtocol.CursorEncoding(),
			compressionLevelEncodingType: compressionLevelEncoding,
			jpegQualityLevelEncodingType: jpegQualityLevelEncoding
		]

		// NOTE (HP): Apple's control-channel pseudo-encodings (cursor 1104, display-layout 0x451, config
		// blobs) are NOT registered here — the HP path does not run the standard framebuffer decoder.
		// They are parsed in-memory, record-framed, by `VNCConnection+AppleControl` (crib §7), which is
		// the only way to survive unknown-length Apple encodings without desyncing.

		// Sanity Check
		do {
			let encodingTypes = encs.values.map({ $0.encodingType })

			try encodingTypes.validate()
		} catch {
            // If the sanity check fails here, it's a programming error
			fatalError(error.debugDescription)
		}

		return encs
	}()

	func orderedEncodingTypes() throws -> [VNCEncodingType] {
		// Frame Encodings (Required)
		var encs: [VNCEncodingType] = [
			VNCFrameEncodingType.copyRect.rawValue
		]

		// Frame Encodings (Customizable; seeded from Settings.frameEncodings, runtime-adjustable
		// via VNCConnection.updateQuality(frameEncodings:)).
		var customizedFrameEncodings = state.frameEncodings.map({ $0.rawValue })

		// TODO: Remove once we support ZRLE for non-24-bit pixel formats
		if let pixelFormat = state.pixelFormat,
		   customizedFrameEncodings.contains(VNCFrameEncodingType.zrle.rawValue),
		   !VNCProtocol.ZRLEEncoding.supportsPixelFormat(pixelFormat) {
			customizedFrameEncodings.removeAll(where: { $0 == VNCFrameEncodingType.zrle.rawValue })
		}

		if let pixelFormat = state.pixelFormat,
		   customizedFrameEncodings.contains(VNCFrameEncodingType.tight.rawValue),
		   !VNCProtocol.TightEncoding.supportsPixelFormat(pixelFormat) {
			customizedFrameEncodings.removeAll(where: { $0 == VNCFrameEncodingType.tight.rawValue })
		}

		let usesTightEncoding = customizedFrameEncodings.contains(VNCFrameEncodingType.tight.rawValue)

		encs.append(contentsOf: customizedFrameEncodings)

		// Frame Encodings (Required)
		encs.append(VNCFrameEncodingType.raw.rawValue)

		// Pseudo Encodings
		encs.append(contentsOf: [
			VNCPseudoEncodingType.lastRect.rawValue,
			VNCPseudoEncodingType.continuousUpdates.rawValue,
			VNCPseudoEncodingType.extendedDesktopSize.rawValue,
			VNCPseudoEncodingType.desktopSize.rawValue,
			VNCPseudoEncodingType.desktopName.rawValue,
			VNCPseudoEncodingType.cursor.rawValue,
			// TODO: Implement
//			VNCPseudoEncodingType.extendedClipboard.rawValue,
		])

		// Compression level (configurable; seeded from Settings.compressionLevel, runtime-adjustable
		// via VNCConnection.updateQuality). `disabled` advertises no compression pseudo-encoding.
		if let compressionLevelEncoding = state.compressionLevel.pseudoEncodingType {
			encs.append(compressionLevelEncoding.rawValue)
		}

		// JPEG quality only applies to Tight encoding (configurable; seeded from
		// Settings.jpegQualityLevel, runtime-adjustable). `disabled` advertises no JPEG pseudo-encoding.
		if usesTightEncoding,
		   let jpegQualityLevelEncoding = state.jpegQualityLevel.pseudoEncodingType {
			encs.append(jpegQualityLevelEncoding.rawValue)
		}

		let uniqueEncs = encs.uniqued()

		// Sanity Check
        // If the sanity check fails here, it could be a programming error, but it could also be an error by the SDK user if he/she specified encodings with invalid values in settings. So we bubble the error up but don't crash.
		try uniqueEncs.validate()

		return uniqueEncs
	}

	// MARK: - Public Initializers
    public init(settings: Settings,
                logger: VNCLogger,
                framebufferAllocator: VNCFramebufferAllocator?,
                context: UnsafeMutableRawPointer?) {
        self.settings = settings

        logger.isDebugLoggingEnabled = settings.isDebugLoggingEnabled

        self.logger = logger
        self.context = context
        
        self.sharedZStream = .init()
        self.sharedZRLEZStream = .init()

        let clipboard = VNCClipboard()

        let clipboardMonitor = VNCClipboardMonitor(clipboard: clipboard,
                                                   monitoringInterval: 0.5,
                                                   tolerance: 0.15)

        self.clipboard = clipboard
        self.clipboardMonitor = clipboardMonitor
        self.framebufferAllocator = framebufferAllocator

        super.init()

        // Seed runtime-adjustable quality state from Settings.
        self.state.jpegQualityLevel = settings.jpegQualityLevel
        self.state.compressionLevel = settings.compressionLevel
        self.state.wantsContinuousUpdates = settings.useContinuousUpdates
        self.state.wantsOptimisticContinuousUpdates = settings.useOptimisticContinuousUpdates
        self.state.frameEncodings = settings.frameEncodings

        self.clipboardMonitor.delegate = self
    }

#if canImport(ObjectiveC)
	@objc
#endif
    public convenience init(settings: Settings,
                            logger: VNCLogger) {
        self.init(settings: settings,
                  logger: logger,
                  framebufferAllocator: nil,
                  context: nil)
	}

#if canImport(ObjectiveC)
	@objc
#endif
	public convenience init(settings: Settings) {
        self.init(settings: settings,
                  context: nil)
	}
    
    public convenience init(settings: Settings,
                            framebufferAllocator: VNCFramebufferAllocator?) {
        self.init(settings: settings,
                  framebufferAllocator: framebufferAllocator,
                  context: nil)
    }

    public convenience init(settings: Settings,
                            framebufferAllocator: VNCFramebufferAllocator?,
                            context: UnsafeMutableRawPointer?) {
#if canImport(OSLog)
        let logger = VNCOSLogLogger()
#else
        let logger = VNCPrintLogger()
#endif

        self.init(settings: settings,
                  logger: logger,
                  framebufferAllocator: framebufferAllocator,
                  context: context)
    }
    
    public convenience init(settings: Settings,
                            context: UnsafeMutableRawPointer?) {
        self.init(settings: settings,
                  framebufferAllocator: nil,
                  context: context)
    }

	deinit {
		let _self = self

		_self.clipboardMonitor.delegate = nil

		stopMonitoringClipboard()
	}
}

// MARK: - Internal Connection State API
extension VNCConnection {
	func beginConnecting() {
		updateConnectionState(.connecting)

		if settings.enableHighPerformance {
			// HP-SPECS §14: run Apple's two-TCP warmup BEFORE the real session TCP. Dispatched on the
			// connection queue so the ~1.4s dwell never blocks the caller (UI) thread; the connection
			// isn't started until the warmup returns.
			queue.async { [weak self] in
				guard let self else { return }

				self.performAppleTwoTCPWarmup()
				self.connection.start(queue: self.queue)
			}
		} else {
			connection.start(queue: queue)
		}
	}

	func beginDisconnecting(error: Error? = nil) {
		guard !state.disconnectRequested else { return }

		state.disconnectRequested = true
		updateConnectionState(.disconnecting)

		connection.setStatusUpdateHandler(nil)
		connection.cancel()

#if canImport(Network)
		// Tear down the HP media session (UDP sockets, NAT-prime, RTCP loop) — NFR-5.
		appleHPMediaReceiver?.cancel()
		appleHPMediaReceiver = nil
#endif

		// T1 Change A: the optimistic-CU watchdog must never outlive the connection. The helper is
		// lock-guarded, so cancelling here (from main / receive / send) is safe.
		cancelContinuousUpdatesWatchdog()

		if let error = error {
			updateConnectionState(.disconnected(error: error))
		} else {
			updateConnectionState(.disconnected)
		}
	}

	func handleBreakingError(_ error: Error) {
		beginDisconnecting(error: error)
	}

	func updateConnectionState(_ newConnectionState: ConnectionState) {
		self.connectionState = newConnectionState

		switch newConnectionState.status {
			case .connecting:
				break

			case .connected:
				startMonitoringClipboard()

			case .disconnecting:
				stopMonitoringClipboard()

			case .disconnected:
				stopMonitoringClipboard()
		}

		notifyDelegateAboutConnectionStateChange(newConnectionState)
	}
}

// MARK: - Connection State Change Handling
private extension VNCConnection {
	func connectionStatusDidChange(_ newState: NetworkConnectionStatus) {
		switch newState {
			case .setup:
				logger.logDebug("Connection State - Setup")

			case .preparing:
				logger.logDebug("Connection State - Preparing")

			case .ready:
				logger.logDebug("Connection State - Ready")

				connectionDidBecomeReady()

			case .waiting(let error):
				logger.logDebug("Connection State - Waiting with error: \(error)")

				connectionDidFail(error: .connection(.failed(error)))

			case .failed(let error):
				logger.logDebug("Connection State - Failed with error: \(error)")

				connectionDidFail(error: .connection(.failed(error)))

			case .cancelled:
				logger.logDebug("Connection State - Cancelled")

				connectionDidFail(error: .connection(.cancelled))

            case .unknown(let underlyingState):
				logger.logDebug("Connection State - Unknown (\(underlyingState))")
		}
	}

	func connectionDidBecomeReady() {
		Task {
			do {
				try await handshake()

				// HP path: on TCP the daemon speaks only Apple control (cursor 1104 / layout 0x451 / config
				// blobs inside 0x00 FBUs, plus clipboard 0x14/0x1f) — real pixels flow over UDP/SRTP. Run
				// the record-framed Apple control loop instead of the standard framebuffer decode loop (which
				// can't survive Apple pseudo-encodings), plus the send loop for clipboard bring-up + outbound.
				// The background media receiver (if negotiated during the handshake) streams UDP in parallel,
				// so ONE HP session carries media (UDP) AND control/clipboard (TCP) together.
				if settings.enableHighPerformance {
					logger.logDebug("[hp] connected — starting Apple control loop + send loop (media receiver active: \(appleHPMediaReceiverActive))")
					updateConnectionState(.connected)
					startAppleControlLoop()
					startSendLoop()
					return
				}

				// T1 Change A: in optimistic mode, enable Continuous Updates WITHOUT the support guard
				// and WITHOUT an initial polling request — the enable region solicits the first frame,
				// and a server that ignores msg 150 leaves framebufferUpdateCount at 0 so the watchdog
				// reverts to polling. (`wantsOptimisticContinuousUpdates` is set once in init and never
				// mutated, so this read is race-free.)
				if state.wantsOptimisticContinuousUpdates {
					try await sendOptimisticEnableContinuousUpdates()
				} else {
					try await sendFramebufferUpdateRequest()
				}
			} catch {
				handleBreakingError(error)

                return
			}

			updateConnectionState(.connected)

			startReceiveLoop()
			startSendLoop()

			stateLock.lock()
			let armWatchdog = state.optimisticCUActive
			stateLock.unlock()
			if armWatchdog { armContinuousUpdatesWatchdog() }
		}
	}

	func connectionDidFail(error: VNCError) {
		handleBreakingError(error)
	}
}
