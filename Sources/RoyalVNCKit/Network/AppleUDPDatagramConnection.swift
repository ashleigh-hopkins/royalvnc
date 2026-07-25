#if canImport(Network)
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch
import Network

/// Net-new UDP datagram endpoint for the Apple HP media subsystem (HP-PHASE4-SPECS §4.2 / §5.5,
/// crib §4a-§4b). One instance = one connected-UDP socket bound to a fixed local port (ctrl 5900 /
/// video 5901), IPv4-forced, matching the reference's symmetric-return scheme (host streams from
/// its 5900/5901 back to the client's 5900/5901). Built on Network.framework (`NWConnection` UDP)
/// per D2; if the fixed-local-port bind / symmetric return doesn't hold live, the fallback is a raw
/// `SOCK_DGRAM` wrapper (R2).
///
/// Resource-safe (NFR-5): `cancel()` tears down the connection + the NAT-prime timer; also on deinit.
final class AppleUDPDatagramConnection {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private var primeTimer: DispatchSourceTimer?
    let localPort: UInt16
    let label: String

    /// `receiveMessage` delivers one datagram per callback.
    private var onDatagram: ((Data) -> Void)?

    init(host: String, remotePort: UInt16, localPort: UInt16, label: String) {
        self.localPort = localPort
        self.label = label
        // High QoS: under FMV load the VideoToolbox decode threads + CoreImage composite + main-thread
        // present saturate the cores, and a default-QoS receive queue gets preempted for up to ~120 ms
        // (measured cbMaxMs) → the kernel UDP buffer overflows → heavy loss on the high-bitrate tiles.
        // .userInteractive keeps `receiveMessage` re-arming promptly so datagrams are drained in time.
        self.queue = DispatchQueue(label: "hp.udp.\(label).\(localPort)", qos: .userInteractive)

        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true            // SO_REUSEADDR analog
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.any),
                                                           port: NWEndpoint.Port(rawValue: localPort)!)
        // Force IPv4 so TCP + the two UDP sockets share the family (NFR-7).
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = .v4
        }
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host),
                                           port: NWEndpoint.Port(rawValue: remotePort)!)
        self.connection = NWConnection(to: endpoint, using: params)
    }

    deinit { cancel() }

    /// Start the connection and begin delivering inbound datagrams to `onDatagram`.
    /// `onState` reports readiness/failure (for logging the bind result).
    func start(onDatagram: @escaping (Data) -> Void,
               onState: @escaping (NWConnection.State) -> Void) {
        self.onDatagram = onDatagram
        connection.stateUpdateHandler = { state in onState(state) }
        connection.start(queue: queue)
        receiveLoop()
    }

    private func receiveLoop() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.onDatagram?(data) }
            // Keep receiving unless the connection errored/closed.
            if error == nil { self.receiveLoop() }
        }
    }

    /// Send one datagram to the connected host:port (NAT-prime punch / RTCP TX).
    func send(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    /// Start the 100 ms 1-byte `\x00` NAT-prime loop (crib §4b) out this socket.
    func startNATPrime(intervalMS: Int = 100) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(intervalMS))
        timer.setEventHandler { [weak self] in self?.send(Data([0x00])) }
        primeTimer = timer
        timer.resume()
    }

    func cancel() {
        primeTimer?.cancel()
        primeTimer = nil
        connection.cancel()
    }
}
#endif
