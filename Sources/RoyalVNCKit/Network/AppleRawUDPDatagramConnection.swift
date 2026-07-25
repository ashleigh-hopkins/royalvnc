#if canImport(Network)
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch
#if canImport(Darwin)
import Darwin
#endif

/// Raw BSD `SOCK_DGRAM` datagram endpoint for the Apple HP video receive path (HP-PHASE4-SPECS §5.5 R2
/// fallback). Drop-in for `AppleUDPDatagramConnection` for the high-bitrate VIDEO socket: same public
/// surface (`start`/`send`/`startNATPrime`/`cancel`/`localPort`), but the receive side is a raw kernel
/// socket with a large `SO_RCVBUF` drained by a dedicated `.userInteractive` thread in a tight blocking
/// `recv()` loop.
///
/// WHY (measured on device, iPhone 16 Pro Max / A18, LAN WiFi, FMV): NWConnection's UDP `receiveMessage`
/// stalls internally ~200–300 ms under the HP packet rate (~2000 pkt/s) — independent of queue QoS and
/// with the worker ~85% idle — so the kernel UDP buffer overflows and the high-bitrate tiles lose >50%
/// of their packets in burst drops (a single 1583-packet gap was observed after a 294 ms stall). A raw
/// socket bypasses that machinery; a multi-MB `SO_RCVBUF` absorbs any residual stall (8 MB ≈ ~3 s of
/// buffering at this rate) so datagrams are not dropped before we read them.
///
/// Connected UDP: `bind()` local `localPort`, `connect()` to `host:remotePort` (the daemon streams
/// symmetrically from its `remotePort` back to our `localPort`), so `recv()`/`send()` need no per-call
/// address. IPv4-forced to match the TCP + ctrl family (NFR-7). Resource-safe (NFR-5): `cancel()` closes
/// the fd (which unblocks + ends the recv thread) and stops the NAT-prime timer; also on `deinit`.
final class AppleRawUDPDatagramConnection {
    let localPort: UInt16
    let label: String
    private let host: String
    private let remotePort: UInt16

    private var fd: Int32 = -1
    private var recvThread: Thread?
    private var running = false
    private var primeTimer: DispatchSourceTimer?
    private let primeQueue = DispatchQueue(label: "hp.rawudp.prime")
    private var onDatagram: ((Data) -> Void)?

    /// Requested kernel receive buffer. The OS clamps to `kern.ipc.maxsockbuf`; the actual value is read
    /// back and reported via `onState`. Even a clamped few-MB buffer dwarfs the ~256 KB default.
    private static let desiredRcvBuf: Int32 = 8 * 1024 * 1024

    init(host: String, remotePort: UInt16, localPort: UInt16, label: String) {
        self.host = host
        self.remotePort = remotePort
        self.localPort = localPort
        self.label = label
    }

    deinit { cancel() }

    /// Create + bind + connect the socket and start draining it on a dedicated high-QoS thread.
    /// `onState` reports readiness (incl. the negotiated `SO_RCVBUF`) or the failing syscall (for logging).
    func start(onDatagram: @escaping (Data) -> Void, onState: @escaping (String) -> Void) {
        self.onDatagram = onDatagram

        let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard s >= 0 else { onState("socket() failed errno=\(errno)"); return }

        var yes: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &yes, socklen_t(MemoryLayout<Int32>.size))
        var rcv = Self.desiredRcvBuf
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcv, socklen_t(MemoryLayout<Int32>.size))
        var actualRcv: Int32 = 0
        var actualLen = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(s, SOL_SOCKET, SO_RCVBUF, &actualRcv, &actualLen)

        // Bind INADDR_ANY:localPort.
        var local = sockaddr_in()
        local.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        local.sin_family = sa_family_t(AF_INET)
        local.sin_port = localPort.bigEndian
        local.sin_addr.s_addr = INADDR_ANY
        let bindRC = withUnsafePointer(to: &local) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRC == 0 else { onState("bind(\(localPort)) failed errno=\(errno)"); close(s); return }

        // Resolve + connect to host:remotePort (IPv4). inet_pton for a dotted IP; getaddrinfo for a name.
        var remote = sockaddr_in()
        remote.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        remote.sin_family = sa_family_t(AF_INET)
        remote.sin_port = remotePort.bigEndian
        if inet_pton(AF_INET, host, &remote.sin_addr) != 1 {
            var hints = addrinfo()
            hints.ai_family = AF_INET
            hints.ai_socktype = SOCK_DGRAM
            var res: UnsafeMutablePointer<addrinfo>?
            if getaddrinfo(host, String(remotePort), &hints, &res) == 0, let info = res,
               let sa = info.pointee.ai_addr {
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { remote.sin_addr = $0.pointee.sin_addr }
                freeaddrinfo(res)
            } else {
                onState("resolve(\(host)) failed errno=\(errno)"); close(s); return
            }
        }
        let connRC = withUnsafePointer(to: &remote) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connRC == 0 else { onState("connect(\(host):\(remotePort)) failed errno=\(errno)"); close(s); return }

        fd = s
        running = true
        onState("ready (SO_RCVBUF=\(actualRcv))")

        let t = Thread { [weak self] in self?.recvLoop() }
        t.name = "hp.rawudp.\(label).\(localPort)"
        t.qualityOfService = .userInteractive
        recvThread = t
        t.start()
    }

    /// Dedicated blocking `recv()` loop. The kernel buffers up to `SO_RCVBUF`, so a transient slow consumer
    /// no longer drops datagrams. Delivers each datagram to `onDatagram` on this (single) thread.
    private func recvLoop() {
        let cap = 65535
        let buf = UnsafeMutableRawPointer.allocate(byteCount: cap, alignment: 1)
        defer { buf.deallocate() }
        while running {
            let n = recv(fd, buf, cap, 0)
            if n > 0 {
                onDatagram?(Data(bytes: buf, count: n))
            } else if n < 0 {
                if errno == EINTR { continue }
                break   // fd closed by cancel() or a fatal error → end the loop
            }
        }
    }

    /// Send one datagram to the connected peer (NAT-prime punch).
    func send(_ data: Data) {
        guard fd >= 0 else { return }
        data.withUnsafeBytes { raw in
            if let base = raw.baseAddress, raw.count > 0 { _ = Darwin.send(fd, base, raw.count, 0) }
        }
    }

    /// Start the 100 ms 1-byte `\x00` NAT-prime loop (crib §4b) out this socket.
    func startNATPrime(intervalMS: Int = 100) {
        let timer = DispatchSource.makeTimerSource(queue: primeQueue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(intervalMS))
        timer.setEventHandler { [weak self] in self?.send(Data([0x00])) }
        primeTimer = timer
        timer.resume()
    }

    func cancel() {
        running = false
        primeTimer?.cancel()
        primeTimer = nil
        if fd >= 0 { close(fd); fd = -1 }   // unblocks the recv() → recvLoop ends
    }
}
#endif
