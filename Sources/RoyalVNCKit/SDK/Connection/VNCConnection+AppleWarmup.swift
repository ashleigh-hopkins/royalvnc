#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Darwin)
import Darwin
#endif

// Apple High-Performance two-TCP warmup (HP-SPECS §14, live-confirmed).
//
// Apple screensharingd requires a first "warmup" TCP that completes ONLY the version-banner +
// security-types exchange, is held ~1.4s, then closed — this registers the session with the daemon
// so the real session TCP is not torn down right after the RSA1 init. This is HP-only (Apple hosts on
// RFB 003.889) and a no-op off Darwin; the standard-RFB path never calls it.
extension VNCConnection {
    /// Dwell (seconds) the warmup TCP is held open after the banner exchange (reference ~1.4s).
    static let appleWarmupDwellSeconds: Double = 1.4

    /// Run the two-TCP warmup synchronously on the connection queue (called before `connection.start`
    /// when HP is enabled). Best-effort: any failure is logged and ignored (the real connection still
    /// attempts). Never touches the main `VNCConnection.connection`; uses a throwaway raw socket.
    func performAppleTwoTCPWarmup() {
#if canImport(Darwin)
        let host = settings.hostname
        let port = settings.port

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP

        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let info = res else {
            logger.logDebug("[hp-warmup] getaddrinfo failed; continuing without warmup")
            return
        }
        defer { freeaddrinfo(res) }

        let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        guard fd >= 0 else {
            logger.logDebug("[hp-warmup] socket() failed; continuing without warmup")
            return
        }
        defer { close(fd) }

        // `Darwin.connect` — unqualified `connect` resolves to `VNCConnection.connect()`.
        guard Darwin.connect(fd, info.pointee.ai_addr, info.pointee.ai_addrlen) == 0 else {
            logger.logDebug("[hp-warmup] connect failed; continuing without warmup")
            return
        }

        func recvExact(_ count: Int) -> [UInt8] {
            var buffer = [UInt8](repeating: 0, count: count)
            var total = 0
            buffer.withUnsafeMutableBytes { raw in
                while total < count {
                    let n = recv(fd, raw.baseAddress!.advanced(by: total), count - total, 0)
                    if n <= 0 { break }
                    total += n
                }
            }
            return Array(buffer.prefix(total))
        }

        // Version-banner exchange only.
        let banner = recvExact(12)
        guard banner.count == 12 else {
            logger.logDebug("[hp-warmup] short banner (\(banner.count)); continuing without warmup")
            return
        }
        let version = Array("RFB 003.889\n".utf8)
        _ = version.withUnsafeBytes { send(fd, $0.baseAddress, version.count, 0) }

        let typeCount = recvExact(1)
        if let count = typeCount.first, count > 0 {
            _ = recvExact(Int(count))   // read + discard the security-types list
        }

        logger.logDebug("[hp-warmup] banner exchanged; holding TCP#1 \(Self.appleWarmupDwellSeconds)s then closing")
        usleep(useconds_t(Self.appleWarmupDwellSeconds * 1_000_000))
        // TCP#1 closed by `defer { close(fd) }`.
#else
        logger.logDebug("[hp-warmup] skipped (non-Darwin platform)")
#endif
    }
}
