#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Apple HP pseudo-encodings pushed over the type-33 control channel that the standard framebuffer
/// decoder doesn't know (HP-PHASE4). Registered only on the HP path. These consume the rect body so
/// the receive loop survives to reach the clipboard / control messages; full rendering (cursor
/// shape, display geometry) is Phase 5.
///
/// `apple1105` (0x451) AppleDisplayLayout: **HYPOTHESIS (pending reference confirmation)** that the
/// wire body matches the standard ExtendedDesktopSize — `numberOfScreens: u8`, 3 pad bytes, then
/// `numberOfScreens × Screen(16 B)`. Live it parsed cleanly (0 screens, w=h=0) and the loop advanced
/// past it — but with 0 screens only 4 bytes were consumed, so this is not yet proven byte-exact
/// against a multi-screen layout; confirm against the iShareScreen reference (rfb.py/session.py).
extension VNCProtocol {
    struct AppleDisplayLayoutEncoding: VNCReceivablePseudoEncoding {
        let encodingType: VNCEncodingType = 1105   // 0x451

        func receive(_ rectangle: VNCProtocol.Rectangle,
                     framebuffer: VNCFramebuffer,
                     connection: NetworkConnectionReading,
                     logger: VNCLogger) async throws {
            let numberOfScreens = try await connection.readUInt8()
            try await connection.readPadding(length: 3)
            for _ in 0..<numberOfScreens {
                _ = try await VNCProtocol.Screen.receive(connection: connection)
            }
            logger.logDebug("[hp-enc] consumed 0x451 AppleDisplayLayout (\(rectangle.width)x\(rectangle.height), \(numberOfScreens) screens)")
        }
    }
}
