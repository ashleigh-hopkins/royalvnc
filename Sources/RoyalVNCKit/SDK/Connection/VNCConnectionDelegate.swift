#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(ObjectiveC)
@objc(VNCConnectionDelegate)
#endif
public protocol VNCConnectionDelegate: AnyObject {
#if canImport(ObjectiveC)
    @objc
#endif
	func connection(_ connection: VNCConnection,
					stateDidChange connectionState: VNCConnection.ConnectionState)

#if canImport(ObjectiveC)
    @objc
#endif
	func connection(_ connection: VNCConnection,
					credentialFor authenticationType: VNCAuthenticationType,
					completion: @escaping (_ credential: VNCCredential?) -> Void)

#if canImport(ObjectiveC)
    @objc
#endif
	func connection(_ connection: VNCConnection,
					didCreateFramebuffer framebuffer: VNCFramebuffer)

#if canImport(ObjectiveC)
    @objc
#endif
	func connection(_ connection: VNCConnection,
					didResizeFramebuffer framebuffer: VNCFramebuffer)

#if canImport(ObjectiveC)
    @objc
#endif
    func connection(_ connection: VNCConnection,
                    didUpdateFramebuffer framebuffer: VNCFramebuffer,
                    x: UInt16, y: UInt16,
                    width: UInt16, height: UInt16)

#if canImport(ObjectiveC)
    @objc
#endif
	func connection(_ connection: VNCConnection,
					didUpdateCursor cursor: VNCCursor)

	// Fired on the connection queue when the server sends clipboard (cut) text and
	// clipboard redirection is enabled. Optional so existing conformers (the C SDK
	// bridge, the demo app) compile unchanged; text-only, matching the RFB ClientCutText/
	// ServerCutText messages RoyalVNCKit supports.
#if canImport(ObjectiveC)
    @objc optional
	func connection(_ connection: VNCConnection,
					didReceiveServerCutText text: String)
#endif
}
