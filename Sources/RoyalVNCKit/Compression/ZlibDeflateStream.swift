#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import Z

/// One-shot zlib **deflate** stream (companion to `ZlibInflateStream`).
///
/// The only compressing producer in the client: Apple's clipboard `0x1f`
/// ClipboardSend (§ AppleClipboardCodec) carries a `Z_SYNC_FLUSH`-framed zlib
/// stream of a pasteboard archive. `deflateInit_` with the default `windowBits`
/// (15) emits a zlib-wrapped stream (`78 9c …`) matching what screensharingd
/// accepts inbound. A `Z_SYNC_FLUSH` terminates the stream with the `00 00 ff ff`
/// empty-stored-block marker and no final `BFINAL`/Adler end — the exact framing
/// the daemon uses for its own `0x1f` sends.
final class ZlibDeflateStream {
	private let streamPtr: UnsafeMutablePointer<z_stream>

	init(level: Int32 = Z_DEFAULT_COMPRESSION) throws {
		let streamPtr = UnsafeMutablePointer<z_stream>.allocate(capacity: 1)

		streamPtr.pointee.total_out = 0
		streamPtr.pointee.zalloc = nil
		streamPtr.pointee.zfree = nil
		streamPtr.pointee.opaque = nil

		var version = ZLIB_VERSION
		var status = Z_VERSION_ERROR

		withUnsafeMutablePointer(to: &version) { versionPtr in
			status = deflateInit_(streamPtr, level, versionPtr, .init(MemoryLayout<z_stream>.size))
		}

		guard status == Z_OK else {
			streamPtr.deallocate()
			throw Self.mapError(status: status, message: nil)
		}

		self.streamPtr = streamPtr
	}

	deinit {
		Z.deflateEnd(streamPtr)
		streamPtr.deallocate()
	}

	/// Compress `data` in one shot, flushing everything with `Z_SYNC_FLUSH`.
	/// Returns the zlib stream bytes (header + deflate blocks + `00 00 ff ff`).
	func compressedData(data: Data, flush: ZlibFlush = .syncFlush) throws -> Data {
		let streamPtr = self.streamPtr
		var input = data
		let inputSize = input.count

		var output = Data()
		// deflateBound-ish headroom; input is small (clipboard text). +64 covers
		// the zlib header, block overhead and the sync-flush marker for empty input.
		let bufferSize = inputSize + (inputSize / 2) + 128
		let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)

		defer { buffer.deallocate() }

		try input.withUnsafeMutableBytes { (inputPtr: UnsafeMutableRawBufferPointer) in
			streamPtr.pointee.next_in = inputSize > 0
				? inputPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
				: nil
			streamPtr.pointee.avail_in = .init(inputSize)

			// Keep deflating for this flush until the output buffer is no longer
			// completely filled (canonical "flush is complete" signal).
			while true {
				streamPtr.pointee.next_out = buffer
				streamPtr.pointee.avail_out = .init(bufferSize)

				let status = Z.deflate(streamPtr, flush.rawValue)
				guard status == Z_OK || status == Z_STREAM_END || status == Z_BUF_ERROR else {
					throw Self.mapError(status: status, message: Self.errorMessage(streamPtr: streamPtr))
				}

				let produced = bufferSize - Int(streamPtr.pointee.avail_out)
				if produced > 0 {
					output.append(buffer, count: produced)
				}

				if streamPtr.pointee.avail_out != 0 || status == Z_STREAM_END {
					break
				}
			}
		}

		return output
	}

	private static func errorMessage(streamPtr: UnsafePointer<z_stream>) -> String? {
		guard let msg = streamPtr.pointee.msg else { return nil }
		return String(cString: msg)
	}

	private static func mapError(status: Int32, message: String?) -> ZlibError {
		switch status {
			case Z_STREAM_ERROR: return .streamError(message: message)
			case Z_DATA_ERROR: return .dataError(message: message)
			case Z_MEM_ERROR: return .memoryError(message: message)
			case Z_BUF_ERROR: return .bufferError(message: message)
			case Z_VERSION_ERROR: return .versionError(message: message)
			default: return .unknown(status: status, message: message)
		}
	}
}
