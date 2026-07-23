#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Shared hex <-> `Data` helpers for the Apple HP crypto seam tests. Kept in one place so the
/// per-seam test files don't each redefine the conversion (DRY).
enum Hex {
    /// Decode a hex string (even length, no separators) into `Data`. Traps on malformed input,
    /// which is acceptable for test-embedded known-answer vectors.
    static func data(_ string: String) -> Data {
        precondition(string.count % 2 == 0, "hex string must have even length")

        var bytes = [UInt8]()
        bytes.reserveCapacity(string.count / 2)

        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<next], radix: 16) else {
                preconditionFailure("invalid hex byte: \(string[index..<next])")
            }
            bytes.append(byte)
            index = next
        }

        return Data(bytes)
    }

    /// Lowercase hex encoding, for readable assertion failure messages.
    static func string(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
