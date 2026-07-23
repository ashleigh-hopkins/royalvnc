#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol.ARDAuthentication {
	struct DiffieHellmanKeyAgreement {
		let publicKey: Data
		let privateKey: Data
		let secretKey: Data

		init?(prime: Data,
			  generator: Data,
			  peerKey: Data,
			  keyLength: Int) {
			guard keyLength > 0 else {
				return nil
			}

			guard let keyPair = Self.generateKeyPair(generator: generator,
													 prime: prime,
													 keyLength: keyLength),
				  !keyPair.privateKey.isEmpty,
				  !keyPair.publicKey.isEmpty else {
				return nil
			}

			guard let secretKey = Self.computeSharedKey(prime: prime,
														peerKey: peerKey,
														privateKey: keyPair.privateKey),
				  !secretKey.isEmpty else {
				return nil
			}

			self.publicKey = keyPair.publicKey
			self.privateKey = keyPair.privateKey
			self.secretKey = secretKey
		}
	}
}

private extension VNCProtocol.ARDAuthentication.DiffieHellmanKeyAgreement {
	struct KeyPair {
		let publicKey: Data
		let privateKey: Data
	}

	// Short DH exponent width (bits). A full keyLength*8-bit (e.g. 4096-bit) private exponent makes
	// the pure-Swift modular exponentiation take ~10s per modexp on-device in a -Onone build (two
	// modexps ≈ ~20s connect stall). A 384-bit ephemeral exponent gives ~192-bit discrete-log
	// security — above the 4096-bit MODP group's own ~150-bit strength and the scheme's AES-128
	// floor (NIST SP 800-56A short exponents) — while cutting the modexp iteration count ~10x.
	static let privateExponentBits = 384

	static func generateKeyPair(generator: Data,
								prime: Data,
								keyLength: Int) -> KeyPair? {
		let bigPrivKey = BigNum()
		let bigPubKey = BigNum()

		guard let bigPrime = BigNum(data: prime),
			  let bigGenerator = BigNum(data: generator) else {
			return nil
		}

		// Generate a short DH private exponent. `rand(exactWidth:)` sets the top bit, so the value
		// is always non-zero and exactly `privateExponentBits` wide — no zero-retry loop needed.
		guard bigPrivKey.rand(exactWidth: privateExponentBits) else {
			return nil
		}

		let modSuccess = BigNum.modExp(y: bigPubKey,
									   g: bigGenerator,
									   x: bigPrivKey,
									   p: bigPrime)

		guard modSuccess else {
			return nil
		}

		guard let privKey = bigPrivKey.bigEndianData(),
			  let pubKeyRaw = bigPubKey.bigEndianData() else {
			return nil
		}

		// The public key (g^x mod p) is transmitted as a fixed-width `keyLength`-byte field, but the
		// big-endian serialization drops leading zero bytes (~1/256 of keys have a zero MSB). Left-pad
		// to keyLength so the server parses the field correctly. (The private key is never sent, so
		// its byte length is irrelevant.)
		let pubKey = Self.leftPad(pubKeyRaw, to: keyLength)

		let keyPair = KeyPair(publicKey: pubKey,
							  privateKey: privKey)

		return keyPair
	}

	/// Left-pads `data` with leading zero bytes to exactly `length` bytes. Returns `data` unchanged
	/// if it is already `length` bytes or longer.
	static func leftPad(_ data: Data, to length: Int) -> Data {
		guard data.count < length else {
			return data
		}

		return Data(count: length - data.count) + data
	}

	static func computeSharedKey(prime: Data,
								 peerKey: Data,
								 privateKey: Data) -> Data? {
		guard let bigPrime = BigNum(data: prime),
			  let bigPrivKey = BigNum(data: privateKey),
			  let bigPeerKey = BigNum(data: peerKey) else {
			return nil
		}

		let bigSharedKey = BigNum()

		let modSuccess = BigNum.modExp(y: bigSharedKey,
									   g: bigPeerKey,
									   x: bigPrivKey,
									   p: bigPrime)

		guard modSuccess else {
			return nil
		}

		guard let sharedKey = bigSharedKey.bigEndianData() else {
			return nil
		}

		return sharedKey
	}
}
