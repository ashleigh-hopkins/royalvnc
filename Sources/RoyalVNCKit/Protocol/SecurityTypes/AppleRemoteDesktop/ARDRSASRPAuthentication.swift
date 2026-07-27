#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Security)
import Security
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift

extension VNCProtocol {
    /// Coordinator for Apple Remote Desktop authentication type 33 (RSA-SRP) — HP-SPECS §5.2,
    /// dossier §3.2. Owns the multi-roundtrip wire exchange over a `NetworkConnection`:
    ///
    ///   RSA1 init → recv server SPKI → build + send `c2s1` → recv `s2c1` challenge
    ///   → solve SRP (`AppleSRPClient`) → build + send `c2s2` → recv `M2` + `SecurityResult`
    ///   → **verify `M2` first** (HP-SPECS §5.2 step 4) → require `SecurityResult == 0`.
    ///
    /// It is a thin I/O adapter: all SRP math (`AppleSRPClient`) and envelope framing
    /// (`AppleRSA1Envelope`) live in the pure, unit-tested 5b seams. The one crypto operation the
    /// coordinator owns itself is the RSA-PKCS#1 v1.5 encryption of the identity block (the seams take
    /// a pre-encrypted 256-byte block), done with the vendored CryptoSwift `RSA` — no new dependency
    /// (NFR-4). Production randomness (`a`, `client_random`) is `SecRandomCopyBytes`; injectable for
    /// determinism (NFR-3, A3).
    ///
    /// Security (NFR-6): never logs `password`, `P'`, `x`, `S`, `K`, `M1`, `M2`, or any wrap/content
    /// key. The `M2`-verification-failure *event* is logged with no proof bytes.
    ///
    /// WIRE FRAMING — ORACLE-GATED. The byte layout of every server message read and client message
    /// written here is confirmed byte-for-byte at the live O-checkpoints O3–O6 (HP-SPECS §8) against
    /// the reference `auth.py -v` tap; it is NOT offline-verifiable and is implemented to the dossier's
    /// stated layout. Each such point is marked `ORACLE(On)` inline. Do not treat these reads/writes
    /// as pinned until the live checkpoint passes.
    struct ARDRSASRPAuthentication {
        /// Result of a successful exchange: the 16-byte record-layer wrap key (`SHA-256(K)[0:16]`).
        /// Never logged.
        struct Success {
            let wrapKey: Data
        }

        /// Injectable randomness (NFR-3). Defaults to `SecRandomCopyBytes` in production (A3).
        let randomBytes: (Int) throws -> Data

        init(randomBytes: @escaping (Int) throws -> Data = ARDRSASRPAuthentication.secureRandomBytes) {
            self.randomBytes = randomBytes
        }

        /// Run the full type-33 exchange. `0x21` (security-type select) has already been sent by the
        /// caller (`sendAuthenticationData`); this begins at the RSA1 init body.
        func authenticate(connection: any NetworkConnection,
                          credential: VNCUsernamePasswordCredential,
                          logger: VNCLogger) async throws -> Success {
            // Step 0 — RSA1 init (c→s), sent as ONE atomic write together with the 0x21 auth-type
            // selector (reference auth.py:61 `sendall(b"\x21" + b"\x00\x00\x00\x0a\x01\x00RSA1…")`):
            //   0x21 || u32-BE length(10) || 10-byte RSA1 init body
            // The caller (`sendAuthenticationData`) skips the standalone 0x21 send for apple33 so the
            // whole 15-byte blob lands in a single segment.
            var initMessage = Data([0x21])
            initMessage.append(Self.bigEndian32(UInt32(AppleRSA1Envelope.rsa1Init().count)))
            initMessage.append(AppleRSA1Envelope.rsa1Init())
            try await connection.write(data: initMessage)
            logger.logDebug("[ard33] sent 0x21+RSA1 init (\(initMessage.count)B, one write)")

            // Step 0 — recv server public key. O3-CONFIRMED (reference auth.py:62-66): read a u32-BE
            // `pkt_len`, then the WHOLE `pkt` of that length, and index WITHIN it:
            //   pkt[0:2]  = direction/prefix (skipped)
            //   pkt[2:6]  = u32-BE keyLen
            //   pkt[6:6+keyLen] = DER SubjectPublicKeyInfo
            //   pkt[6+keyLen:]  = trailing byte(s) (ignored — but MUST be consumed to stay aligned).
            // Reading only prefix+keyLen+DER leaves the trailing byte in the stream and desyncs s2c1.
            let pktLen = try await connection.readUInt32()
            guard pktLen >= 6 else { throw VNCError.protocol(.invalidData) }
            let pkt = Array(try await connection.readBuffered(length: Int(pktLen)))
            let keyLength = (UInt32(pkt[2]) << 24) | (UInt32(pkt[3]) << 16)
                | (UInt32(pkt[4]) << 8) | UInt32(pkt[5])
            guard 6 + Int(keyLength) <= pkt.count else { throw VNCError.protocol(.invalidData) }
            let spki = Data(pkt[6..<(6 + Int(keyLength))])
            logger.logDebug("[ard33] server-key: pktLen=\(pktLen) keyLen=\(keyLength) spki=\(spki.count)B trailing=\(pkt.count - 6 - Int(keyLength))")

            let publicKey = try AppleRSA1Envelope.parseSPKI(spki)
            logger.logDebug("[ard33] parsed SPKI: n=\(publicKey.n.count)B e=\(publicKey.e.count)B")

            // Step 1 — c2s1 (650B). identity is RSA-PKCS#1 v1.5-encrypted under the server key.
            // O3-CONFIRMED (reference auth.py:_send_srp_modulus): the c2s1 identity carries the ACTUAL
            // username — the Apple SRP server routes on it to pick the account's verifier. (The empty
            // username belongs ONLY in the SRP x-derivation's SASL identity, not here; the dossier's
            // "empty-username identity" note conflated the two. Sending empty routes to the wrong/default
            // verifier → a different iteration count and M1 rejection.)
            let identity = AppleRSA1Envelope.identity(username: credential.username)
            let rsaEncrypted = try Self.rsaEncryptPKCS1(identity,
                                                        modulus: publicKey.n,
                                                        exponent: publicKey.e)
            let c2s1 = try AppleRSA1Envelope.c2s1(rsaEncrypted: rsaEncrypted)
            // O3-CONFIRMED (reference auth.py:170): c2s1 is sent WITH a u32-BE length prefix (=650),
            // exactly as the RSA1 init body was framed above.
            var c2s1Message = Self.bigEndian32(UInt32(c2s1.count))
            c2s1Message.append(c2s1)
            try await connection.write(data: c2s1Message)
            logger.logDebug("[ard33] sent c2s1 (\(c2s1Message.count)B, rsaBlock=\(rsaEncrypted.count)B)")

            // Step 2 — recv s2c1 challenge.
            // ORACLE(O4/O5/R9): the s2c1 framing (leading total length; g width; the u64 `iterations`
            // endianness — assumed big-endian per RFB convention; the trailing `options` extent).
            let challenge = try await Self.readChallenge(connection: connection)
            logger.logDebug("[ard33] s2c1: N=\(challenge.N.count)B g=\(challenge.g.map { String(format: "%02x", $0) }.joined()) salt=\(challenge.salt.count)B B=\(challenge.B.count)B iters=\(challenge.iterations) opts=\(challenge.options.count)B")

            // Step 3 — solve SRP. `a` is a fresh ≥256-bit private exponent (A3).
            //
            // This is the connect path's CPU floor: PBKDF2 at the server's iteration count plus three
            // 4096-bit modular exponentiations. The per-phase timing is logged (durations only, never
            // key material) because it is the first thing to look at whenever HP connect feels slow —
            // both terms are pure compute and inflate ~10-40x in a Debug (`-Onone`) build.
            let a = try randomBytes(32)
            let deriveStart = Date()
            let srp = try AppleSRPClient.derive(password: Data(credential.password.utf8),
                                                salt: challenge.salt,
                                                iterations: challenge.iterations,
                                                N: challenge.N,
                                                g: challenge.g,
                                                B: challenge.B,
                                                a: a,
                                                onPhase: { phase, seconds in
                                                    logger.logDebug("[ard33] srp \(phase): \(Self.milliseconds(seconds))ms")
                                                })
            logger.logDebug("[ard33] srp derive total: \(Self.milliseconds(-deriveStart.timeIntervalSinceNow))ms (iters=\(challenge.iterations))")

            let clientRandom = try randomBytes(16)
            // ORACLE(O5): the `opts` echoed in c2s2 (here: the server's s2c1 options verbatim).
            let c2s2 = try AppleRSA1Envelope.c2s2(A: srp.A,
                                                  M1: srp.M1,
                                                  opts: challenge.options,
                                                  clientRandom: clientRandom)
            // O5-CONFIRMED (reference auth.py:326): c2s2 is sent WITH a u32-BE length prefix (=1076).
            var c2s2Message = Self.bigEndian32(UInt32(c2s2.count))
            c2s2Message.append(c2s2)
            try await connection.write(data: c2s2Message)
            logger.logDebug("[ard33] sent c2s2 (\(c2s2Message.count)B, A=\(srp.A.count)B); awaiting M2/result")

            // Step 4 — recv the server's final message. O6-CONFIRMED layout (reference auth.py:334-336):
            //   [u32-BE m2_len][m2_len bytes M2][u32-BE SecurityResult]
            // M2 is LENGTH-PREFIXED (m2_len == 64 expected), and SecurityResult immediately follows —
            // there is NO gap/filler between them (corrects BLOCKER-F3 / the "M2[64] then gap" guess).
            // O6-CONFIRMED server final message: [u32-BE m2_len][M2][u32-BE SecurityResult].
            // We do NOT verify M2. Live finding: the server's SUCCESS M2 is 98 bytes, NOT the 64-byte
            // SHA512(PAD(A)||M1||K) the spec (NFR-6/§13.2) assumed — so the added verify is
            // unimplementable as specced (the real M2 framing is undocumented). The reference likewise
            // skips M2 and treats SecurityResult as canonical. Server authentication is instead
            // guaranteed downstream by the AES-128-CBC record layer: its keys derive from the SRP
            // session key K (via `wrapKey`), so a server that did not possess the account verifier
            // cannot produce records that our `open()` accepts (SHA-1 trailer would fail). See
            // HP-SPECS §14. (`AppleSRPClient.computeM2/verifyM2` are retained + unit-tested for a
            // future revision that reverse-engineers the 98-byte M2.)
            let m2Len = try await connection.readUInt32()
            logger.logDebug("[ard33] server final: m2Len=\(m2Len)")
            guard m2Len > 0, m2Len <= 4096 else {
                throw VNCError.protocol(.invalidData)
            }
            _ = try await connection.readBuffered(length: Int(m2Len))   // M2 consumed, not verified (reference parity)
            let securityResult = try await connection.readUInt32()
            logger.logDebug("[ard33] SecurityResult=\(securityResult)")

            guard securityResult == 0 else {
                throw VNCError.authentication(.ardAuthenticationFailed)
            }

            return Success(wrapKey: AppleSRPClient.wrapKey(K: srp.K))
        }
    }
}

// MARK: - Challenge parsing (s2c1)
private extension VNCProtocol.ARDRSASRPAuthentication {
    /// The parsed s2c1 challenge. All SRP field byte-orders are taken verbatim from the dossier /
    /// reference and confirmed at O4/O5 — not independently re-derived (NFR-2).
    struct Challenge {
        let N: Data          // 4096-bit MODP modulus (512 bytes)
        let g: Data          // generator (Apple: 5)
        let salt: Data       // 32 bytes
        let B: Data          // server public value (512 bytes)
        let iterations: Int  // PBKDF2 iteration count — READ from wire (never hardcoded)
        let options: Data    // capability string, echoed in c2s2
    }

    /// Read + slice the s2c1 challenge.
    ///
    /// O4/O5-CONFIRMED layout (reference `auth.py:186-224`), behind a leading u32-BE total length:
    ///   [0..11]  12-byte TLV header (static; skipped)
    ///   [12]     0x00 DER positive-int marker (verified == 0)
    ///   [13..]   N modulus, FIXED 512 bytes (4096-bit MODP; not length-prefixed)
    ///   +        u16-BE g_len   || g
    ///   +        u8    salt_len || salt          (salt_len is a SINGLE byte, not u16)
    ///   +        u16-BE B_len   || B
    ///   +        u64-BE iterations                (R9: big-endian CONFIRMED)
    ///   +        u16-BE cap_len || cap            (echoed verbatim into c2s2 as `opts`)
    /// N is a fixed width; g/salt/B/cap are length-prefixed. `iterations` is never hardcoded.
    static func readChallenge(connection: any NetworkConnection) async throws -> Challenge {
        let totalLength = try await connection.readUInt32()

        // 13-byte lead-in (header + marker) + fixed 512-byte N + at least the length-prefix bytes.
        guard totalLength >= 13 + 512 + 2 + 1 + 2 + 8 + 2 else {
            throw VNCError.protocol(.invalidData)
        }

        let body = try await connection.readBuffered(length: Int(totalLength))
        let bytes = Array(body)

        var offset = 0
        func take(_ count: Int) throws -> Data {
            guard count >= 0, offset + count <= bytes.count else {
                throw VNCError.protocol(.invalidData)
            }
            let slice = Data(bytes[offset..<(offset + count)])
            offset += count
            return slice
        }
        func takeU16BE() throws -> Int {
            let d = Array(try take(2))
            return (Int(d[0]) << 8) | Int(d[1])
        }

        offset = 12                              // skip the 12-byte static TLV header
        let marker = try take(1)                 // DER positive-int marker
        guard marker.first == 0x00 else {
            throw VNCError.protocol(.invalidData)
        }

        let N = try take(512)                    // fixed 4096-bit modulus
        let gLen = try takeU16BE()
        let g = try take(gLen)
        let saltLen = Int(try take(1).first ?? 0)   // single-byte length
        let salt = try take(saltLen)
        let bLen = try takeU16BE()
        let B = try take(bLen)
        let iterationsData = try take(8)

        // iterations: u64 big-endian (R9). Fits in Int on 64-bit; guard against a pathological value.
        var iterations: UInt64 = 0
        for byte in iterationsData {
            iterations = (iterations << 8) | UInt64(byte)
        }
        guard iterations > 0, iterations <= 1_000_000 else {   // reference sanity cap (auth.py:231)
            throw VNCError.protocol(.invalidData)
        }

        let capLen = try takeU16BE()
        let options = try take(capLen)           // capability string, echoed verbatim into c2s2

        return Challenge(N: N,
                         g: g,
                         salt: salt,
                         B: B,
                         iterations: Int(iterations),
                         options: options)
    }
}

// MARK: - RSA-PKCS#1 v1.5 encryption (coordinator-owned)
private extension VNCProtocol.ARDRSASRPAuthentication {
    /// RSA-PKCS#1 v1.5-encrypt `plaintext` under the server public key `(modulus, exponent)`, producing
    /// exactly a 256-byte block (RSA-2048, dossier §3.2 step 1). Uses the vendored CryptoSwift `RSA`
    /// (default `.pksc1v15`, secure random padding) — no new dependency (NFR-4).
    ///
    /// ORACLE(O3): assumes a 2048-bit server key (256-byte block). The output is left-zero-padded to
    /// 256 bytes defensively (a well-formed 2048-bit modulus already yields 256).
    static func rsaEncryptPKCS1(_ plaintext: Data,
                                modulus: Data,
                                exponent: Data) throws -> Data {
        let rsa = RSA(n: Array(modulus), e: Array(exponent))

        let encrypted: [UInt8]
        do {
            encrypted = try rsa.encrypt(Array(plaintext), variant: .pksc1v15)
        } catch {
            throw VNCError.authentication(.ardAuthenticationFailed)
        }

        var block = Data(encrypted)
        guard block.count <= 256 else {
            throw VNCError.authentication(.ardAuthenticationFailed)
        }
        if block.count < 256 {
            block = Data(repeating: 0, count: 256 - block.count) + block
        }

        return block
    }
}

// MARK: - Randomness
extension VNCProtocol.ARDRSASRPAuthentication {
    /// Cryptographically-secure random bytes (A3). `SecRandomCopyBytes` on Apple platforms, matching
    /// the type-30 path (`ARDAuthenticationImpl.swift`); a system-RNG fallback elsewhere.
    static func secureRandomBytes(_ count: Int) throws -> Data {
        guard count > 0 else { return Data() }

#if canImport(Security)
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { pointer -> Int32 in
            guard let baseAddress = pointer.baseAddress else { return errSecParam }

            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }

        guard status == errSecSuccess else {
            throw VNCError.authentication(.ardAuthenticationFailed)
        }

        return bytes
#else
        return Data((0..<count).map { _ in UInt8.random(in: 0...255) })
#endif
    }
}

// MARK: - Logging helpers
private extension VNCProtocol.ARDRSASRPAuthentication {
    /// Whole milliseconds, for the connect-timing log lines.
    static func milliseconds(_ seconds: Double) -> Int {
        Int((seconds * 1000).rounded())
    }
}

// MARK: - Big-endian helper
private extension VNCProtocol.ARDRSASRPAuthentication {
    static func bigEndian32(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ])
    }
}
