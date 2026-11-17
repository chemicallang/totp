// totp — RFC 6238 TOTP + RFC 4226 HOTP over HMAC-SHA1, with a Base32 codec.
//
// Vendored from `github.com/chemicallang/totp` and ported to the safe stdlib
// surface. The published module still takes `*u8`/`*mut u8` out-parameters,
// reads with the old `vector.get()` shape and calls raw `rand()`/`time()`, none
// of which compiles under the safe compiler. The public API deliberately keeps
// the names account already calls, so this stays a drop-in replacement.
//
// Everything here works on owned buffers and `&[u8]` slices: no raw pointers
// escape, no output parameter, no unchecked indexing.

using std::string
using std::string_view
using std::vector

public namespace totp {

    // ========================================================================
    // SHA-1 (FIPS 180-4) — HMAC-SHA1 is the algorithm every authenticator app
    // implements for TOTP, so it cannot be swapped for SHA-256 without
    // invalidating every already-enrolled secret.
    // ========================================================================

    private func rotl32(value : u32, shift : u32) : u32 {
        return (value << shift) | (value >> (32u - shift))
    }

    public func sha1(message : &[u8]) : [20]u8 {
        var h0 : u32 = 0x67452301u32
        var h1 : u32 = 0xEFCDAB89u32
        var h2 : u32 = 0x98BADCFEu32
        var h3 : u32 = 0x10325476u32
        var h4 : u32 = 0xC3D2E1F0u32

        var ml_bits : u64 = (message.size() as u64) * 8u64

        var padded = vector<u8>()
        var i : size_t = 0
        while(i < message.size()) {
            padded.push(message[i])
            i += 1
        }
        padded.push(0x80u8)
        while(padded.size() % 64u != 56u) {
            padded.push(0u8)
        }
        padded.push((ml_bits >> 56u) as u8)
        padded.push((ml_bits >> 48u) as u8)
        padded.push((ml_bits >> 40u) as u8)
        padded.push((ml_bits >> 32u) as u8)
        padded.push((ml_bits >> 24u) as u8)
        padded.push((ml_bits >> 16u) as u8)
        padded.push((ml_bits >> 8u) as u8)
        padded.push(ml_bits as u8)

        var block_idx : size_t = 0
        while(block_idx < padded.size()) {
            var w : [80]u32
            var k : size_t = 0
            while(k < 16) {
                var idx = block_idx + k * 4
                w[k] = (padded.at(idx) as u32) << 24u |
                       (padded.at(idx + 1) as u32) << 16u |
                       (padded.at(idx + 2) as u32) << 8u |
                       (padded.at(idx + 3) as u32)
                k += 1
            }
            k = 16
            while(k < 80) {
                w[k] = rotl32(w[k - 3] ^ w[k - 8] ^ w[k - 14] ^ w[k - 16], 1u)
                k += 1
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4

            k = 0
            while(k < 80) {
                var f : u32
                var kk : u32
                if(k < 20) {
                    f = (b & c) | ((~b) & d)
                    kk = 0x5A827999u32
                } else if(k < 40) {
                    f = b ^ c ^ d
                    kk = 0x6ED9EBA1u32
                } else if(k < 60) {
                    f = (b & c) | (b & d) | (c & d)
                    kk = 0x8F1BBCDCu32
                } else {
                    f = b ^ c ^ d
                    kk = 0xCA62C1D6u32
                }

                var temp = rotl32(a, 5u) + f + e + kk + w[k]
                e = d
                d = c
                c = rotl32(b, 30u)
                b = a
                a = temp
                k += 1
            }

            h0 = h0 + a
            h1 = h1 + b
            h2 = h2 + c
            h3 = h3 + d
            h4 = h4 + e

            block_idx += 64
        }

        var digest : [20]u8
        digest[0] = (h0 >> 24u) as u8
        digest[1] = (h0 >> 16u) as u8
        digest[2] = (h0 >> 8u) as u8
        digest[3] = h0 as u8
        digest[4] = (h1 >> 24u) as u8
        digest[5] = (h1 >> 16u) as u8
        digest[6] = (h1 >> 8u) as u8
        digest[7] = h1 as u8
        digest[8] = (h2 >> 24u) as u8
        digest[9] = (h2 >> 16u) as u8
        digest[10] = (h2 >> 8u) as u8
        digest[11] = h2 as u8
        digest[12] = (h3 >> 24u) as u8
        digest[13] = (h3 >> 16u) as u8
        digest[14] = (h3 >> 8u) as u8
        digest[15] = h3 as u8
        digest[16] = (h4 >> 24u) as u8
        digest[17] = (h4 >> 16u) as u8
        digest[18] = (h4 >> 8u) as u8
        digest[19] = h4 as u8
        return digest
    }

    // ========================================================================
    // HMAC-SHA1 (RFC 2104)
    // ========================================================================

    public func hmac_sha1(key : &[u8], message : &[u8]) : [20]u8 {
        var block : [64]u8
        var i : size_t = 0
        if(key.size() > 64u) {
            var hashed = sha1(key)
            while(i < 20u) {
                block[i] = hashed[i]
                i += 1
            }
        } else {
            while(i < key.size()) {
                block[i] = key[i]
                i += 1
            }
        }
        while(i < 64u) {
            block[i] = 0u8
            i += 1
        }

        var inner_data = vector<u8>()
        i = 0
        while(i < 64u) {
            inner_data.push(block[i] ^ 0x36u8)
            i += 1
        }
        i = 0
        while(i < message.size()) {
            inner_data.push(message[i])
            i += 1
        }
        var inner_hash = sha1(inner_data.as_span())

        var outer_data = vector<u8>()
        i = 0
        while(i < 64u) {
            outer_data.push(block[i] ^ 0x5Cu8)
            i += 1
        }
        i = 0
        while(i < 20u) {
            outer_data.push(inner_hash[i])
            i += 1
        }
        return sha1(outer_data.as_span())
    }

    // ========================================================================
    // Base32 (RFC 4648) — the encoding authenticator apps exchange secrets in
    // ========================================================================

    private func base32_alphabet() : string_view {
        return string_view("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    }

    public func base32_encode(data : &[u8]) : string {
        var alphabet = base32_alphabet()
        var result = string()
        var i : size_t = 0
        var bits : u32 = 0u
        var buffer : u32 = 0u

        while(i < data.size()) {
            buffer = (buffer << 8u) | (data[i] as u32)
            bits = bits + 8u
            while(bits >= 5u) {
                bits = bits - 5u
                var index = (buffer >> bits) & 0x1Fu
                result.append(alphabet.at(index as size_t))
            }
            i += 1
        }

        if(bits > 0u) {
            buffer = buffer << (5u - bits)
            var index = buffer & 0x1Fu
            result.append(alphabet.at(index as size_t))
        }

        while(result.size() % 8u != 0u) {
            result.append('=')
        }
        return result
    }

    private func base32_char_value(c : char) : u8 {
        if(c >= 'A' && c <= 'Z') { return ((c as u8) - ('A' as u8)) }
        if(c >= '2' && c <= '7') { return ((c as u8) - ('2' as u8)) + 26u8 }
        return 0u8
    }

    public func base32_decode(input : &string_view) : vector<u8> {
        var result = vector<u8>()
        var buffer : u32 = 0u
        var bits : u32 = 0u

        var i : size_t = 0
        while(i < input.size()) {
            var c = input.at(i)
            i += 1
            if(c == '=') { break }
            if(c == ' ' || c == '-' || c == '\n' || c == '\r') { continue }
            buffer = (buffer << 5u) | (base32_char_value(c) as u32)
            bits = bits + 5u
            if(bits >= 8u) {
                bits = bits - 8u
                result.push((buffer >> bits) as u8)
                buffer = buffer & ((1u << bits) - 1u)
            }
        }
        return result
    }

    // ========================================================================
    // HOTP / TOTP
    // ========================================================================

    /// RFC 4226 §5.3 dynamic truncation, done on the digest array itself so the
    /// module never needs a `[u8]` view over a fixed array. The digest is passed
    /// by value (20 bytes, `Copy`): a reference to a fixed array is not yet
    /// emitted correctly by the C backend.
    private func dynamic_truncate(hash : [20]u8) : u32 {
        var offset = (hash[19] & 0x0Fu) as size_t
        var value = ((hash[offset] as u32) << 24u) |
                    ((hash[offset + 1] as u32) << 16u) |
                    ((hash[offset + 2] as u32) << 8u) |
                    (hash[offset + 3] as u32)
        return value & 0x7FFFFFFFu32
    }

    /// The 6-digit code for one HOTP counter (RFC 4226).
    public func hotp(secret : &[u8], counter : u64) : u32 {
        var message = vector<u8>()
        message.push(((counter >> 56u) & 0xFFu64) as u8)
        message.push(((counter >> 48u) & 0xFFu64) as u8)
        message.push(((counter >> 40u) & 0xFFu64) as u8)
        message.push(((counter >> 32u) & 0xFFu64) as u8)
        message.push(((counter >> 24u) & 0xFFu64) as u8)
        message.push(((counter >> 16u) & 0xFFu64) as u8)
        message.push(((counter >> 8u) & 0xFFu64) as u8)
        message.push((counter & 0xFFu64) as u8)
        var mac = hmac_sha1(secret, message.as_span())
        return dynamic_truncate(mac) % 1000000u32
    }

    /// The code for a Unix timestamp, 30-second steps (RFC 6238).
    public func totp_code(secret : &[u8], unix_secs : i64) : u32 {
        var step : u64 = (unix_secs / 30i64) as u64
        return hotp(secret, step)
    }

    /// Zero-pads a code to the six digits a user types. Splitting this out keeps
    /// the formatting testable without a clock.
    public func format_code(code : u32) : string {
        var out = string()
        var divisor : u32 = 100000u32
        var remaining = code
        var i : int = 0
        while(i < 6) {
            var digit = remaining / divisor
            out.append(((digit + 48u) as u8) as char)
            remaining = remaining % divisor
            divisor = divisor / 10u
            i += 1
        }
        return out
    }

    // ========================================================================
    // Enrolment helpers
    // ========================================================================

    /// 160 bits of CSPRNG material, Base32-encoded — the RFC-recommended
    /// minimum. An unavailable OS RNG is an error, never a weak fallback.
    public func generate_totp_secret() : std::Result<string, std::io::IoError> {
        var bytes = osrand::random_bytes(20u)
        if(bytes is std::Result.Err) {
            var Err(error) = bytes else unsafe { unreachable }
            return std::Result.Err(error)
        }
        var Ok(random) = bytes else unsafe { unreachable }
        return std::Result.Ok(base32_encode(random.as_span()))
    }

    /// The `otpauth://` URL an authenticator app reads from the QR code.
    public func generate_totp_uri(issuer : &string_view, account_name : &string_view, secret : &string_view) : string {
        var uri = string()
        uri.append_view("otpauth://totp/")
        uri.append_view(issuer)
        uri.append(':')
        uri.append_view(account_name)
        uri.append_view("?secret=")
        uri.append_view(secret)
        uri.append_view("&issuer=")
        uri.append_view(issuer)
        return uri
    }

    /// Accepts the current step and its immediate neighbours, so a phone whose
    /// clock is up to 30 seconds off still signs in.
    public func validate_totp_code(secret_base32 : &string_view, code : &string_view) : bool {
        if(secret_base32.size() == 0u) { return false }
        var secret_bytes = base32_decode(secret_base32)
        if(secret_bytes.size() == 0u) { return false }

        var now = std::chrono::SystemTime::now().as_unix_epoch_secs()
        var step = now / 30i64

        var offsets : [3]i64
        offsets[0] = 0i64
        offsets[1] = 1i64
        offsets[2] = -1i64
        var i : int = 0
        while(i < 3) {
            var candidate_time = (step + offsets[i]) * 30i64
            var expected = format_code(totp_code(secret_bytes.as_span(), candidate_time))
            if(expected.to_view().equals(code)) { return true }
            i += 1
        }
        return false
    }

}
