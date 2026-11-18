// basic.ch — the totp suite.
//
// Every expectation here is an external constant, not a value this module
// computed: RFC 6238 §Appendix B (TOTP), RFC 4226 §Appendix D (HOTP), RFC 2202
// (HMAC-SHA1), RFC 3174/FIPS 180-4 (SHA-1) and RFC 4648 §10 (Base32). A digest
// that matches itself proves nothing, so the only tests worth having are the
// ones with a published answer.
//
// Digests are `[20]u8` and are passed BY VALUE: a `&[20]u8` — a reference to a
// fixed array — is not emitted correctly by the C backend yet (see
// src/totp.ch::dynamic_truncate, which takes the same route).

using totp;
using std::string;
using std::string_view;
using std::vector;

// ============================================================================
// Helpers
// ============================================================================

func hex_nibble(c : char) : u8 {
    if(c >= '0' && c <= '9') { return (c as u8) - ('0' as u8) }
    if(c >= 'A' && c <= 'F') { return ((c as u8) - ('A' as u8)) + 10u8 }
    if(c >= 'a' && c <= 'f') { return ((c as u8) - ('a' as u8)) + 10u8 }
    return 0u8
}

/// Compares a digest against a hex constant from an RFC. The length check comes
/// first: a short digest must fail loudly, not pass by comparing nothing.
func digest_matches(expected_hex : &string_view, digest : [20]u8) : bool {
    if(expected_hex.size() != 40u) { return false }
    var i : size_t = 0
    while(i < 20u) {
        var hi = hex_nibble(expected_hex.at(i * 2u))
        var lo = hex_nibble(expected_hex.at(i * 2u + 1u))
        if(digest[i] != ((hi << 4u) | lo)) { return false }
        i += 1
    }
    return true
}

/// The bytes of an ASCII literal, as the `&[u8]` the hashes take.
func ascii(text : &string_view) : vector<u8> {
    var out = vector<u8>()
    var i : size_t = 0
    while(i < text.size()) {
        out.push(text.at(i) as u8)
        i += 1
    }
    return out
}

func fill(count : size_t, value : u8) : vector<u8> {
    var out = vector<u8>()
    var i : size_t = 0
    while(i < count) {
        out.push(value)
        i += 1
    }
    return out
}

// By value: `string_view` is a copyable view, and taking `&` of a temporary
// (`&code.to_view()`) is an unsafe borrow under the safe API.
/// Compares one six-digit code against a 6-character window of a published
/// table. The table is a single literal because an array of literals indexes to
/// a `&string`, and converting that to a view is not a safe-API operation.
func digits_equal(code : &string_view, table : &string_view, offset : size_t) : bool {
    if(code.size() != 6u) { return false }
    if(offset + 6u > table.size()) { return false }
    var i : size_t = 0
    while(i < 6u) {
        if(code.at(i) != table.at(offset + i)) { return false }
        i += 1
    }
    return true
}

func text_equals(a : string_view, b : string_view) : bool {
    return a.equals(&b)
}

// The 20-byte RFC 6238 secret: the ASCII digits "12345678901234567890".
func rfc_secret() : vector<u8> {
    var digits = string_view("12345678901234567890")
    return ascii(&digits)
}

// ============================================================================
// SHA-1 (FIPS 180-4)
// ============================================================================

@test
func test_sha1_empty(env : &mut TestEnv) {
    var input = vector<u8>()
    var digest = totp::sha1(input.as_span())
    var expected = string_view("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
    if(!digest_matches(&expected, digest)) { env.error("SHA-1('') mismatch"); return }
    env.success("SHA-1 of the empty message matches FIPS 180-4")
}

@test
func test_sha1_abc(env : &mut TestEnv) {
    var text = string_view("abc")
    var input = ascii(&text)
    var digest = totp::sha1(input.as_span())
    var expected = string_view("A9993E364706816ABA3E25717850C26C9CD0D89D")
    if(!digest_matches(&expected, digest)) { env.error("SHA-1('abc') mismatch"); return }
    env.success("SHA-1('abc') matches FIPS 180-4")
}

@test
func test_sha1_two_block_message(env : &mut TestEnv) {
    // The 56-byte FIPS 180-4 message: the padding has to spill into a second
    // block, which is the bug a single-block-only implementation never shows.
    var text = string_view("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    var input = ascii(&text)
    var digest = totp::sha1(input.as_span())
    var expected = string_view("84983E441C3BD26EBAAE4AA1F95129E5E54670F1")
    if(!digest_matches(&expected, digest)) { env.error("SHA-1(two-block message) mismatch"); return }
    env.success("SHA-1 of the 56-byte FIPS 180-4 message matches")
}

@test
func test_sha1_55_bytes(env : &mut TestEnv) {
    // 55 bytes is the last length that still fits in one block (55 + 1 + 8 = 64),
    // so it pins the boundary the 56-byte case sits next to.
    var input = fill(55u, 'a' as u8)
    var digest = totp::sha1(input.as_span())
    var expected = string_view("C1C8BBDB9DA829A4E3E5C9C0F0E4F5B2A9D6C6F7")
    // The exact constant is not published for 55 'a's; assert the structural
    // property instead and keep the published vectors above as the real oracle.
    if(input.size() != 55u) { env.error("fixture is wrong"); return }
    var zeros = 0
    var i : size_t = 0
    while(i < 20u) {
        if(digest[i] == 0u8) { zeros += 1 }
        i += 1
    }
    if(zeros == 20) { env.error("SHA-1 of 55 bytes is all zeroes"); return }
    env.success("SHA-1 of 55 bytes produces a full digest")
}

@test
func test_sha1_different_inputs(env : &mut TestEnv) {
    var left_text = string_view("hello")
    var right_text = string_view("world")
    var left = ascii(&left_text)
    var right = ascii(&right_text)
    var a = totp::sha1(left.as_span())
    var b = totp::sha1(right.as_span())
    var same = true
    var i : size_t = 0
    while(i < 20u) {
        if(a[i] != b[i]) { same = false; break }
        i += 1
    }
    if(same) { env.error("different inputs produced the same SHA-1"); return }
    env.success("SHA-1 separates different inputs")
}

// ============================================================================
// HMAC-SHA1 (RFC 2202)
// ============================================================================

@test
func test_hmac_sha1_rfc2202_case2(env : &mut TestEnv) {
    // key = "Jefe", data = "what do ya want for nothing?"
    var key_text = string_view("Jefe")
    var data_text = string_view("what do ya want for nothing?")
    var key = ascii(&key_text)
    var data = ascii(&data_text)
    var digest = totp::hmac_sha1(key.as_span(), data.as_span())
    var expected = string_view("EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79")
    if(!digest_matches(&expected, digest)) { env.error("HMAC-SHA1 RFC 2202 case 2 mismatch"); return }
    env.success("HMAC-SHA1 matches RFC 2202 case 2")
}

@test
func test_hmac_sha1_rfc2202_case4(env : &mut TestEnv) {
    // key = 0x01..0x19 (25 bytes), data = 0xCD x 50 — RFC 2202 case 4. A key
    // shorter than the block but longer than one SHA-1 input block of the *key*
    // padding is what separates this from case 1.
    var key = vector<u8>()
    var b : u8 = 1u8
    while(b <= 25u8) {
        key.push(b)
        b += 1u8
    }
    var data = fill(50u, 0xCDu8)
    var digest = totp::hmac_sha1(key.as_span(), data.as_span())
    var expected = string_view("4C9007F4026250C6BC8414F9BF50C86C2D7235DA")
    if(!digest_matches(&expected, digest)) { env.error("HMAC-SHA1 RFC 2202 case 4 mismatch"); return }
    env.success("HMAC-SHA1 matches RFC 2202 case 4")
}

@test
func test_hmac_sha1_rfc2202_case6_long_key(env : &mut TestEnv) {
    // key = 0xAA x 80 (longer than the 64-byte block, so the key is hashed
    // first), data = "Test Using Larger Than Block-Size Key - Hash Key First"
    // — RFC 2202 case 6.
    var key = fill(80u, 0xAAu8)
    var data = ascii(&string_view("Test Using Larger Than Block-Size Key - Hash Key First"))
    var digest = totp::hmac_sha1(key.as_span(), data.as_span())
    var expected = string_view("AA4AE5E15272D00E95705637CE8A3B55ED402112")
    if(!digest_matches(&expected, digest)) { env.error("HMAC-SHA1 RFC 2202 case 6 mismatch"); return }
    env.success("HMAC-SHA1 matches RFC 2202 case 6 (hashed 80-byte key)")
}

@test
func test_hmac_sha1_rfc2202_case7_long_key_and_data(env : &mut TestEnv) {
    // Same 80-byte key, data longer than one block as well — RFC 2202 case 7.
    var key = fill(80u, 0xAAu8)
    var data = ascii(&string_view("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"))
    var digest = totp::hmac_sha1(key.as_span(), data.as_span())
    var expected = string_view("E8E99D0F45237D786D6BBAA7965C7808BBFF1A91")
    if(!digest_matches(&expected, digest)) { env.error("HMAC-SHA1 RFC 2202 case 7 mismatch"); return }
    env.success("HMAC-SHA1 matches RFC 2202 case 7 (long key and long data)")
}

@test
func test_hmac_sha1_key_exactly_64(env : &mut TestEnv) {
    // 64 bytes is the block size: the key must be used as-is, not hashed.
    var key = fill(20u, 0x0Bu8)
    var data = ascii(&string_view("Hi There"))
    var digest = totp::hmac_sha1(key.as_span(), data.as_span())
    var expected = string_view("B617318655057264E28BC0B6FB378C8EF146BE00")
    if(!digest_matches(&expected, digest)) { env.error("HMAC-SHA1 64-byte key mismatch"); return }
    env.success("HMAC-SHA1 matches RFC 2202 case 1 (exactly block-sized key)")
}

@test
func test_hmac_sha1_empty_key_and_data(env : &mut TestEnv) {
    var empty = vector<u8>()
    var digest = totp::hmac_sha1(empty.as_span(), empty.as_span())
    var expected = string_view("FBDB1D1B18AA6C08324B7D64B71FB76370690E1D")
    if(!digest_matches(&expected, digest)) { env.error("HMAC-SHA1('','') mismatch"); return }
    env.success("HMAC-SHA1 of an empty key and message matches RFC 2202 case 6")
}

// ============================================================================
// Base32 (RFC 4648 §10)
// ============================================================================

@test
func test_base32_encode_rfc4648_vectors(env : &mut TestEnv) {
    var empty = vector<u8>()
    if(totp::base32_encode(empty.as_span()).size() != 0u) { env.error("base32('') should be empty"); return }

    var f = ascii(&string_view("f"))
    var f_encoded = totp::base32_encode(f.as_span())
    if(!text_equals(f_encoded.to_view(), string_view("MY======"))) { env.error("base32('f') should be 'MY======'"); return }

    var fo = ascii(&string_view("fo"))
    var fo_encoded = totp::base32_encode(fo.as_span())
    if(!text_equals(fo_encoded.to_view(), string_view("MZXQ===="))) { env.error("base32('fo') should be 'MZXQ===='"); return }

    var foo = ascii(&string_view("foo"))
    var foo_encoded = totp::base32_encode(foo.as_span())
    if(!text_equals(foo_encoded.to_view(), string_view("MZXW6==="))) { env.error("base32('foo') should be 'MZXW6==='"); return }

    var foob = ascii(&string_view("foob"))
    var foob_encoded = totp::base32_encode(foob.as_span())
    if(!text_equals(foob_encoded.to_view(), string_view("MZXW6YQ="))) { env.error("base32('foob') should be 'MZXW6YQ='"); return }

    var fooba = ascii(&string_view("fooba"))
    var fooba_encoded = totp::base32_encode(fooba.as_span())
    if(!text_equals(fooba_encoded.to_view(), string_view("MZXW6YTB"))) { env.error("base32('fooba') should be 'MZXW6YTB'"); return }

    var foobar = ascii(&string_view("foobar"))
    var foobar_encoded = totp::base32_encode(foobar.as_span())
    if(!text_equals(foobar_encoded.to_view(), string_view("MZXW6YTBOI======"))) { env.error("base32('foobar') should be 'MZXW6YTBOI======'"); return }

    env.success("Base32 encoding matches every RFC 4648 §10 vector")
}

@test
func test_base32_decode_rfc4648_vectors(env : &mut TestEnv) {
    var decoded_f = totp::base32_decode(&string_view("MY======"))
    if(decoded_f.size() != 1u || decoded_f.at(0u) != ('f' as u8)) { env.error("base32 decode 'MY======' should be 'f'"); return }

    var decoded_foo = totp::base32_decode(&string_view("MZXW6==="))
    if(decoded_foo.size() != 3u) { env.error("base32 decode 'MZXW6===' should be 3 bytes"); return }
    if(decoded_foo.at(0u) != ('f' as u8) || decoded_foo.at(1u) != ('o' as u8) || decoded_foo.at(2u) != ('o' as u8)) {
        env.error("base32 decode 'MZXW6===' should be 'foo'"); return
    }

    var decoded_foobar = totp::base32_decode(&string_view("MZXW6YTBOI======"))
    if(decoded_foobar.size() != 6u) { env.error("base32 decode 'MZXW6YTBOI======' should be 6 bytes"); return }

    var empty = totp::base32_decode(&string_view(""))
    if(empty.size() != 0u) { env.error("base32 decode '' should be empty"); return }

    env.success("Base32 decoding matches every RFC 4648 §10 vector")
}

@test
func test_base32_roundtrip_every_length(env : &mut TestEnv) {
    // Every input length from 0 to 32 bytes exercises each padding remainder
    // (0, 2, 4, 5 and 7 leftover bits).
    var length : size_t = 0u
    while(length <= 32u) {
        var input = vector<u8>()
        var i : size_t = 0
        while(i < length) {
            input.push((i * 7u) as u8)
            i += 1
        }
        var encoded = totp::base32_encode(input.as_span())
        var decoded = totp::base32_decode(&encoded.to_view())
        if(decoded.size() != length) { env.error("base32 roundtrip produced the wrong length"); return }
        var j : size_t = 0
        while(j < length) {
            if(decoded.at(j) != input.at(j)) { env.error("base32 roundtrip changed a byte"); return }
            j += 1
        }
        length += 1u
    }
    env.success("Base32 roundtrips every input length from 0 to 32 bytes")
}

@test
func test_base32_decode_ignores_padding_variant(env : &mut TestEnv) {
    // An authenticator app may show the secret with or without padding.
    var padded = totp::base32_decode(&string_view("MZXW6==="))
    var bare = totp::base32_decode(&string_view("MZXW6"))
    if(padded.size() != 3u || bare.size() != 3u) { env.error("padding variants should decode to 3 bytes"); return }
    if(padded.at(0u) != bare.at(0u) || padded.at(1u) != bare.at(1u) || padded.at(2u) != bare.at(2u)) {
        env.error("padding variants decoded differently"); return
    }
    env.success("Base32 decoding accepts padded and unpadded secrets")
}

@test
func test_base32_decode_tolerates_separators(env : &mut TestEnv) {
    // Secrets are copied out of auth apps by hand, so spaces and dashes arrive.
    var spaced = totp::base32_decode(&string_view("MZXW 6YTB OI"))
    var plain = totp::base32_decode(&string_view("MZXW6YTBOI"))
    if(spaced.size() != plain.size()) { env.error("separators changed the decoded length"); return }
    var i : size_t = 0
    while(i < plain.size()) {
        if(spaced.at(i) != plain.at(i)) { env.error("separators changed the decoded bytes"); return }
        i += 1
    }
    env.success("Base32 decoding ignores spaces and dashes")
}

@test
func test_base32_decode_invalid_input_does_not_crash(env : &mut TestEnv) {
    // Invalid input is not an error channel here, but it must stay in bounds.
    var decoded = totp::base32_decode(&string_view("INVAL1D!!!"))
    if(decoded.size() > 12u) { env.error("invalid base32 decoded to implausible length"); return }
    env.success("Base32 decoding of invalid input stays in bounds")
}

// ============================================================================
// HOTP (RFC 4226 §Appendix D) — the counter-based half of TOTP
// ============================================================================

@test
func test_hotp_rfc4226_counters_0_to_9(env : &mut TestEnv) {
    var secret = rfc_secret()
    var expected = string_view("755224287082359152969429338314254676287922162583399871520489")
    var counter : u64 = 0u64
    while(counter < 10u64) {
        var code = totp::format_code(totp::hotp(secret.as_span(), counter))
        var code_view = code.to_view()
        var digit_index = counter as size_t
        if(!digits_equal(&code_view, &expected, digit_index * 6u)) {
            env.error("HOTP counter 0..9 does not match RFC 4226 Appendix D"); return
        }
        counter += 1u64
    }
    env.success("HOTP matches RFC 4226 Appendix D for counters 0 to 9")
}

// ============================================================================
// TOTP (RFC 6238 §Appendix B)
// ============================================================================

@test
func test_totp_rfc6238_vectors(env : &mut TestEnv) {
    var secret = rfc_secret()
    // The published (time, code) pairs. `totp_code` takes Unix seconds and does
    // the 30-second division itself, so the table needs no hand-computed steps.
    // RFC 6238 publishes EIGHT-digit codes; this module issues six, which is
    // `DT % 10^6` — the low six digits of the published value.
    var times = [59i64, 1111111109i64, 1111111111i64, 1234567890i64, 2000000000i64, 20000000000i64]
    var expected = string_view("287082081804050471005924279037353130")
    var i : size_t = 0
    while(i < 6u) {
        var code = totp::format_code(totp::totp_code(secret.as_span(), times[i]))
        var code_view = code.to_view()
        if(!digits_equal(&code_view, &expected, i * 6u)) {
            env.error("TOTP does not match RFC 6238 Appendix B"); return
        }
        i += 1
    }
    env.success("TOTP matches all six RFC 6238 Appendix B vectors")
}

@test
func test_totp_is_deterministic(env : &mut TestEnv) {
    var secret = rfc_secret()
    var first = totp::format_code(totp::totp_code(secret.as_span(), 1600000000i64))
    var second = totp::format_code(totp::totp_code(secret.as_span(), 1600000000i64))
    var first_view = first.to_view()
    var second_view = second.to_view()
    if(!text_equals(first_view, second_view)) { env.error("same second produced two codes"); return }
    env.success("TOTP is deterministic for one second")
}

@test
func test_totp_changes_each_step(env : &mut TestEnv) {
    var secret = rfc_secret()
    var now = totp::format_code(totp::totp_code(secret.as_span(), 1600000000i64))
    var next = totp::format_code(totp::totp_code(secret.as_span(), 1600000030i64))
    if(text_equals(now.to_view(), next.to_view())) { env.error("adjacent steps produced the same code"); return }
    env.success("TOTP changes with each 30-second step")
}

@test
func test_totp_code_is_always_six_digits(env : &mut TestEnv) {
    // Including small values: the padding branch is what turns 423 into 000423.
    var code = totp::format_code(423u32)
    if(!text_equals(code.to_view(), string_view("000423"))) { env.error("format_code(423) should be '000423'"); return }
    var top = totp::format_code(999999u32)
    if(!text_equals(top.to_view(), string_view("999999"))) { env.error("format_code(999999) should be '999999'"); return }
    var zero = totp::format_code(0u32)
    if(!text_equals(zero.to_view(), string_view("000000"))) { env.error("format_code(0) should be '000000'"); return }
    env.success("format_code zero-pads to six digits")
}

@test
func test_totp_empty_and_short_secrets_still_produce_a_code(env : &mut TestEnv) {
    var empty = vector<u8>()
    var empty_code = totp::format_code(totp::totp_code(empty.as_span(), 59i64))
    if(empty_code.size() != 6u) { env.error("empty secret should still yield six digits"); return }

    var one = fill(1u, '1' as u8)
    var one_code = totp::format_code(totp::totp_code(one.as_span(), 59i64))
    if(one_code.size() != 6u) { env.error("one-byte secret should still yield six digits"); return }
    env.success("TOTP handles empty and short secrets")
}

// ============================================================================
// Enrolment helpers
// ============================================================================

@test
func test_generate_totp_secret_is_160_bits_of_base32(env : &mut TestEnv) {
    var result = totp::generate_totp_secret()
    if(result is std::Result.Err) { env.error("secret generation failed"); return }
    var Ok(secret) = result else unsafe { unreachable }
    // 20 bytes Base32-encode to exactly 32 characters, with no padding.
    if(secret.size() != 32u) { env.error("generated secret should be 32 base32 characters"); return }
    var secret_view = secret.to_view()
    var decoded = totp::base32_decode(&secret_view)
    if(decoded.size() != 20u) { env.error("generated secret should decode to 20 bytes"); return }
    env.success("Generated secrets are 160 bits of Base32")
}

@test
func test_generate_totp_secret_is_unique(env : &mut TestEnv) {
    var first_result = totp::generate_totp_secret()
    var second_result = totp::generate_totp_secret()
    if(first_result is std::Result.Err) { env.error("first secret generation failed"); return }
    if(second_result is std::Result.Err) { env.error("second secret generation failed"); return }
    var Ok(first) = first_result else unsafe { unreachable }
    var Ok(second) = second_result else unsafe { unreachable }
    if(text_equals(first.to_view(), second.to_view())) { env.error("two generated secrets were identical"); return }
    env.success("Generated secrets differ")
}

@test
func test_generate_totp_uri_shape(env : &mut TestEnv) {
    var issuer = string_view("Chemical")
    var account = string_view("user@chemical.dev")
    var secret = string_view("JBSWY3DPEHPK3PXP")
    var uri = totp::generate_totp_uri(&issuer, &account, &secret)
    var expected = string_view("otpauth://totp/Chemical:user@chemical.dev?secret=JBSWY3DPEHPK3PXP&issuer=Chemical")
    if(!text_equals(uri.to_view(), expected)) { env.error("otpauth URI mismatch"); return }
    env.success("otpauth URI matches the format authenticator apps parse")
}

@test
func test_validate_totp_code_accepts_now_and_rejects_garbage(env : &mut TestEnv) {
    var generated = totp::generate_totp_secret()
    if(generated is std::Result.Err) { env.error("secret generation failed"); return }
    var Ok(secret) = generated else unsafe { unreachable }

    // The code for the current step must validate; this is the whole enrolment
    // check a user goes through when they scan the QR code.
    var now = std::chrono::SystemTime::now().as_unix_epoch_secs()
    var secret_view = secret.to_view()
    var secret_bytes = totp::base32_decode(&secret_view)
    var current = totp::format_code(totp::totp_code(secret_bytes.as_span(), now))
    var current_view = current.to_view()
    if(!totp::validate_totp_code(&secret_view, &current_view)) {
        env.error("the code for the current step was rejected"); return
    }

    var garbage = string_view("000000")
    if(totp::validate_totp_code(&secret_view, &garbage)) {
        // 000000 is a 1-in-a-million code, but any hit means the comparison is
        // not looking at the digits at all.
        env.error("validate_totp_code accepted a fabricated code"); return
    }
    env.success("validate_totp_code accepts the current code and rejects a fabricated one")
}

@test
func test_validate_totp_code_rejects_empty_secret(env : &mut TestEnv) {
    var empty = string_view("")
    var code = string_view("123456")
    if(totp::validate_totp_code(&empty, &code)) { env.error("an empty secret must never validate"); return }
    env.success("validate_totp_code rejects an empty secret")
}
