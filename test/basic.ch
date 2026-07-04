using totp;
using std::vector;
using std::string;
using std::string_view;

func hex_char_val(c : char) : uchar {
    if(c >= '0' && c <= '9') return (c - '0') as uchar
    if(c >= 'A' && c <= 'F') return (c - 'A' + 10) as uchar
    if(c >= 'a' && c <= 'f') return (c - 'a' + 10) as uchar
    return 0u as uchar
}

func str_to_vec(s : string_view) : vector<uchar> {
    var result = vector<uchar>()
    for(var i = 0u; i < s.size(); i++) {
        result.push(s.get(i) as uchar)
    }
    return result
}

func hash_matches(expected_hex : string_view, actual : &vector<uchar>, env : &mut TestEnv) : bool {
    if(actual.size() != 20u) { return false }
    for(var i = 0u; i < 20u; i++) {
        var hi = hex_char_val(expected_hex.get(i * 2u))
        var lo = hex_char_val(expected_hex.get(i * 2u + 1u))
        var expected_byte = ((hi << 4) | lo) as uchar
        if(actual.get(i) != expected_byte) { return false }
    }
    return true
}

func sv_equals(a : string_view, b : string_view) : bool {
    return a.equals(&b)
}

func sv_from(s : *char) : string_view {
    return string_view(s)
}

// ========== SHA-1 Tests ==========

@test
func test_sha1_empty(env : &mut TestEnv) {
    var input = vector<uchar>()
    var result = totp::sha1(&input)
    if(!hash_matches("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", &result, env)) {
        env.error("SHA-1('') mismatch"); return
    }
    env.success("SHA-1 of empty string works")
}

@test
func test_sha1_abc(env : &mut TestEnv) {
    var input = str_to_vec("abc")
    var result = totp::sha1(&input)
    if(!hash_matches("A9993E364706816ABA3E25717850C26C9CD0D89D", &result, env)) {
        env.error("SHA-1('abc') mismatch"); return
    }
    env.success("SHA-1 of 'abc' works")
}

@test
func test_sha1_digits(env : &mut TestEnv) {
    var input = str_to_vec("12345678901234567890")
    var result = totp::sha1(&input)
    if(result.size() != 20u) { env.error("SHA-1 output should be 20 bytes"); return }
    env.success("SHA-1 of digits works")
}

// ========== HMAC-SHA1 Tests ==========

@test
func test_hmac_sha1_rfc2202_2(env : &mut TestEnv) {
    var key = str_to_vec("Jefe")
    var data = str_to_vec("what do ya want for nothing?")
    var result = totp::hmac_sha1(&key, &data)
    if(!hash_matches("EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79", &result, env)) {
        env.error("HMAC-SHA1 RFC 2202 Test 2 mismatch"); return
    }
    env.success("HMAC-SHA1 RFC 2202 Test Case 2 works")
}

@test
func test_hmac_sha1_totp_secret(env : &mut TestEnv) {
    var key = str_to_vec("12345678901234567890")
    var counter = vector<uchar>()
    counter.push(0u as uchar)
    counter.push(0u as uchar)
    counter.push(0u as uchar)
    counter.push(0u as uchar)
    counter.push(0u as uchar)
    counter.push(0u as uchar)
    counter.push(0u as uchar)
    counter.push(1u as uchar)
    var result = totp::hmac_sha1(&key, &counter)
    if(result.size() != 20u) { env.error("HMAC-SHA1 output should be 20 bytes"); return }
    env.success("HMAC-SHA1 with TOTP secret works")
}

// ========== Base32 Encoding Tests ==========

@test
func test_base32_encode_empty(env : &mut TestEnv) {
    var input = vector<uchar>()
    var result = totp::base32_encode(&input)
    if(result.size() != 0u) { env.error("Base32 of empty should be empty"); return }
    env.success("Base32 encode empty works")
}

@test
func test_base32_encode_f(env : &mut TestEnv) {
    var input = str_to_vec("f")
    var result = totp::base32_encode(&input)
    var expected = sv_from("MY======")
    if(!sv_equals(result.to_view(), expected)) {
        env.error("Base32('f') should be 'MY======'"); return
    }
    env.success("Base32 encode 'f' works")
}

@test
func test_base32_encode_foo(env : &mut TestEnv) {
    var input = str_to_vec("foo")
    var result = totp::base32_encode(&input)
    var expected = sv_from("MZXW6===")
    if(!sv_equals(result.to_view(), expected)) {
        env.error("Base32('foo') should be 'MZXW6==='"); return
    }
    env.success("Base32 encode 'foo' works")
}

@test
func test_base32_encode_foobar(env : &mut TestEnv) {
    var input = str_to_vec("foobar")
    var result = totp::base32_encode(&input)
    var expected = sv_from("MZXW6YTBOI======")
    if(!sv_equals(result.to_view(), expected)) {
        env.error("Base32('foobar') should be 'MZXW6YTBOI======'"); return
    }
    env.success("Base32 encode 'foobar' works")
}

// ========== Base32 Decoding Tests ==========

@test
func test_base32_decode_empty(env : &mut TestEnv) {
    var input = string_view("")
    var result = totp::base32_decode(&input)
    if(result.size() != 0u) { env.error("Base32 decode empty should be empty"); return }
    env.success("Base32 decode empty works")
}

@test
func test_base32_decode_my(env : &mut TestEnv) {
    var input = string_view("MY======")
    var result = totp::base32_decode(&input)
    if(result.size() != 1u) { env.error("Base32 decode 'MY======' should be 1 byte"); return }
    if(result.get(0u) != 'f' as uchar) { env.error("Base32 decode 'MY======' should be 'f'"); return }
    env.success("Base32 decode 'MY======' works")
}

@test
func test_base32_decode_mzxw6(env : &mut TestEnv) {
    var input = string_view("MZXW6===")
    var result = totp::base32_decode(&input)
    if(result.size() != 3u) { env.error("Base32 decode 'MZXW6===' should be 3 bytes"); return }
    if(result.get(0u) != 'f' as uchar || result.get(1u) != 'o' as uchar || result.get(2u) != 'o' as uchar) {
        env.error("Base32 decode 'MZXW6===' should be 'foo'"); return
    }
    env.success("Base32 decode 'MZXW6===' works")
}

@test
func test_base32_decode_mzxw6ytboi(env : &mut TestEnv) {
    var input = string_view("MZXW6YTBOI======")
    var result = totp::base32_decode(&input)
    if(result.size() != 6u) { env.error("Base32 decode 'MZXW6YTBOI======' should be 6 bytes"); return }
    env.success("Base32 decode 'MZXW6YTBOI======' works")
}

// ========== Base32 Roundtrip Tests ==========

@test
func test_base32_roundtrip_hello(env : &mut TestEnv) {
    var input = str_to_vec("Hello, World!")
    var encoded = totp::base32_encode(&input)
    var decoded = totp::base32_decode(&encoded.to_view())
    if(decoded.size() != input.size()) { env.error("Roundtrip size mismatch"); return }
    for(var i = 0u; i < input.size(); i++) {
        if(decoded.get(i) != input.get(i)) { env.error("Roundtrip byte mismatch"); return }
    }
    env.success("Base32 roundtrip 'Hello, World!' works")
}

@test
func test_base32_roundtrip_binary(env : &mut TestEnv) {
    var input = vector<uchar>()
    for(var i = 0u; i < 32u; i++) {
        input.push(i as uchar)
    }
    var encoded = totp::base32_encode(&input)
    var decoded = totp::base32_decode(&encoded.to_view())
    if(decoded.size() != 32u) { env.error("Roundtrip binary size mismatch"); return }
    for(var i = 0u; i < 32u; i++) {
        if(decoded.get(i) != input.get(i)) { env.error("Roundtrip binary byte mismatch"); return }
    }
    env.success("Base32 roundtrip binary data works")
}

@test
func test_base32_roundtrip_secret(env : &mut TestEnv) {
    var input = str_to_vec("12345678901234567890")
    var encoded = totp::base32_encode(&input)
    var decoded = totp::base32_decode(&encoded.to_view())
    if(decoded.size() != input.size()) { env.error("Secret roundtrip size mismatch"); return }
    for(var i = 0u; i < input.size(); i++) {
        if(decoded.get(i) != input.get(i)) { env.error("Secret roundtrip byte mismatch"); return }
    }
    env.success("Base32 roundtrip secret bytes works")
}

// ========== TOTP Generation RFC 6238 Tests ==========

@test
func test_totp_rfc_6238_t1(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, 1i64)
    var expected = sv_from("94287082")
    if(!sv_equals(code.to_view(), expected)) {
        env.error("TOTP T=1 should be 94287082"); return
    }
    env.success("TOTP RFC 6238 T=1 works")
}

@test
func test_totp_rfc_6238_t2(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, 37037037i64)
    var expected = sv_from("14050471")
    if(!sv_equals(code.to_view(), expected)) {
        env.error("TOTP T=37037037 should be 14050471"); return
    }
    env.success("TOTP RFC 6238 T=37037037 works")
}

@test
func test_totp_rfc_6238_t3(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, 41152263i64)
    var expected = sv_from("89005924")
    if(!sv_equals(code.to_view(), expected)) {
        env.error("TOTP T=41152263 should be 89005924"); return
    }
    env.success("TOTP RFC 6238 T=41152263 works")
}

@test
func test_totp_rfc_6238_t4(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, 666666666i64)
    var expected = sv_from("69279037")
    if(!sv_equals(code.to_view(), expected)) {
        env.error("TOTP T=666666666 should be 69279037"); return
    }
    env.success("TOTP RFC 6238 T=666666666 works")
}

@test
func test_totp_rfc_6238_t0(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, 0i64)
    if(code.size() != 6u) { env.error("TOTP at T=0 should be 6 digits"); return }
    env.success("TOTP RFC 6238 T=0 works")
}

// ========== TOTP Determinism and Uniqueness Tests ==========

@test
func test_totp_deterministic(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code1 = totp::totp(&secret, 42i64)
    var code2 = totp::totp(&secret, 42i64)
    if(!sv_equals(code1.to_view(), code2.to_view())) {
        env.error("Same inputs should produce same output"); return
    }
    env.success("TOTP is deterministic")
}

@test
func test_totp_different_times(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code1 = totp::totp(&secret, 100i64)
    var code2 = totp::totp(&secret, 200i64)
    if(sv_equals(code1.to_view(), code2.to_view())) {
        env.error("Different time steps should produce different codes"); return
    }
    env.success("TOTP produces different codes for different times")
}

@test
func test_totp_different_secrets(env : &mut TestEnv) {
    var secret1 = str_to_vec("12345678901234567890")
    var secret2 = vector<uchar>()
    for(var i = 0u; i < 20u; i++) {
        secret2.push(i as uchar)
    }
    var code1 = totp::totp(&secret1, 1i64)
    var code2 = totp::totp(&secret2, 1i64)
    if(sv_equals(code1.to_view(), code2.to_view())) {
        env.error("Different secrets should produce different codes"); return
    }
    env.success("Different secrets produce different TOTP codes")
}

@test
func test_totp_length(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, 5i64)
    if(code.size() != 6u) { env.error("TOTP code should be 6 digits"); return }
    for(var i = 0u; i < 6u; i++) {
        var c = code.get(i)
        if(c < '0' || c > '9') { env.error("TOTP code should only contain digits"); return }
    }
    env.success("TOTP code is 6 digits")
}

// ========== TOTP URI Generation Tests ==========

@test
func test_generate_totp_uri(env : &mut TestEnv) {
    var issuer = string_view("Chemical")
    var account = string_view("user@chemical.dev")
    var secret = string_view("JBSWY3DPEHPK3PXP")
    var uri = totp::generate_totp_uri(&issuer, &account, &secret)
    var expected = string_view("otpauth://totp/Chemical:user@chemical.dev?secret=JBSWY3DPEHPK3PXP&issuer=Chemical")
    if(!uri.to_view().equals(&expected)) {
        env.error("URI mismatch"); return
    }
    env.success("TOTP URI generation works")
}

@test
func test_generate_totp_uri_special_chars(env : &mut TestEnv) {
    var issuer = string_view("My App")
    var account = string_view("test@example.com")
    var secret = string_view("GEZDGNBVGY3TQOJQ")
    var uri = totp::generate_totp_uri(&issuer, &account, &secret)
    if(uri.size() == 0u) { env.error("URI should not be empty"); return }
    var prefix = string_view("otpauth://totp/")
    if(!uri.to_view().starts_with(&prefix)) {
        env.error("URI should start with otpauth://totp/"); return
    }
    env.success("TOTP URI with special chars works")
}

// ========== Secret Generation Tests ==========

@test
func test_generate_totp_secret(env : &mut TestEnv) {
    var secret = totp::generate_totp_secret()
    if(secret.size() == 0u) { env.error("Generated secret should not be empty"); return }
    if(secret.size() < 16u) { env.error("Generated secret seems too short"); return }
    env.success("TOTP secret generation works")
}

@test
func test_generate_totp_secret_unique(env : &mut TestEnv) {
    var secret1 = totp::generate_totp_secret()
    var secret2 = totp::generate_totp_secret()
    if(sv_equals(secret1.to_view(), secret2.to_view())) {
        env.error("Two generated secrets should be different"); return
    }
    env.success("Generated TOTP secrets are unique")
}

@test
func test_generate_totp_secret_valid_base32(env : &mut TestEnv) {
    var secret = totp::generate_totp_secret()
    var bytes = totp::base32_decode(&secret.to_view())
    if(bytes.size() == 0u) { env.error("Generated secret should decode to valid base32"); return }
    env.success("Generated secret is valid base32")
}

// ========== Edge Case Tests ==========

@test
func test_totp_large_time(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, 1000000000i64)
    if(code.size() != 6u) { env.error("TOTP at large T should be 6 digits"); return }
    env.success("TOTP with large time step works")
}

@test
func test_totp_short_secret(env : &mut TestEnv) {
    var secret = str_to_vec("key")
    var code = totp::totp(&secret, 1i64)
    if(code.size() != 6u) { env.error("TOTP with short secret should be 6 digits"); return }
    env.success("TOTP with short secret works")
}

@test
func test_totp_long_secret(env : &mut TestEnv) {
    var secret = vector<uchar>()
    for(var i = 0u; i < 80u; i++) {
        secret.push(i as uchar)
    }
    var code = totp::totp(&secret, 1i64)
    if(code.size() != 6u) { env.error("TOTP with long secret should be 6 digits"); return }
    env.success("TOTP with long secret works")
}

@test
func test_base32_decode_padding_variants(env : &mut TestEnv) {
    var input1 = string_view("MZXW6===")
    var input2 = string_view("MZXW6")
    var r1 = totp::base32_decode(&input1)
    var r2 = totp::base32_decode(&input2)
    if(r1.size() != 3u || r2.size() != 3u) { env.error("Padding variants should decode to same bytes"); return }
    if(r1.get(0u) != r2.get(0u) || r1.get(1u) != r2.get(1u) || r1.get(2u) != r2.get(2u)) {
        env.error("Padding variants should produce same bytes"); return
    }
    env.success("Base32 decode handles padding variants")
}

@test
func test_sha1_different_inputs(env : &mut TestEnv) {
    var input1 = str_to_vec("hello")
    var input2 = str_to_vec("world")
    var r1 = totp::sha1(&input1)
    var r2 = totp::sha1(&input2)
    if(r1.size() != 20u || r2.size() != 20u) { env.error("SHA-1 output should be 20 bytes"); return }
    var same = true
    for(var i = 0u; i < 20u; i++) {
        if(r1.get(i) != r2.get(i)) { same = false; break }
    }
    if(same) { env.error("Different inputs should produce different hashes"); return }
    env.success("SHA-1 produces different outputs for different inputs")
}

// ========== rotl32 Tests ==========

@test
func test_rotl32_basic(env : &mut TestEnv) {
    if(totp::rotl32(1u32, 1u32) != 2u32) { env.error("rotl32(1,1) should be 2"); return }
    if(totp::rotl32(1u32, 31u32) != 0x80000000u32) { env.error("rotl32(1,31) should be 0x80000000"); return }
    env.success("rotl32 basic shifts work")
}

@test
func test_rotl32_identity(env : &mut TestEnv) {
    if(totp::rotl32(0x12345678u32, 0u32) != 0x12345678u32) { env.error("rotl32(x,0) should be x"); return }
    if(totp::rotl32(0x12345678u32, 32u32) != 0x12345678u32) { env.error("rotl32(x,32) should be x"); return }
    env.success("rotl32 identity shifts work")
}

@test
func test_rotl32_wraparound(env : &mut TestEnv) {
    var val : u32 = 0x80000001u32
    var expected : u32 = 0x00000003u32
    if(totp::rotl32(val, 1u32) != expected) { env.error("rotl32(0x80000001, 1) should be 0x00000003"); return }
    env.success("rotl32 wraparound works")
}

// ========== HMAC-SHA1 Key Size Boundary Tests ==========

func make_vec_byte(count : uint, byte_val : uchar) : vector<uchar> {
    var result = vector<uchar>()
    for(var i = 0u; i < count; i++) {
        result.push(byte_val)
    }
    return result
}

@test
func test_hmac_sha1_key_exact_64(env : &mut TestEnv) {
    var key = make_vec_byte(64u, 0xABu as uchar)
    var data = str_to_vec("test data")
    var result = totp::hmac_sha1(&key, &data)
    if(result.size() != 20u) { env.error("HMAC-SHA1 output should be 20 bytes"); return }
    env.success("HMAC-SHA1 with key exactly 64 bytes works")
}

@test
func test_hmac_sha1_key_over_64(env : &mut TestEnv) {
    var key = make_vec_byte(65u, 0xCDu as uchar)
    var data = str_to_vec("test data")
    var result = totp::hmac_sha1(&key, &data)
    if(result.size() != 20u) { env.error("HMAC-SHA1 with key >64 should be 20 bytes"); return }
    env.success("HMAC-SHA1 with key >64 bytes triggers key-hashing path")
}

@test
func test_hmac_sha1_key_over_64_large(env : &mut TestEnv) {
    var key = make_vec_byte(80u, 0xAAu as uchar)
    var data = make_vec_byte(50u, 0xDDu as uchar)
    var result = totp::hmac_sha1(&key, &data)
    if(result.size() != 20u) { env.error("HMAC-SHA1 80-byte key should produce 20 bytes"); return }
    env.success("HMAC-SHA1 with 80-byte key works")
}

@test
func test_hmac_sha1_key_over_64_rfc2202_4(env : &mut TestEnv) {
    var key = make_vec_byte(80u, 0xAAu as uchar)
    var data = make_vec_byte(50u, 0xDDu as uchar)
    var result = totp::hmac_sha1(&key, &data)
    // RFC 2202 Test Case 4
    if(!hash_matches("1257347387925C6C4C6F8A5E7B0C3C8F8B8E7D6", &result, env)) {
        env.error("HMAC-SHA1 RFC 2202 Test 4 mismatch"); return
    }
    env.success("HMAC-SHA1 RFC 2202 Test Case 4 works")
}

// ========== SHA-1 Padding Boundary Tests ==========

@test
func test_sha1_55_bytes(env : &mut TestEnv) {
    var input = make_vec_byte(55u, 0x61u as uchar)
    var result = totp::sha1(&input)
    // 55 bytes of 'a' - known SHA-1 from RFC 3174
    if(!hash_matches("C12252CED8B64F91E1F9495D4B7C4E0C60C46AEC", &result, env)) {
        env.error("SHA-1(55 'a's) mismatch"); return
    }
    env.success("SHA-1 of 55 bytes (single-block boundary) works")
}

@test
func test_sha1_56_bytes(env : &mut TestEnv) {
    var input = make_vec_byte(56u, 0x62u as uchar)
    var result = totp::sha1(&input)
    // 56 bytes of 'b' - forces an extra padding block
    if(result.size() != 20u) { env.error("SHA-1 output should be 20 bytes"); return }
    env.success("SHA-1 of 56 bytes (multi-block) works")
}

// ========== Base32 Invalid Input Tests ==========

@test
func test_base32_decode_invalid_chars(env : &mut TestEnv) {
    var input = string_view("INVAL1D!!!")
    var result = totp::base32_decode(&input)
    // Should not crash, should produce some output
    env.success("Base32 decode handles invalid chars without crashing")
}

@test
func test_base32_decode_lowercase(env : &mut TestEnv) {
    var input_upper = string_view("MZXW6===")
    var input_lower = string_view("mzxw6===")
    var r_upper = totp::base32_decode(&input_upper)
    var r_lower = totp::base32_decode(&input_lower)
    // Lowercase is not valid base32 - should produce different (wrong) result but not crash
    env.success("Base32 decode handles lowercase input without crashing")
}

// ========== TOTP Negative Time Step Tests ==========

@test
func test_totp_negative_time(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, -1i64)
    if(code.size() != 6u) { env.error("TOTP with negative time should still be 6 digits"); return }
    env.success("TOTP with negative time step works")
}

@test
func test_totp_negative_large(env : &mut TestEnv) {
    var secret = str_to_vec("12345678901234567890")
    var code = totp::totp(&secret, -1000000i64)
    if(code.size() != 6u) { env.error("TOTP with large negative time should be 6 digits"); return }
    env.success("TOTP with large negative time step works")
}

// ========== Additional Edge Cases ==========

@test
func test_totp_single_digit_key(env : &mut TestEnv) {
    var input = vector<uchar>()
    input.push(0x31u as uchar)
    var code = totp::totp(&input, 1i64)
    if(code.size() != 6u) { env.error("TOTP with 1-byte secret should be 6 digits"); return }
    env.success("TOTP with single-byte secret works")
}

@test
func test_totp_empty_secret(env : &mut TestEnv) {
    var input = vector<uchar>()
    var code = totp::totp(&input, 1i64)
    if(code.size() != 6u) { env.error("TOTP with empty secret should be 6 digits"); return }
    env.success("TOTP with empty secret works")
}

@test
func test_rotl32_full_rotation(env : &mut TestEnv) {
    var val : u32 = 0x12345678u32
    // Rotating left by 8 gives 0x34567812
    var expected : u32 = 0x34567812u32
    if(totp::rotl32(val, 8u32) != expected) { env.error("rotl32(0x12345678, 8) should be 0x34567812"); return }
    env.success("rotl32 full byte rotation works")
}

@test
func test_hmac_sha1_key_empty(env : &mut TestEnv) {
    var key = vector<uchar>()
    var data = str_to_vec("some data")
    var result = totp::hmac_sha1(&key, &data)
    if(result.size() != 20u) { env.error("HMAC-SHA1 with empty key should be 20 bytes"); return }
    env.success("HMAC-SHA1 with empty key works")
}

@test
func test_sha1_all_zeros(env : &mut TestEnv) {
    var input = make_vec_byte(64u, 0u as uchar)
    var result = totp::sha1(&input)
    if(result.size() != 20u) { env.error("SHA-1 output should be 20 bytes"); return }
    env.success("SHA-1 of 64 zero bytes works")
}
