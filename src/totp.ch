public namespace totp {

public func rotl32(value : u32, shift : u32) : u32 {
    return (value << shift) | (value >> (32u - shift))
}

public func sha1(message : &std::vector<uchar>) : std::vector<uchar> {
    var h0 : u32 = 0x67452301u32
    var h1 : u32 = 0xEFCDAB89u32
    var h2 : u32 = 0x98BADCFEu32
    var h3 : u32 = 0x10325476u32
    var h4 : u32 = 0xC3D2E1F0u32

    var ml_bits = message.size() as u64 * 8u64

    var padded = std::vector<uchar>()
    for(var i = 0u; i < message.size(); i++) {
        padded.push(message.get(i))
    }
    padded.push(0x80u as uchar)
    while(padded.size() % 64u != 56u) {
        padded.push(0u as uchar)
    }
    padded.push((ml_bits >> 56u) as uchar)
    padded.push((ml_bits >> 48u) as uchar)
    padded.push((ml_bits >> 40u) as uchar)
    padded.push((ml_bits >> 32u) as uchar)
    padded.push((ml_bits >> 24u) as uchar)
    padded.push((ml_bits >> 16u) as uchar)
    padded.push((ml_bits >> 8u) as uchar)
    padded.push(ml_bits as uchar)

    var block_idx = 0u
    while(block_idx < padded.size()) {
        var w : [80]u32
        for(var i = 0; i < 16; i++) {
            var idx = block_idx + (i * 4) as uint
            w[i] = (padded.get(idx) as u32) << 24u |
                   (padded.get(idx + 1u) as u32) << 16u |
                   (padded.get(idx + 2u) as u32) << 8u |
                   (padded.get(idx + 3u) as u32)
        }
        for(var i = 16; i < 80; i++) {
            w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1u)
        }

        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4

        for(var i = 0; i < 80; i++) {
            var f : u32
            var k : u32
            if(i < 20) {
                f = (b & c) | ((~b) & d)
                k = 0x5A827999u32
            } else if(i < 40) {
                f = b ^ c ^ d
                k = 0x6ED9EBA1u32
            } else if(i < 60) {
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDCu32
            } else {
                f = b ^ c ^ d
                k = 0xCA62C1D6u32
            }

            var temp = rotl32(a, 5u) + f + e + k + w[i]
            e = d
            d = c
            c = rotl32(b, 30u)
            b = a
            a = temp
        }

        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e

        block_idx += 64u
    }

    var result = std::vector<uchar>()
    result.push((h0 >> 24u) as uchar)
    result.push((h0 >> 16u) as uchar)
    result.push((h0 >> 8u) as uchar)
    result.push(h0 as uchar)
    result.push((h1 >> 24u) as uchar)
    result.push((h1 >> 16u) as uchar)
    result.push((h1 >> 8u) as uchar)
    result.push(h1 as uchar)
    result.push((h2 >> 24u) as uchar)
    result.push((h2 >> 16u) as uchar)
    result.push((h2 >> 8u) as uchar)
    result.push(h2 as uchar)
    result.push((h3 >> 24u) as uchar)
    result.push((h3 >> 16u) as uchar)
    result.push((h3 >> 8u) as uchar)
    result.push(h3 as uchar)
    result.push((h4 >> 24u) as uchar)
    result.push((h4 >> 16u) as uchar)
    result.push((h4 >> 8u) as uchar)
    result.push(h4 as uchar)
    return result
}

public func hmac_sha1(key : &std::vector<uchar>, message : &std::vector<uchar>) : std::vector<uchar> {
    var k : [64]uchar
    if(key.size() > 64u) {
        var hashed = sha1(key)
        for(var i = 0u; i < 20u; i++) k[i] = hashed.get(i)
        for(var i = 20u; i < 64u; i++) k[i] = 0u as uchar
    } else {
        for(var i = 0u; i < key.size(); i++) k[i] = key.get(i)
        for(var i = key.size(); i < 64u; i++) k[i] = 0u as uchar
    }

    var inner_key : [64]uchar
    var outer_key : [64]uchar
    for(var i = 0u; i < 64u; i++) {
        inner_key[i] = (k[i] as uchar) ^ 0x36u as uchar
        outer_key[i] = (k[i] as uchar) ^ 0x5Cu as uchar
    }

    var inner_data = std::vector<uchar>()
    for(var i = 0u; i < 64u; i++) inner_data.push(inner_key[i])
    for(var i = 0u; i < message.size(); i++) inner_data.push(message.get(i))
    var inner_hash = sha1(&inner_data)

    var outer_data = std::vector<uchar>()
    for(var i = 0u; i < 64u; i++) outer_data.push(outer_key[i])
    for(var i = 0u; i < inner_hash.size(); i++) outer_data.push(inner_hash.get(i))
    return sha1(&outer_data)
}

func dynamic_truncate(hash : &std::vector<uchar>) : u32 {
    var offset = hash.get(19u) as u32 & 0x0Fu
    var value = (hash.get(offset) as u32) << 24u |
                (hash.get(offset + 1u) as u32) << 16u |
                (hash.get(offset + 2u) as u32) << 8u |
                (hash.get(offset + 3u) as u32)
    return value & 0x7FFFFFFFu32
}

public func totp(secret_bytes : &std::vector<uchar>, time_step : i64) : std::string {
    var counter = std::vector<uchar>()
    counter.push((time_step >> 56) as uchar)
    counter.push((time_step >> 48) as uchar)
    counter.push((time_step >> 40) as uchar)
    counter.push((time_step >> 32) as uchar)
    counter.push((time_step >> 24) as uchar)
    counter.push((time_step >> 16) as uchar)
    counter.push((time_step >> 8) as uchar)
    counter.push(time_step as uchar)

    var hmac_result = hmac_sha1(secret_bytes, &counter)
    var value = dynamic_truncate(&hmac_result)
    var code_num = value % 1000000u32

    var result = std::string()
    var divisor : u32 = 100000u32
    var remaining = code_num
    for(var i = 0; i < 6; i++) {
        var digit = remaining / divisor
        result.append((digit as u32 + 48u) as char)
        remaining = remaining % divisor
        divisor = divisor / 10u
    }
    return result
}

public func base32_encode(data : &std::vector<uchar>) : std::string {
    const BASE32_ALPHABET = std::string_view("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var result = std::string()
    var i = 0u
    var bits = 0u
    var buffer : u32 = 0u

    while(i < data.size()) {
        buffer = (buffer << 8u) | (data.get(i) as u32)
        bits += 8u
        while(bits >= 5u) {
            bits -= 5u
            var index = (buffer >> bits) & 0x1Fu
            result.append(BASE32_ALPHABET.get(index))
        }
        i++
    }

    if(bits > 0u) {
        buffer = buffer << (5u - bits)
        var index = buffer & 0x1Fu
        result.append(BASE32_ALPHABET.get(index))
    }

    while(result.size() % 8u != 0u) {
        result.append('=')
    }

    return result
}

func base32_char_value(c : char) : uchar {
    if(c >= 'A' && c <= 'Z') return (c - 'A') as uchar
    if(c >= '2' && c <= '7') return (c - '2' + 26) as uchar
    return 0u as uchar
}

public func base32_decode(input : &std::string_view) : std::vector<uchar> {
    var result = std::vector<uchar>()
    var buffer : u32 = 0u
    var bits = 0u

    for(var i = 0u; i < input.size(); i++) {
        var c = input.get(i)
        if(c == '=') break
        buffer = (buffer << 5u) | (base32_char_value(c) as u32)
        bits += 5u
        if(bits >= 8u) {
            bits -= 8u
            result.push((buffer >> bits) as uchar)
            buffer = buffer & ((1u << bits) - 1u)
        }
    }
    return result
}

public func generate_totp_secret() : std::string {
    var bytes = std::vector<uchar>()
    for(var i = 0u; i < 20u; i++) {
        bytes.push((rand() % 256) as uchar)
    }
    return base32_encode(&bytes)
}

public func generate_totp_uri(issuer : &std::string_view, account_name : &std::string_view, secret : &std::string_view) : std::string {
    var uri = std::string()
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

public func validate_totp_code(secret_base32 : &std::string_view, code : &std::string_view) : bool {
    if(secret_base32.size() == 0u) return false
    var secret_bytes = base32_decode(secret_base32)
    if(secret_bytes.size() == 0u) return false

    var now = time(null) as i64
    var time_step = now / 30i64

    var steps : [3]i64
    steps[0] = time_step
    steps[1] = time_step + 1i64
    steps[2] = if(time_step > 0i64) time_step - 1i64 else 0i64
    for(var i = 0; i < 3; i++) {
        var expected = totp(&secret_bytes, steps[i])
        if(expected.to_view().equals(code)) return true
    }
    return false
}

}
