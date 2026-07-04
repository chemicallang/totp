# totp

Time-based One-Time Password (TOTP) implementation in pure Chemical — no external dependencies. Implements RFC 6238 with SHA-1 HMAC.

Includes SHA-1, HMAC-SHA1, Base32 encode/decode, and the full TOTP code generation pipeline.

## Running Tests

```bash
chemical chemical.mod -o build/test.exe --test
build/test.exe
```

## Usage

In your `chemical.mod`:

```chmod
import "github.com/chemicallang/totp"
```

## Example

```chemical
using totp;
using std::vector;
using std::string;
using std::string_view;

func main() : int {
    // 1. Generate a random secret (base32-encoded)
    var secret = totp::generate_totp_secret();
    printf("Secret: %s\n", secret.data());

    // 2. Decode the base32 secret to raw bytes
    var secret_bytes = totp::base32_decode(&secret.to_view());

    // 3. Generate a TOTP code for the current time step
    var now = time(null) as i64;
    var time_step = now / 30i64;
    var code = totp::totp(&secret_bytes, time_step);
    printf("TOTP code: %s\n", code.data());

    // 4. Validate a code (checks current ± 1 time step)
    if(totp::validate_totp_code(&secret.to_view(), &code.to_view())) {
        printf("Code is valid!\n");
    }

    // 5. Generate an otpauth:// URI for QR codes
    var uri = totp::generate_totp_uri(&string_view("MyApp"),
                                      &string_view("user@example.com"),
                                      &secret.to_view());
    printf("URI: %s\n", uri.data());

    return 0;
}
```

## API

| Function | Description |
|----------|-------------|
| `totp::sha1(message)` | SHA-1 hash, returns 20-byte `vector<uchar>` |
| `totp::hmac_sha1(key, message)` | HMAC-SHA1, returns 20-byte `vector<uchar>` |
| `totp::base32_encode(data)` | Base32 encode, returns `string` |
| `totp::base32_decode(input)` | Base32 decode, returns `vector<uchar>` |
| `totp::totp(secret_bytes, time_step)` | Generate 6-digit TOTP code |
| `totp::generate_totp_secret()` | Generate random 20-byte secret, base32-encoded |
| `totp::generate_totp_uri(issuer, account, secret)` | Generate `otpauth://` URI |
| `totp::validate_totp_code(secret_base32, code)` | Validate code against current ± 1 time step |
