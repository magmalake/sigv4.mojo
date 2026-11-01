"""sigv4 — AWS Signature Version 4 for Mojo.

`sigv4.crypto` is SHA-256, HMAC-SHA256 and hex in pure Mojo (ARMv8 SHA-2 and
x86 SHA-NI backends chosen at compile time, scalar otherwise). `sigv4.signer`
is the signing algorithm itself: canonical request, string to sign, signing
key ladder, the `Authorization` header and presigned query strings.

```mojo
from sigv4.signer import AmzTime, Header, QueryParam, sign_request
from sigv4.crypto import sha256_hex

var body = String('{"Granularity":"MONTHLY"}')
var when = AmzTime.now()
var headers: List[Header] = [
    Header("host", "ce.us-east-1.amazonaws.com"),
    Header("x-amz-date", when.amz_date),
]
var signed = sign_request(
    "POST", "/", List[QueryParam](), headers, sha256_hex(body),
    access_key, secret_key, "us-east-1", "ce", when, normalize=True,
)
# send signed.authorization as the Authorization header
```
"""
