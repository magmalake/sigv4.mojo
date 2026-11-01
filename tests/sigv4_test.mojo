"""Test suite for sigv4.mojo — no network, no server.

SHA-256 against the FIPS 180-4 vectors (and OpenSSL's libcrypto as an oracle
when the environment has one), HMAC against RFC 4231, and the signer against
every usable case of the published `aws-sig-v4-test-suite`.
"""

from std.os import getenv
from std.os.path import exists as path_exists
from std.ffi import OwnedDLHandle, c_size_t
from std.testing import TestSuite, assert_equal, assert_raises, assert_true

from sigv4_vectors import sigv4_cases

from sigv4.crypto import (
    Sha256,
    from_hex,
    hmac_sha256,
    sha256,
    sha256_backend,
    sha256_hex,
    sha256_scalar,
    sha256_target_features,
    to_hex,
)
from sigv4.signer import (
    AmzTime,
    QueryParam,
    canonical_path,
    canonical_query,
    sign_request,
    url_encode,
)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for k in range(len(b)):
        out.append(b[k])
    return out^


def _repeat(byte: UInt8, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(byte)
    return out^


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------


def test_sha256_vectors() raises:
    assert_equal(
        sha256_hex(String("abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    assert_equal(
        sha256_hex(String("")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert_equal(
        sha256_hex(
            String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        ),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )


def test_sha256_one_million_a() raises:
    """FIPS 180-4's long-message vector, fed in awkward chunk sizes so the
    block-buffering path is exercised rather than the aligned one."""
    var h = Sha256()
    var chunk = _repeat(97, 1000)
    for _ in range(1000):
        h.update(Span(chunk))
    assert_equal(
        to_hex(Span(h.digest())),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )

    var h2 = Sha256()
    var odd = _repeat(97, 7)
    for _ in range(142857):
        h2.update(Span(odd))
    h2.update(Span(_repeat(97, 1)))
    assert_equal(
        to_hex(Span(h2.digest())),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )


@always_inline
def _xorshift32(mut state: UInt32) -> UInt32:
    """A deterministic PRNG, so a failure is reproducible from the seed alone.
    """
    var x = state
    x ^= x << UInt32(13)
    x ^= x >> UInt32(17)
    x ^= x << UInt32(5)
    state = x
    return x


def _random_bytes(mut state: UInt32, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(UInt8(Int(_xorshift32(state) & UInt32(0xFF))))
    return out^


@always_inline
def _digests_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for k in range(len(a)):
        if a[k] != b[k]:
            return False
    return True


def test_sha256_hardware_matches_scalar() raises:
    """Cross-check whichever backend this build compiled in against the
    portable one, over 1000 pseudo-random buffers of 0..10 KB.

    The FIPS vectors cover three lengths; a message-schedule bug in the
    hardware path would sail past them and show up only at some particular
    block count, so the randomized sweep is the test that actually guards the
    intrinsics. Mismatches are counted and asserted once — `assert_equal` is
    expensive enough that a thousand of them would dominate the suite.
    """
    print("sha256 backend:", sha256_backend())
    print("sha256 target features:", sha256_target_features())
    var rng = UInt32(0x9E3779B9)
    var buf = _random_bytes(rng, 10240)
    var bad = 0
    var checked = 0
    for trial in range(1000):
        if trial % 100 == 0:
            buf = _random_bytes(rng, 10240)
        var n = Int(_xorshift32(rng) % UInt32(10241))
        var span = Span(buf)[0:n]
        if not _digests_equal(sha256(span), sha256_scalar(span)):
            bad += 1
            print("sha256 != sha256_scalar at length", n)
        checked += 1
    assert_equal(checked, 1000)
    assert_equal(bad, 0)


def test_sha256_streaming_matches_one_shot() raises:
    """The same bytes fed in ragged chunks must hash the same as one call —
    the multi-block fast path only runs on the whole-blocks remainder, so the
    held-over partial block is where a streaming bug would hide."""
    var rng = UInt32(0x12345678)
    var buf = _random_bytes(rng, 5000)
    var bad = 0
    for _ in range(200):
        var n = Int(_xorshift32(rng) % UInt32(5001))
        var h = Sha256()
        var off = 0
        while off < n:
            var take = Int(_xorshift32(rng) % UInt32(200)) + 1
            if off + take > n:
                take = n - off
            h.update(Span(buf)[off : off + take])
            off += take
        if not _digests_equal(h.digest(), sha256(Span(buf)[0:n])):
            bad += 1
            print("streaming != one-shot at length", n)
    assert_equal(bad, 0)


def _libcrypto_path() -> String:
    """libcrypto ships in this environment as a libcurl dependency. It is a
    test-only oracle — nothing in `sigv4` links it."""
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix == "":
        return String("")
    var candidates: List[String] = [
        String("/lib/libcrypto.3.dylib"),
        String("/lib/libcrypto.so.3"),
        String("/lib/libcrypto.dylib"),
        String("/lib/libcrypto.so"),
    ]
    for k in range(len(candidates)):
        var path = prefix + candidates[k]
        if path_exists(path):
            return path^
    return String("")


def test_sha256_matches_openssl() raises:
    """Cross-check against a second, independent implementation: OpenSSL's
    `SHA256()`. libcrypto is already in the environment as a libcurl
    dependency — this is a test-only oracle, nothing in `objectstore` links
    it."""
    var path = _libcrypto_path()
    if path == "":
        print("SKIP test_sha256_matches_openssl: no libcrypto in CONDA_PREFIX")
        return
    var lib = OwnedDLHandle(path)
    var f = lib.get_function[Pointer[UInt8, MutUntrackedOrigin]]("SHA256")
    var rng = UInt32(0xC0FFEE11)
    var buf = _random_bytes(rng, 10240)
    var out = List[UInt8](length=32, fill=0)
    var bad = 0
    var checked = 0
    for trial in range(1000):
        if trial % 100 == 0:
            buf = _random_bytes(rng, 10240)
        var n = Int(_xorshift32(rng) % UInt32(10241))
        _ = f(buf.unsafe_ptr(), c_size_t(n), out.unsafe_ptr())
        var span = Span(buf)[0:n]
        if not _digests_equal(sha256(span), out):
            bad += 1
            print("sha256 != OpenSSL at length", n)
        if not _digests_equal(sha256_scalar(span), out):
            bad += 1
            print("sha256_scalar != OpenSSL at length", n)
        checked += 1
    assert_equal(checked, 1000)
    assert_equal(bad, 0)
    # Keep `lib` alive past `f`'s last call in the loop above: Mojo destroys a
    # value at its last syntactic use, and `f` was obtained from
    # `lib.get_function`, so without this `lib.__del__` (dlclose) would run
    # before the loop even started — see the FFI-handle-lifetime note in
    # src/objectstore/http.mojo.
    _ = lib^
    _ = buf^
    _ = out^


def test_hmac_sha256_rfc4231() raises:
    assert_equal(
        to_hex(Span(hmac_sha256(Span(_repeat(0x0B, 20)), String("Hi There")))),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    )
    assert_equal(
        to_hex(
            Span(
                hmac_sha256(
                    _bytes(String("Jefe")),
                    String("what do ya want for nothing?"),
                )
            )
        ),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    )
    assert_equal(
        to_hex(
            Span(hmac_sha256(Span(_repeat(0xAA, 20)), Span(_repeat(0xDD, 50))))
        ),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    )
    var key4 = List[UInt8]()
    for i in range(1, 26):
        key4.append(UInt8(i))
    assert_equal(
        to_hex(Span(hmac_sha256(Span(key4), Span(_repeat(0xCD, 50))))),
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    )
    # Cases 6 and 7: a key longer than the 64-byte block, which must be
    # hashed down first.
    assert_equal(
        to_hex(
            Span(
                hmac_sha256(
                    Span(_repeat(0xAA, 131)),
                    String(
                        "Test Using Larger Than Block-Size Key - Hash Key First"
                    ),
                )
            )
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    )
    assert_equal(
        to_hex(
            Span(
                hmac_sha256(
                    Span(_repeat(0xAA, 131)),
                    String(
                        "This is a test using a larger than block-size key"
                        " and a larger than block-size data. The key needs"
                        " to be hashed before being used by the HMAC"
                        " algorithm."
                    ),
                )
            )
        ),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    )


def test_hex_roundtrip() raises:
    var data = List[UInt8]()
    for i in range(256):
        data.append(UInt8(i))
    var hex = to_hex(Span(data))
    assert_equal(hex.byte_length(), 512)
    var back = from_hex(hex)
    assert_equal(len(back), 256)
    for i in range(256):
        assert_equal(back[i], UInt8(i))
    with assert_raises():
        _ = from_hex(String("abc"))
    with assert_raises():
        _ = from_hex(String("zz"))


# ---------------------------------------------------------------------------
# signer
# ---------------------------------------------------------------------------


def test_url_encode() raises:
    assert_equal(url_encode(String("a b")), "a%20b")
    assert_equal(url_encode(String("a/b")), "a%2Fb")
    assert_equal(url_encode(String("a/b"), encode_slash=False), "a/b")
    assert_equal(url_encode(String("-._~")), "-._~")
    assert_equal(url_encode(String("ሴ")), "%E1%88%B4")


def test_sigv4_test_suite() raises:
    """Every usable case of the published `aws-sig-v4-test-suite`."""
    var cases = sigv4_cases()
    assert_true(len(cases) >= 30)
    for i in range(len(cases)):
        ref c = cases[i]
        var when = AmzTime.from_amz_date(c.amz_date)
        var got = sign_request(
            c.method,
            c.path,
            c.params,
            c.headers,
            c.payload_hash,
            c.access_key,
            c.secret_key,
            c.region,
            c.service,
            when,
            c.normalize,
        )
        assert_equal(got.canonical_request, c.canonical)
        assert_equal(got.string_to_sign, c.sts)
        assert_equal(got.signature, c.signature)


def test_sigv4_canonical_pieces() raises:
    # S3 does not normalize: `..` is a legal key segment.
    assert_equal(canonical_path(String("/a/../b"), False), "/a/../b")
    assert_equal(canonical_path(String("/a/../b"), True), "/b")
    assert_equal(canonical_path(String(""), False), "/")
    assert_equal(canonical_path(String("/a b"), False), "/a%20b")

    var params = List[QueryParam]()
    params.append(QueryParam("b", "2"))
    params.append(QueryParam("a", "1"))
    params.append(QueryParam("a", "0"))
    assert_equal(canonical_query(params), "a=0&a=1&b=2")


def test_amz_time_from_epoch() raises:
    # 2015-08-30T12:36:00Z, the test suite's timestamp.
    var t = AmzTime.from_epoch(1440938160)
    assert_equal(t.amz_date, "20150830T123600Z")
    assert_equal(t.date_stamp, "20150830")
    # A leap day, and the epoch itself.
    assert_equal(AmzTime.from_epoch(1709208000).date_stamp, "20240229")
    assert_equal(AmzTime.from_epoch(0).amz_date, "19700101T000000Z")
    assert_equal(AmzTime.now().amz_date.byte_length(), 16)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
