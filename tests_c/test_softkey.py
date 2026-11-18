"""Checks of Module C's own software authenticator (harness/softkey.py).

The expected values here come from the WebAuthn and COSE specifications, written out by
hand, not from the code under test and not from the service's WebAuthn library:
  - authenticator data layout: 32-byte rpIdHash, 1 flags byte, 4-byte big-endian counter
    (WebAuthn Level 2, Section 6.1); flag bits UP = 0x01, UV = 0x04, AT = 0x40
  - COSE key for ES256: {1: 2, 3: -7, -1: 1, -2: x, -3: y} (RFC 8152, Section 13.1.1)
  - base64url without padding (RFC 4648, Section 5), e.g. b"\xfb\xff" -> "-_8"
  - an ECDSA signature must verify with the public key taken from the COSE key
"""
import hashlib
import json

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from harness import softkey

RP = "example.test"
ORIGIN = "https://example.test"


def test_base64url_has_no_padding_and_uses_the_url_alphabet():
    assert softkey.b64u(b"\xfb\xff") == "-_8"      # standard base64 would give "+/8="
    assert softkey.b64u(b"a") == "YQ"
    assert softkey.from_b64u("YQ") == b"a"
    assert softkey.from_b64u("-_8") == b"\xfb\xff"


def test_authenticator_data_layout():
    data = softkey.authenticator_data(RP, up=True, uv=False, counter=0x01020304)
    assert data[:32] == hashlib.sha256(b"example.test").digest()
    assert data[32] == 0x01                         # only the user presence bit
    assert data[33:37] == bytes([1, 2, 3, 4])       # big-endian counter
    assert len(data) == 37


def test_flags_bits():
    assert softkey.authenticator_data(RP, up=True, uv=True, counter=0)[32] == 0x05
    assert softkey.authenticator_data(RP, up=False, uv=False, counter=0)[32] == 0x00
    assert softkey.authenticator_data(RP, up=True, uv=True, counter=0, attested=True)[32] == 0x45


def test_cose_key_is_an_es256_key_with_the_right_point():
    key = ec.generate_private_key(ec.SECP256R1())
    cose = cbor2.loads(softkey.cose_public_key(key))
    assert cose[1] == 2 and cose[3] == -7 and cose[-1] == 1
    numbers = key.public_key().public_numbers()
    assert int.from_bytes(cose[-2], "big") == numbers.x
    assert int.from_bytes(cose[-3], "big") == numbers.y
    assert len(cose[-2]) == 32 and len(cose[-3]) == 32


def _options(challenge=b"\x01" * 32):
    return {"challenge": softkey.b64u(challenge), "rp": {"id": RP}, "user": {"id": softkey.b64u(b"user-1")}}


def test_registration_response_contains_the_credential_and_a_matching_public_key():
    key = softkey.SoftKey(rp_id=RP, origin=ORIGIN)
    cred = key.register(_options())
    client_data = json.loads(softkey.from_b64u(cred["response"]["clientDataJSON"]))
    assert client_data["type"] == "webauthn.create"
    assert client_data["origin"] == ORIGIN
    assert client_data["challenge"] == softkey.b64u(b"\x01" * 32)

    attestation = cbor2.loads(softkey.from_b64u(cred["response"]["attestationObject"]))
    assert attestation["fmt"] == "none"
    auth_data = attestation["authData"]
    assert auth_data[:32] == hashlib.sha256(RP.encode()).digest()
    assert auth_data[32] & 0x40                     # attested credential data is present
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    assert auth_data[55:55 + cred_id_len] == softkey.from_b64u(cred["rawId"])
    cose = cbor2.loads(auth_data[55 + cred_id_len:])
    assert cose[1] == 2 and cose[3] == -7


def test_assertion_signature_verifies_with_the_registered_public_key():
    key = softkey.SoftKey(rp_id=RP, origin=ORIGIN)
    reg = key.register(_options())
    auth_data = cbor2.loads(softkey.from_b64u(reg["response"]["attestationObject"]))["authData"]
    cose = cbor2.loads(auth_data[55 + int.from_bytes(auth_data[53:55], "big"):])
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()).public_key()

    assertion = key.assertion(_options(b"\x02" * 32))
    resp = assertion["response"]
    signed = softkey.from_b64u(resp["authenticatorData"]) + hashlib.sha256(softkey.from_b64u(resp["clientDataJSON"])).digest()
    public.verify(softkey.from_b64u(resp["signature"]), signed, ec.ECDSA(hashes.SHA256()))  # raises if invalid

    assert assertion["rawId"] == reg["rawId"]
    assert json.loads(softkey.from_b64u(resp["clientDataJSON"]))["type"] == "webauthn.get"


def test_the_counter_goes_up_with_every_assertion():
    key = softkey.SoftKey(rp_id=RP, origin=ORIGIN)
    key.register(_options())
    counters = []
    for _ in range(3):
        a = key.assertion(_options())
        counters.append(int.from_bytes(softkey.from_b64u(a["response"]["authenticatorData"])[33:37], "big"))
    assert counters == [1, 2, 3]


def test_origin_and_rp_id_can_be_overridden_for_an_attack():
    key = softkey.SoftKey(rp_id=RP, origin=ORIGIN)
    key.register(_options())
    a = key.assertion(_options(), origin="https://evil.example", rp_id="evil.example")
    client_data = json.loads(softkey.from_b64u(a["response"]["clientDataJSON"]))
    assert client_data["origin"] == "https://evil.example"
    assert softkey.from_b64u(a["response"]["authenticatorData"])[:32] == hashlib.sha256(b"evil.example").digest()
