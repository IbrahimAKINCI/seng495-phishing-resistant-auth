"""Module C's own software passkey authenticator (a "soft key").

It produces the same JSON a browser returns from navigator.credentials.create() and .get(),
so the attack tests can talk to the service over HTTP without a browser. NFR-7: this file
does not import anything from the service, and it is written from the WebAuthn and COSE
specifications, not copied from Module A's test helper.

Every field an attacker could influence (origin, RP ID, ...) can be overridden per call.
That is how the attack tests build a "response made for another site".
"""
import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01   # user present
FLAG_UV = 0x04   # user verified (PIN or biometrics)
FLAG_AT = 0x40   # attested credential data follows (registration only)


def b64u(data: bytes) -> str:
    """base64url without padding: the encoding WebAuthn uses for binary values in JSON."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def from_b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def authenticator_data(rp_id: str, *, up: bool, uv: bool, counter: int, attested: bool = False) -> bytes:
    """The first 37 bytes of authenticatorData: SHA-256(rpId), flags, signature counter."""
    flags = (FLAG_UP if up else 0) | (FLAG_UV if uv else 0) | (FLAG_AT if attested else 0)
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", counter)


def cose_public_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """The public key as a CBOR-encoded COSE key (ES256, curve P-256)."""
    point = private_key.public_key().public_numbers()
    return cbor2.dumps({
        1: 2,                           # kty: EC2 (elliptic curve with x and y)
        3: -7,                          # alg: ES256 (ECDSA with SHA-256)
        -1: 1,                          # crv: P-256
        -2: point.x.to_bytes(32, "big"),
        -3: point.y.to_bytes(32, "big"),
    })


class SoftKey:
    """One passkey. `rp_id` and `origin` are the real service's values; they are what an
    honest browser would put in the response. A call can override them."""

    def __init__(self, rp_id: str, origin: str):
        self.rp_id = rp_id
        self.origin = origin
        self.private_key: ec.EllipticCurvePrivateKey | None = None
        self.credential_id = b""
        self.user_handle = b""
        self.counter = 0

    def _client_data(self, type_: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps({
            "type": type_, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False,
        }).encode()

    def register(self, options: dict, *, origin: str | None = None, rp_id: str | None = None,
                 up: bool = True, uv: bool = True) -> dict:
        """What the browser returns from navigator.credentials.create(): a new key pair, and
        the public key inside an attestationObject (format "none": no attestation)."""
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.user_handle = from_b64u(options["user"]["id"])
        self.counter = 0
        auth_data = (
            authenticator_data(rp_id or self.rp_id, up=up, uv=uv, counter=self.counter, attested=True)
            + bytes(16)                                       # AAGUID: all zero (no model information)
            + struct.pack(">H", len(self.credential_id))      # credential id length
            + self.credential_id
            + cose_public_key(self.private_key)
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        return {
            "id": b64u(self.credential_id),
            "rawId": b64u(self.credential_id),
            "type": "public-key",
            "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(attestation)},
            "clientExtensionResults": {},
        }

    def assertion(self, options: dict, *, origin: str | None = None, rp_id: str | None = None,
                  up: bool = True, uv: bool = True) -> dict:
        """What the browser returns from navigator.credentials.get(): the signature over
        authenticatorData || SHA-256(clientDataJSON). The signature is always made with the
        real private key, so only the fields passed in decide whether the response is valid."""
        self.counter += 1
        auth_data = authenticator_data(rp_id or self.rp_id, up=up, uv=uv, counter=self.counter)
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.private_key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64u(self.credential_id),
            "rawId": b64u(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client_data),
                "authenticatorData": b64u(auth_data),
                "signature": b64u(signature),
                "userHandle": b64u(self.user_handle),
            },
            "clientExtensionResults": {},
        }
