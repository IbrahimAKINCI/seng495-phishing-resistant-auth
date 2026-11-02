"""A small software passkey authenticator for tests.

It produces the same responses a browser returns from navigator.credentials.create()
and .get(), so the server can be tested without a browser. Every field can be changed,
which is how the negative tests in test_webauthn.py break one check at a time.

End-to-end tests with the Chrome virtual authenticator (Playwright) come later, once
Module B's client exists."""
import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

RP_ID = "localhost"
ORIGIN = "http://localhost:8000"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def from_b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _flags(up: bool, uv: bool, attested: bool = False) -> int:
    return (0x01 if up else 0) | (0x04 if uv else 0) | (0x40 if attested else 0)


@dataclass
class StoredCredential:
    cred_id: bytes
    key: ec.EllipticCurvePrivateKey
    user_handle: bytes
    counter: int = 0


class SoftAuthenticator:
    def __init__(self):
        self.credentials: dict[bytes, StoredCredential] = {}

    def create(self, options: dict, *, origin=ORIGIN, rp_id=RP_ID, type_="webauthn.create",
               up=True, uv=True, challenge: str | None = None, reuse: StoredCredential | None = None) -> dict:
        if reuse is not None:
            cred = reuse
        else:
            cred = StoredCredential(os.urandom(16), ec.generate_private_key(ec.SECP256R1()), from_b64u(options["user"]["id"]))
            self.credentials[cred.cred_id] = cred
        nums = cred.key.public_key().public_numbers()
        cose_key = {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([_flags(up, uv, attested=True)])
            + struct.pack(">I", cred.counter)
            + bytes(16)  # AAGUID
            + struct.pack(">H", len(cred.cred_id))
            + cred.cred_id
            + cbor2.dumps(cose_key)
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = json.dumps({
            "type": type_, "challenge": challenge or options["challenge"], "origin": origin, "crossOrigin": False,
        }).encode()
        return {
            "id": b64u(cred.cred_id),
            "rawId": b64u(cred.cred_id),
            "type": "public-key",
            "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(attestation), "transports": ["internal"]},
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(self, options: dict, cred: StoredCredential | None = None, *, origin=ORIGIN, rp_id=RP_ID,
            type_="webauthn.get", up=True, uv=True, challenge: str | None = None,
            counter: int | None = None, flip_signature=False) -> dict:
        if cred is None:
            allowed = [from_b64u(c["id"]) for c in options.get("allowCredentials", [])]
            candidates = [c for c in self.credentials.values() if not allowed or c.cred_id in allowed]
            cred = candidates[0]
        cred.counter = cred.counter + 1 if counter is None else counter
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([_flags(up, uv)]) + struct.pack(">I", cred.counter)
        client_data = json.dumps({
            "type": type_, "challenge": challenge or options["challenge"], "origin": origin, "crossOrigin": False,
        }).encode()
        signature = cred.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        if flip_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
        return {
            "id": b64u(cred.cred_id),
            "rawId": b64u(cred.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client_data),
                "authenticatorData": b64u(auth_data),
                "signature": b64u(signature),
                "userHandle": b64u(cred.user_handle),
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
