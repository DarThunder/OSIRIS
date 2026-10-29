# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

"""Almacén de llaves Ed25519 de OSIRIS, con rotación.

Cada llave es un PEM (PKCS8, permisos 600) en KEY_DIR, llamado `<timestamp_ms>-<kid>.pem`.
  - La llave ACTIVA (la que firma) es la de nombre más reciente.
  - TODAS se publican en el JWKS, para que los tokens firmados con una llave anterior
    sigan siendo verificables mientras no expiren. Cuando pasen al menos ACCESS_TTL desde
    la rotación, la llave vieja se puede borrar del directorio.
  - El `kid` es el thumbprint RFC 7638 de la llave pública.

CLI:
    python keys.py list
    python keys.py rotate
"""
import base64
import hashlib
import json
import os
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _public_x(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64u(raw)

def thumbprint(x: str) -> str:
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    return _b64u(hashlib.sha256(canonical.encode()).digest())

class KeyStore:
    def __init__(self, key_dir: str):
        self.key_dir = key_dir
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        self._lock = threading.RLock()
        self._signature: tuple | None = None
        self._keys: dict[str, tuple[Ed25519PrivateKey, str]] = {}
        self._active_kid: str | None = None
        self._reload(force=True)
        if not self._keys:
            self.rotate()

    def _dir_signature(self) -> tuple:
        return tuple(sorted(n for n in os.listdir(self.key_dir) if n.endswith(".pem")))

    def _reload(self, force: bool = False) -> None:
        with self._lock:
            sig = self._dir_signature()
            if not force and sig == self._signature:
                return
            keys: dict[str, tuple[Ed25519PrivateKey, str]] = {}
            active = None
            for name in sig:
                with open(os.path.join(self.key_dir, name), "rb") as f:
                    priv = serialization.load_pem_private_key(f.read(), password=None)
                if not isinstance(priv, Ed25519PrivateKey):
                    raise ValueError(f"{name} no es una llave Ed25519")
                x = _public_x(priv)
                kid = thumbprint(x)
                keys[kid] = (priv, x)
                active = kid
            self._keys, self._active_kid, self._signature = keys, active, sig

    def rotate(self) -> str:
        with self._lock:
            priv = Ed25519PrivateKey.generate()
            kid = thumbprint(_public_x(priv))
            path = os.path.join(self.key_dir, f"{int(time.time() * 1000):015d}-{kid}.pem")
            pem = priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
                f.flush()
                os.fsync(f.fileno())
            self._reload(force=True)
            return kid

    def signing_key(self) -> tuple[str, Ed25519PrivateKey]:
        with self._lock:
            self._reload()
            assert self._active_kid is not None
            return self._active_kid, self._keys[self._active_kid][0]

    def jwks(self) -> dict:
        with self._lock:
            self._reload()
            return {
                "keys": [
                    {"kty": "OKP", "crv": "Ed25519", "x": x, "use": "sig", "alg": "EdDSA", "kid": kid}
                    for kid, (_priv, x) in self._keys.items()
                ]
            }

if __name__ == "__main__":
    import sys

    import config

    store = KeyStore(config.KEY_DIR)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "rotate":
        print("nueva llave activa:", store.rotate())
    elif cmd == "list":
        active = store.signing_key()[0]
        for k in store.jwks()["keys"]:
            print(k["kid"], "(activa)" if k["kid"] == active else "")
    else:
        sys.exit("uso: python keys.py [list|rotate]")
