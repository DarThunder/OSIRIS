# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

_DUMMY_HASH = _hasher.hash("osiris-dummy-password")

def hash_password(password: str) -> str:
    return _hasher.hash(password)

def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False

def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)

def new_refresh_token() -> str:
    return secrets.token_urlsafe(32)

def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 50_000:
                self._hits = defaultdict(deque, {k: v for k, v in self._hits.items() if v})
            return True
