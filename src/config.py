# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

import os
from pathlib import Path
from dotenv import load_dotenv
from urllib.parse import urlsplit

def _parse_redirects(raw: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for part in raw.split(";"):
        audience, _, uris = part.partition("=")
        audience = audience.strip()
        if not audience:
            continue
        for uri in (u.strip() for u in uris.split(",")):
            if not uri:
                continue
            u = urlsplit(uri)
            if u.scheme not in {"http", "https"} or not u.netloc or u.fragment:
                raise ValueError(f"redirect_uri inválido: {uri}")
            out.setdefault(audience, set()).add(uri)
    return out

CONFIG_DIR = Path.home() / ".config" / "osiris"
ENV_PATH = CONFIG_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH)

ISSUER = os.getenv("OSIRIS_ISSUER", "osiris-auth-service")

AUTH_CODE_TTL = int(os.getenv("OSIRIS_AUTH_CODE_TTL_SECONDS", "60"))
ACCESS_TTL = int(os.getenv("OSIRIS_ACCESS_TTL_SECONDS", str(15 * 60)))
REFRESH_TTL = int(os.getenv("OSIRIS_REFRESH_TTL_SECONDS", str(30 * 24 * 3600)))
SESSION_MAX = int(os.getenv("OSIRIS_SESSION_MAX_SECONDS", str(90 * 24 * 3600)))

ADMIN_AUDIENCE = "osiris"
AUDIENCES = {
    a.strip()
    for a in os.getenv("OSIRIS_AUDIENCES", "blob-storage").split(",")
    if a.strip()
} | {ADMIN_AUDIENCE}

KEY_DIR = os.path.expanduser(os.getenv("OSIRIS_KEY_DIR", "~/osiris/keys"))
DATABASE_URL = os.getenv("OSIRIS_DATABASE_URL", "sqlite:///./osiris.db")

if DATABASE_URL and "sqlite:///" in DATABASE_URL:
    DATABASE_URL = f"sqlite:///{Path(DATABASE_URL.replace("sqlite:///", "")).expanduser()}"

MAX_FAILED_LOGINS = int(os.getenv("OSIRIS_MAX_FAILED_LOGINS", "5"))
LOCKOUT_SECONDS = int(os.getenv("OSIRIS_LOCKOUT_SECONDS", "900"))
LOGIN_IP_LIMIT = int(os.getenv("OSIRIS_LOGIN_IP_LIMIT", "20"))
LOGIN_USER_LIMIT = int(os.getenv("OSIRIS_LOGIN_USER_LIMIT", "10"))
REFRESH_IP_LIMIT = int(os.getenv("OSIRIS_REFRESH_IP_LIMIT", "60"))

TRUST_FORWARDED_FOR = os.getenv("OSIRIS_TRUST_FORWARDED_FOR", "0") == "1"
REGISTRATION_MODE = os.getenv("OSIRIS_REGISTRATION", "invite").strip().lower()

if REGISTRATION_MODE not in {"open", "invite", "closed"}:
    raise ValueError("OSIRIS_REGISTRATION debe ser open, invite o closed")

REGISTER_IP_LIMIT = int(os.getenv("OSIRIS_REGISTER_IP_LIMIT", "10"))
DEFAULT_ROLES = [r.strip() for r in os.getenv("OSIRIS_DEFAULT_ROLES", "user").split(",") if r.strip()]
INVITE_DEFAULT_TTL = 7 * 24 * 3600

BOOTSTRAP_ADMIN_USERNAME = os.getenv("OSIRIS_ADMIN_USERNAME")
BOOTSTRAP_ADMIN_PASSWORD = os.getenv("OSIRIS_ADMIN_PASSWORD")
BOOTSTRAP_ADMIN_TENANT = os.getenv("OSIRIS_ADMIN_TENANT", "system")

CLEANUP_INTERVAL_SECONDS = int(os.getenv("OSIRIS_CLEANUP_INTERVAL_SECONDS", "3600"))

REDIRECT_URIS = _parse_redirects(os.getenv("OSIRIS_REDIRECT_URIS", ""))
REDIRECT_ORIGINS = sorted({
    f"{urlsplit(u).scheme}://{urlsplit(u).netloc}"
    for uris in REDIRECT_URIS.values() for u in uris
})