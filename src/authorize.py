# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

import base64
import hashlib
import logging
import secrets
from pathlib import Path
from typing import Annotated, Callable, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, StringConstraints
from sqlalchemy import select, update
from sqlalchemy.orm import Session

import config
from db import AuthCode, User, get_db, now_ts
from schemas import TokenResponse
from security import hash_password, hash_refresh_token, needs_rehash, new_refresh_token, verify_password

logger = logging.getLogger("osiris.authorize")

_CHALLENGE_RE = r"^[A-Za-z0-9_-]{43}$"
_VERIFIER_RE = r"^[A-Za-z0-9._~-]{43,128}$"

class AuthorizeRequest(BaseModel):
    username: Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, min_length=1, max_length=128)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    audience: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    redirect_uri: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    code_challenge: Annotated[str, StringConstraints(pattern=_CHALLENGE_RE)]
    code_challenge_method: Literal["S256"] = "S256"
    state: Annotated[str, StringConstraints(max_length=512)] | None = None

class AuthorizeResponse(BaseModel):
    redirect_to: str

class CodeExchangeRequest(BaseModel):
    code: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    code_verifier: Annotated[str, StringConstraints(pattern=_VERIFIER_RE)]
    redirect_uri: Annotated[str, StringConstraints(min_length=1, max_length=2048)]

def _unauthorized() -> HTTPException:
    return HTTPException(401, "Credenciales inválidas", headers={"WWW-Authenticate": "Bearer"})

def _invalid_grant() -> HTTPException:
    return HTTPException(400, "Code inválido, expirado o ya usado")

def _check_target(audience: str, redirect_uri: str) -> None:
    allowed = config.REDIRECT_URIS.get(audience)
    if audience not in config.AUDIENCES or not allowed or redirect_uri not in allowed:
        raise HTTPException(400, "Audiencia o redirect_uri no permitidos")

def _pkce_ok(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(computed, challenge)

def _with_params(uri: str, params: dict[str, str]) -> str:
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True) + list(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

def authenticate(db: Session, username: str, password: str) -> User:
    now = now_ts()
    user = db.scalar(select(User).where(User.username == username))
    password_ok = verify_password(user.password_hash if user else None, password)

    if user is None or not user.is_active or user.locked_until > now:
        raise _unauthorized()
    if not password_ok:
        user.failed_attempts += 1
        if user.failed_attempts >= config.MAX_FAILED_LOGINS:
            user.locked_until = now + config.LOCKOUT_SECONDS
            user.failed_attempts = 0
            logger.warning("Cuenta bloqueada temporalmente: %s", user.username)
        db.commit()
        raise _unauthorized()

    user.failed_attempts = 0
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user

def build_router(
    *,
    rate_limit: Callable[[str, int], None],
    client_ip: Callable[[Request], str],
    create_session_token: Callable,
    token_response: Callable,
    web_dir: Path,
) -> APIRouter:
    router = APIRouter(tags=["authorize"])
    api = APIRouter(prefix="/api/v1/auth", tags=["auth"])

    @router.get("/authorize", include_in_schema=False)
    def authorize_page(
        audience: str,
        redirect_uri: str,
        code_challenge: Annotated[str, Query(pattern=_CHALLENGE_RE)],
        code_challenge_method: str = "S256",
        response_type: str = "code",
        state: str | None = None,
    ):
        if response_type != "code" or code_challenge_method != "S256":
            raise HTTPException(400, "Solo se soporta response_type=code con PKCE S256")
        _check_target(audience, redirect_uri)
        return FileResponse(web_dir / "authorize.html", headers={"Cache-Control": "no-store"})

    @api.get("/config")
    def public_config():
        return {"registration": config.REGISTRATION_MODE}

    @api.post("/authorize", response_model=AuthorizeResponse)
    def authorize(req: AuthorizeRequest, request: Request, db: Session = Depends(get_db)):
        rate_limit(f"login:ip:{client_ip(request)}", config.LOGIN_IP_LIMIT)
        rate_limit(f"login:user:{req.username}", config.LOGIN_USER_LIMIT)
        _check_target(req.audience, req.redirect_uri)

        user = authenticate(db, req.username, req.password)

        code = "ac_" + new_refresh_token()
        db.add(AuthCode(
            code_hash=hash_refresh_token(code),
            user_id=user.id,
            audience=req.audience,
            redirect_uri=req.redirect_uri,
            code_challenge=req.code_challenge,
            expires_at=now_ts() + config.AUTH_CODE_TTL,
        ))
        db.commit()

        params = {"code": code}
        if req.state:
            params["state"] = req.state
        return AuthorizeResponse(redirect_to=_with_params(req.redirect_uri, params))

    @api.post("/token", response_model=TokenResponse)
    def token(req: CodeExchangeRequest, request: Request, db: Session = Depends(get_db)):
        rate_limit(f"token:ip:{client_ip(request)}", config.REFRESH_IP_LIMIT)
        now = now_ts()

        row = db.scalar(select(AuthCode).where(AuthCode.code_hash == hash_refresh_token(req.code)))
        if row is None:
            raise _invalid_grant()

        claimed = db.execute(
            update(AuthCode)
            .where(AuthCode.id == row.id, AuthCode.used_at.is_(None), AuthCode.expires_at > now)
            .values(used_at=now)
        )
        db.commit()
        if claimed.rowcount == 0:
            raise _invalid_grant()

        if row.redirect_uri != req.redirect_uri or not _pkce_ok(req.code_verifier, row.code_challenge):
            raise _invalid_grant()

        user = db.get(User, row.user_id)
        if user is None or not user.is_active:
            raise _invalid_grant()

        raw, session_row = create_session_token(db, user, row.audience)
        db.commit()
        return token_response(user, row.audience, raw, session_row)

    router.include_router(api)
    return router
