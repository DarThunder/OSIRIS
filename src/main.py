# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

import asyncio
import logging
from pathlib import Path
import uuid
from contextlib import asynccontextmanager, suppress

import jwt
import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import config
from db import Invite, RefreshToken, SessionLocal, User, AuthCode, get_db, init_db, new_id, now_ts
from keys import KeyStore
from osiris_client import OsirisVerifier, bearer_dependency
from schemas import (
    AdminResetPasswordRequest,
    ChangePasswordRequest,
    CreateInviteRequest,
    CreateUserRequest,
    InviteCreated,
    InviteOut,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UpdateUserRequest,
    UserOut,
)
from security import (
    RateLimiter,
    hash_password,
    hash_refresh_token,
    needs_rehash,
    new_refresh_token,
    verify_password,
)
import authorize

logger = logging.getLogger("osiris")

keystore = KeyStore(config.KEY_DIR)
limiter = RateLimiter()

_self_verifier = OsirisVerifier(
    issuer=config.ISSUER,
    audience=config.ADMIN_AUDIENCE,
    jwks_fetch=keystore.jwks,
    min_refetch_interval=0,
)
token_claims = bearer_dependency(_self_verifier)

def _unauthorized(detail: str = "Credenciales inválidas") -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})

def client_ip(request: Request) -> str:
    if config.TRUST_FORWARDED_FOR:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _rate_limit(key: str, limit: int, window: int = 60) -> None:
    if not limiter.allow(key, limit, window):
        raise HTTPException(429, "Demasiados intentos, espera un momento", headers={"Retry-After": str(window)})

def issue_access_token(user: User, audience: str) -> str:
    kid, private_key = keystore.signing_key()
    now = now_ts()
    payload = {
        "iss": config.ISSUER,
        "sub": user.id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + config.ACCESS_TTL,
        "jti": uuid.uuid4().hex,
        "tid": user.tenant_id,
        "roles": user.role_list,
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})

def create_session_token(
    db: Session,
    user: User,
    audience: str,
    family_id: str | None = None,
    family_expires_at: int | None = None,
) -> tuple[str, RefreshToken]:
    now = now_ts()
    family_expires_at = family_expires_at or now + config.SESSION_MAX
    raw = new_refresh_token()
    row = RefreshToken(
        id=new_id(),
        family_id=family_id or new_id(),
        user_id=user.id,
        token_hash=hash_refresh_token(raw),
        audience=audience,
        created_at=now,
        expires_at=min(now + config.REFRESH_TTL, family_expires_at),
        family_expires_at=family_expires_at,
    )
    db.add(row)
    return raw, row

def token_response(user: User, audience: str, raw_refresh: str, row: RefreshToken) -> TokenResponse:
    return TokenResponse(
        access_token=issue_access_token(user, audience),
        expires_in=config.ACCESS_TTL,
        refresh_token=raw_refresh,
        refresh_expires_in=max(0, row.expires_at - now_ts()),
        audience=audience,
    )

def revoke_family(db: Session, family_id: str) -> None:
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now_ts())
    )

def revoke_user_sessions(db: Session, user_id: str) -> None:
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now_ts())
    )

def invite_out(i: Invite) -> InviteOut:
    return InviteOut(
        id=i.id, tenant_id=i.tenant_id, roles=i.role_list, max_uses=i.max_uses,
        uses=i.uses, expires_at=i.expires_at, revoked_at=i.revoked_at, created_at=i.created_at,
    )

def user_out(u: User) -> UserOut:
    return UserOut(
        id=u.id, username=u.username, tenant_id=u.tenant_id,
        roles=u.role_list, is_active=u.is_active, created_at=u.created_at,
    )

def cleanup_expired(db: Session) -> int:
    res = db.execute(delete(RefreshToken).where(RefreshToken.expires_at < now_ts() - 86400))
    db.execute(delete(AuthCode).where(AuthCode.expires_at < now_ts() - 3600))
    db.commit()
    return res.rowcount

def current_user(claims=Depends(token_claims), db: Session = Depends(get_db)) -> User:
    user = db.get(User, claims.sub)
    if user is None or not user.is_active:
        raise _unauthorized("Usuario inexistente o desactivado")
    return user

def require_admin(user: User = Depends(current_user)) -> User:
    if "admin" not in user.role_list:
        raise HTTPException(403, "Se requiere el rol admin")
    return user

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)) is None:
            if config.BOOTSTRAP_ADMIN_USERNAME and config.BOOTSTRAP_ADMIN_PASSWORD:
                db.add(User(
                    username=config.BOOTSTRAP_ADMIN_USERNAME.strip().lower(),
                    password_hash=hash_password(config.BOOTSTRAP_ADMIN_PASSWORD),
                    tenant_id=config.BOOTSTRAP_ADMIN_TENANT,
                    roles="admin",
                ))
                db.commit()
                logger.warning("Admin inicial creado: %s", config.BOOTSTRAP_ADMIN_USERNAME)
            else:
                logger.warning(
                    "No hay usuarios y OSIRIS_ADMIN_USERNAME/OSIRIS_ADMIN_PASSWORD no están definidos"
                )
        cleanup_expired(db)

    task = None
    if config.CLEANUP_INTERVAL_SECONDS > 0:
        async def _loop():
            while True:
                await asyncio.sleep(config.CLEANUP_INTERVAL_SECONDS)
                try:
                    def _run():
                        with SessionLocal() as s:
                            return cleanup_expired(s)
                    await asyncio.to_thread(_run)
                except Exception:
                    logger.exception("Limpieza de tokens falló")
        task = asyncio.create_task(_loop())
    try:
        yield
    finally:
        if task:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

app = FastAPI(title="OSIRIS", lifespan=lifespan)
web = Path(__file__).parent / "web"
auth = APIRouter(prefix="/api/v1/auth", tags=["auth"])
users = APIRouter(prefix="/api/v1/users", tags=["users"])


@app.get("/health")
def healthz():
    return {"Aquí Delta 7, que paso jefe"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.REDIRECT_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
    return response
@app.get("/.well-known/jwks.json")
@auth.get("/.well-known/jwks.json")
def jwks(response: Response):
    response.headers["Cache-Control"] = "public, max-age=300"
    return keystore.jwks()

@auth.post("/register", response_model=UserOut, status_code=201)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    mode = config.REGISTRATION_MODE
    if mode == "closed":
        raise HTTPException(403, "El registro está deshabilitado")
    _rate_limit(f"register:ip:{client_ip(request)}", config.REGISTER_IP_LIMIT, window=3600)

    invite = None
    if req.invite_code:
        invite = db.scalar(select(Invite).where(Invite.code_hash == hash_refresh_token(req.invite_code)))
        invalid = HTTPException(403, "Invitación inválida, expirada o agotada")
        if invite is None:
            raise invalid
        now = now_ts()
        claimed = db.execute(
            update(Invite)
            .where(
                Invite.id == invite.id,
                Invite.revoked_at.is_(None),
                Invite.expires_at > now,
                Invite.uses < Invite.max_uses,
            )
            .values(uses=Invite.uses + 1)
        )
        if claimed.rowcount == 0:
            db.rollback()
            raise invalid
    elif mode == "invite":
        raise HTTPException(403, "Se requiere un código de invitación")

    user_id = new_id()
    if invite is not None:
        tenant_id = invite.tenant_id or f"personal-{user_id}"
        roles = invite.role_list
    else:
        tenant_id = f"personal-{user_id}"
        roles = config.DEFAULT_ROLES
    user = User(
        id=user_id,
        username=req.username,
        password_hash=hash_password(req.password),
        tenant_id=tenant_id,
        roles=",".join(dict.fromkeys(roles)),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El nombre de usuario ya está en uso")
    return user_out(user)

@auth.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    _rate_limit(f"login:ip:{client_ip(request)}", config.LOGIN_IP_LIMIT)
    _rate_limit(f"login:user:{req.username}", config.LOGIN_USER_LIMIT)
    if req.audience not in config.AUDIENCES:
        raise HTTPException(400, "Audiencia no permitida")

    now = now_ts()
    user = db.scalar(select(User).where(User.username == req.username))
    password_ok = verify_password(user.password_hash if user else None, req.password)

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
        user.password_hash = hash_password(req.password)
    raw, row = create_session_token(db, user, req.audience)
    db.commit()
    return token_response(user, req.audience, raw, row)

@auth.post("/refresh", response_model=TokenResponse)
def refresh(req: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    _rate_limit(f"refresh:ip:{client_ip(request)}", config.REFRESH_IP_LIMIT)
    now = now_ts()
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(req.refresh_token)))
    if row is None:
        raise _unauthorized("Refresh token inválido")
    if row.revoked_at is not None or row.expires_at <= now or row.family_expires_at <= now:
        raise _unauthorized("Refresh token inválido")

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        revoke_family(db, row.family_id)
        db.commit()
        raise _unauthorized("Refresh token inválido")

    claimed = db.execute(
        update(RefreshToken)
        .where(RefreshToken.id == row.id, RefreshToken.used_at.is_(None))
        .values(used_at=now)
    )
    if claimed.rowcount == 0:
        revoke_family(db, row.family_id)
        db.commit()
        logger.warning("Reuso de refresh token detectado (usuario %s): sesión revocada", user.username)
        raise _unauthorized("Refresh token inválido")

    raw, new_row = create_session_token(
        db, user, row.audience, family_id=row.family_id, family_expires_at=row.family_expires_at
    )
    db.execute(update(RefreshToken).where(RefreshToken.id == row.id).values(replaced_by=new_row.id))
    db.commit()
    return token_response(user, row.audience, raw, new_row)

@auth.post("/logout")
def logout(req: RefreshRequest, db: Session = Depends(get_db)):
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(req.refresh_token)))
    if row is not None:
        revoke_family(db, row.family_id)
        db.commit()
    return {"status": "ok"}

@auth.post("/password", status_code=204)
def change_password(req: ChangePasswordRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(user.password_hash, req.current_password):
        raise HTTPException(403, "Contraseña actual incorrecta")
    user.password_hash = hash_password(req.new_password)
    user.password_changed_at = now_ts()
    revoke_user_sessions(db, user.id)
    db.commit()
    return Response(status_code=204)

@users.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user_out(user)

@users.post("", response_model=UserOut, status_code=201)
def create_user(req: CreateUserRequest, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = User(
        username=req.username,
        password_hash=hash_password(req.password),
        tenant_id=req.tenant_id,
        roles=",".join(dict.fromkeys(req.roles)),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "El usuario ya existe")
    return user_out(user)

@users.get("", response_model=list[UserOut])
def list_users(
    tenant_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = select(User).order_by(User.created_at, User.id).limit(min(max(limit, 1), 500)).offset(max(offset, 0))
    if tenant_id:
        q = q.where(User.tenant_id == tenant_id)
    return [user_out(u) for u in db.scalars(q).all()]

@users.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    req: UpdateUserRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Usuario no encontrado")
    if user.id == admin.id and (
        req.is_active is False or (req.roles is not None and "admin" not in req.roles)
    ):
        raise HTTPException(400, "No puedes desactivarte ni quitarte el rol admin a ti mismo")
    if req.tenant_id is not None:
        user.tenant_id = req.tenant_id
    if req.roles is not None:
        user.roles = ",".join(dict.fromkeys(req.roles))
    if req.is_active is not None:
        user.is_active = req.is_active
        if not req.is_active:
            revoke_user_sessions(db, user.id)
    db.commit()
    return user_out(user)

@users.post("/{user_id}/password", status_code=204)
def admin_reset_password(
    user_id: str,
    req: AdminResetPasswordRequest,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Usuario no encontrado")
    user.password_hash = hash_password(req.new_password)
    user.password_changed_at = now_ts()
    user.failed_attempts = 0
    user.locked_until = 0
    revoke_user_sessions(db, user.id)
    db.commit()
    return Response(status_code=204)

invites = APIRouter(prefix="/api/v1/invites", tags=["invites"])

@invites.post("", response_model=InviteCreated, status_code=201)
def create_invite(req: CreateInviteRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    code = "inv_" + new_refresh_token()
    invite = Invite(
        code_hash=hash_refresh_token(code),
        tenant_id=req.tenant_id,
        roles=",".join(dict.fromkeys(req.roles)),
        max_uses=req.max_uses,
        expires_at=now_ts() + req.expires_in_seconds,
        created_by=admin.id,
    )
    db.add(invite)
    db.commit()
    return InviteCreated(**invite_out(invite).model_dump(), code=code)

@invites.get("", response_model=list[InviteOut])
def list_invites(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.scalars(select(Invite).order_by(Invite.created_at.desc()).limit(500)).all()
    return [invite_out(i) for i in rows]

@invites.delete("/{invite_id}", status_code=204)
def revoke_invite(invite_id: str, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    invite = db.get(Invite, invite_id)
    if invite is None:
        raise HTTPException(404, "Invitación no encontrada")
    if invite.revoked_at is None:
        invite.revoked_at = now_ts()
        db.commit()
    return Response(status_code=204)

app.include_router(authorize.build_router(
    rate_limit=_rate_limit,
    client_ip=client_ip,
    create_session_token=create_session_token,
    token_response=token_response,
    web_dir=web,
))
app.include_router(auth)
app.include_router(users)
app.include_router(invites)
app.mount("/", StaticFiles(directory=web, html=True), name="web")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8090)