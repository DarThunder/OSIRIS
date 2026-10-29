# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

import time
import uuid

from sqlalchemy import BigInteger, Boolean, Column, ForeignKey, Integer, String, create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

import config

IS_SQLITE = config.DATABASE_URL.startswith("sqlite")
_connect_args = {"check_same_thread": False} if IS_SQLITE else {}
engine = create_engine(config.DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)

if IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()

def now_ts() -> int:
    return int(time.time())

def new_id() -> str:
    return uuid.uuid4().hex

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=new_id)
    username = Column(String, nullable=False, unique=True, index=True)
    password_hash = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False, index=True)
    roles = Column(String, nullable=False, default="")
    is_active = Column(Boolean, nullable=False, default=True)
    failed_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(BigInteger, nullable=False, default=0)
    created_at = Column(BigInteger, nullable=False, default=now_ts)
    password_changed_at = Column(BigInteger, nullable=False, default=now_ts)

    @property
    def role_list(self) -> list[str]:
        return [r for r in (self.roles or "").split(",") if r]

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String, primary_key=True, default=new_id)
    family_id = Column(String, nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    audience = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False, default=now_ts)
    expires_at = Column(BigInteger, nullable=False, index=True)
    family_expires_at = Column(BigInteger, nullable=False)
    used_at = Column(BigInteger, nullable=True)
    revoked_at = Column(BigInteger, nullable=True)
    replaced_by = Column(String, nullable=True)

class Invite(Base):
    __tablename__ = "invites"

    id = Column(String, primary_key=True, default=new_id)
    code_hash = Column(String, nullable=False, unique=True, index=True)
    tenant_id = Column(String, nullable=True)
    roles = Column(String, nullable=False, default="")
    max_uses = Column(Integer, nullable=False, default=1)
    uses = Column(Integer, nullable=False, default=0)
    expires_at = Column(BigInteger, nullable=False)
    revoked_at = Column(BigInteger, nullable=True)
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(BigInteger, nullable=False, default=now_ts)

    @property
    def role_list(self) -> list[str]:
        return [r for r in (self.roles or "").split(",") if r]

class AuthCode(Base):
    __tablename__ = "auth_codes"

    id = Column(String, primary_key=True, default=new_id)
    code_hash = Column(String, nullable=False, unique=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    audience = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    code_challenge = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False, default=now_ts)
    expires_at = Column(BigInteger, nullable=False, index=True)
    used_at = Column(BigInteger, nullable=True)

def init_db() -> None:
    Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()