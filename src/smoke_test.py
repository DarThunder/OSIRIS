# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

import base64
import os
import sys
import tempfile
import time

tmp = tempfile.mkdtemp()
os.environ["OSIRIS_KEY_DIR"] = os.path.join(tmp, "keys")
os.environ["OSIRIS_DATABASE_URL"] = f"sqlite:///{tmp}/osiris.db"
os.environ["OSIRIS_AUDIENCES"] = "blob-storage,chat-service"
os.environ["OSIRIS_ADMIN_USERNAME"] = "root"
os.environ["OSIRIS_ADMIN_PASSWORD"] = "correct horse battery staple"
os.environ["OSIRIS_LOGIN_IP_LIMIT"] = "1000"
os.environ["OSIRIS_REGISTER_IP_LIMIT"] = "1000"
os.environ["OSIRIS_CLEANUP_INTERVAL_SECONDS"] = "0"

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import config
import main
from db import SessionLocal, User
from osiris_client import AuthError, OsirisVerifier

def ok(cond, msg):
    print(("OK  " if cond else "FAIL"), msg)
    if not cond:
        sys.exit(1)

def verifier(aud, **kw):
    return OsirisVerifier(issuer=config.ISSUER, audience=aud, jwks_fetch=main.keystore.jwks,
                          min_refetch_interval=0, **kw)

def rejects(v, token):
    try:
        v.verify(token)
        return False
    except AuthError:
        return True

ADMIN_PW = "correct horse battery staple"

with TestClient(main.app) as c:
    def login(user, pw, aud):
        return c.post("/api/v1/auth/login", json={"username": user, "password": pw, "audience": aud})

    def hdr(tok):
        return {"Authorization": f"Bearer {tok}"}

    ok(c.get("/healthz").json() == {"status": "ok"}, "healthz")
    j = c.get("/.well-known/jwks.json")
    ok(j.status_code == 200 and len(j.json()["keys"]) == 1, "JWKS publica 1 llave")
    k = j.json()["keys"][0]
    ok(k["kty"] == "OKP" and k["crv"] == "Ed25519" and k["alg"] == "EdDSA" and k["kid"], "JWKS: formato OKP/Ed25519/EdDSA con kid")
    ok(c.get("/api/v1/auth/.well-known/jwks.json").json() == j.json(), "JWKS también bajo /api/v1/auth/")
    ok("max-age" in j.headers.get("cache-control", ""), "JWKS con Cache-Control")
    perms = oct(os.stat(os.path.join(tmp, "keys", os.listdir(os.path.join(tmp, "keys"))[0])).st_mode & 0o777)
    ok(perms == "0o600", f"llave privada con permisos 600 ({perms})")

    r1 = login("root", "mala", "osiris")
    r2 = login("noexiste", "mala", "osiris")
    ok(r1.status_code == 401 and r2.status_code == 401 and r1.json() == r2.json(), "login fallido: misma respuesta para usuario inexistente y contraseña mala")
    ok(login("root", ADMIN_PW, "otro-servicio").status_code == 400, "audiencia no permitida -> 400")
    r = login("root", ADMIN_PW, "osiris")
    ok(r.status_code == 200, "login admin (bootstrap) ok")
    adm = r.json()
    ok(adm["expires_in"] == 900, "access token dura 15 min")
    ok(abs(adm["refresh_expires_in"] - 30 * 86400) < 5, "refresh token dura 30 días")
    admin_h = hdr(adm["access_token"])

    claims = verifier("osiris").verify(adm["access_token"])
    ok(claims.raw["iss"] == "osiris-auth-service" and claims.aud == "osiris", "claims: iss y aud")
    ok(claims.raw["exp"] - claims.raw["iat"] == 900, "claims: exp - iat = 900 s")
    ok(claims.tid == "system" and "admin" in claims.roles and claims.jti, "claims: tid, roles y jti")

    ok(c.post("/api/v1/users", json={}).status_code == 401, "crear usuario sin token -> 401")
    body = {"username": "Alice", "password": "alice-password-1", "tenant_id": "t1", "roles": ["user"]}
    r = c.post("/api/v1/users", json=body, headers=admin_h)
    ok(r.status_code == 201 and r.json()["username"] == "alice" and r.json()["tenant_id"] == "t1", "admin crea usuario (username normalizado)")
    alice_id = r.json()["id"]
    ok(c.post("/api/v1/users", json=body, headers=admin_h).status_code == 409, "usuario duplicado -> 409")
    ok(c.post("/api/v1/users", json={**body, "username": "weak", "password": "corta"}, headers=admin_h).status_code == 422, "contraseña débil -> 422")
    ok(c.post("/api/v1/users", json={**body, "username": "x y"}, headers=admin_h).status_code == 422, "username inválido -> 422")

    alice = login("alice", "alice-password-1", "blob-storage").json()
    alice_osiris = login("alice", "alice-password-1", "osiris").json()
    ok(c.post("/api/v1/users", json={**body, "username": "bob"}, headers=hdr(alice_osiris["access_token"])).status_code == 403, "usuario sin rol admin no puede crear usuarios -> 403")
    ok(c.get("/api/v1/users/me", headers=hdr(alice_osiris["access_token"])).json()["tenant_id"] == "t1", "GET /users/me")
    ok(c.get("/api/v1/users/me", headers=hdr(alice["access_token"])).status_code == 401, "token aud=blob-storage NO sirve en OSIRIS")

    v_blob = verifier("blob-storage")
    ac = v_blob.verify(alice["access_token"])
    ok(ac.sub == alice_id and ac.tid == "t1" and ac.roles == ("user",), "Holder vería sub/tid/roles correctos")
    ok(rejects(verifier("chat-service"), alice["access_token"]), "token de blob-storage rechazado por chat-service (aud)")
    ok(rejects(OsirisVerifier(issuer="otro", audience="blob-storage", jwks_fetch=main.keystore.jwks), alice["access_token"]), "issuer incorrecto rechazado")

    kid = k["kid"]
    now = int(time.time())
    base = {"iss": config.ISSUER, "sub": "x", "aud": "blob-storage", "iat": now, "exp": now + 600, "tid": "t1", "roles": ["admin"]}
    ok(rejects(v_blob, jwt.encode(base, None, algorithm="none", headers={"kid": kid})), "alg=none rechazado")
    x_bytes = base64.urlsafe_b64decode(k["x"] + "==")
    ok(rejects(v_blob, jwt.encode(base, x_bytes, algorithm="HS256", headers={"kid": kid})), "HS256 con la llave pública como secreto rechazado")
    attacker = Ed25519PrivateKey.generate()
    ok(rejects(v_blob, jwt.encode(base, attacker, algorithm="EdDSA", headers={"kid": kid})), "firma de otra llave (mismo kid) rechazada")
    ok(rejects(v_blob, jwt.encode(base, attacker, algorithm="EdDSA", headers={"kid": "desconocido"})), "kid desconocido rechazado")
    ok(rejects(v_blob, jwt.encode(base, attacker, algorithm="EdDSA")), "sin kid rechazado")
    tampered = alice["access_token"].split(".")
    tampered[1] = base64.urlsafe_b64encode(b'{"iss":"osiris-auth-service","sub":"x","aud":"blob-storage","iat":1,"exp":9999999999,"roles":["admin"]}').rstrip(b"=").decode()
    ok(rejects(v_blob, ".".join(tampered)), "payload alterado rechazado")
    ok(rejects(v_blob, "basura"), "token malformado rechazado")
    config.ACCESS_TTL = -60
    expired = main.issue_access_token(main.SessionLocal().get(User, alice_id), "blob-storage")
    config.ACCESS_TTL = 900
    ok(rejects(verifier("blob-storage", leeway=0), expired), "token expirado rechazado")

    r = c.post("/api/v1/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    ok(r.status_code == 200, "refresh ok")
    alice2 = r.json()
    ok(alice2["refresh_token"] != alice["refresh_token"], "el refresh token rota")
    ok(alice2["audience"] == "blob-storage" and v_blob.verify(alice2["access_token"]).tid == "t1", "el refresh conserva la audiencia")

    r = c.post("/api/v1/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    ok(r.status_code == 401, "reusar un refresh token ya rotado -> 401")
    r = c.post("/api/v1/auth/refresh", json={"refresh_token": alice2["refresh_token"]})
    ok(r.status_code == 401, "...y el token legítimo posterior también queda revocado (familia)")

    s = login("alice", "alice-password-1", "blob-storage").json()
    ok(c.post("/api/v1/auth/logout", json={"refresh_token": s["refresh_token"]}).json() == {"status": "ok"}, "logout ok")
    ok(c.post("/api/v1/auth/logout", json={"refresh_token": "no-existe"}).json() == {"status": "ok"}, "logout idempotente")
    ok(c.post("/api/v1/auth/refresh", json={"refresh_token": s["refresh_token"]}).status_code == 401, "refresh tras logout -> 401")
    ok(c.post("/api/v1/auth/refresh", json={"refresh_token": "inventado"}).status_code == 401, "refresh inventado -> 401")

    s = login("alice", "alice-password-1", "blob-storage").json()
    with SessionLocal() as db:
        from db import RefreshToken
        from sqlalchemy import update
        db.execute(update(RefreshToken).values(expires_at=int(time.time()) - 1))
        db.commit()
    ok(c.post("/api/v1/auth/refresh", json={"refresh_token": s["refresh_token"]}).status_code == 401, "refresh expirado -> 401")

    c.post("/api/v1/users", json={**body, "username": "bobby", "password": "bobby-password-1", "tenant_id": "t2"}, headers=admin_h)
    for _ in range(5):
        login("bobby", "mala", "blob-storage")
    ok(login("bobby", "bobby-password-1", "blob-storage").status_code == 401, "tras 5 fallos la cuenta se bloquea (aun con la contraseña correcta)")
    with SessionLocal() as db:
        u = db.query(User).filter_by(username="bobby").one()
        u.locked_until = 0
        db.commit()
    ok(login("bobby", "bobby-password-1", "blob-storage").status_code == 200, "al expirar el bloqueo vuelve a entrar")

    codes = [login("fantasma", "x", "blob-storage").status_code for _ in range(12)]
    ok(codes[:10] == [401] * 10 and codes[10] == 429, "rate limit por usuario: 429 tras 10 intentos/minuto")

    a_os = login("alice", "alice-password-1", "osiris").json()
    a_blob = login("alice", "alice-password-1", "blob-storage").json()
    r = c.post("/api/v1/auth/password", json={"current_password": "equivocada", "new_password": "alice-password-2"}, headers=hdr(a_os["access_token"]))
    ok(r.status_code == 403, "cambio de contraseña con la actual incorrecta -> 403")
    r = c.post("/api/v1/auth/password", json={"current_password": "alice-password-1", "new_password": "alice-password-2"}, headers=hdr(a_os["access_token"]))
    ok(r.status_code == 204, "cambio de contraseña ok")
    ok(c.post("/api/v1/auth/refresh", json={"refresh_token": a_blob["refresh_token"]}).status_code == 401, "cambiar contraseña revoca todas las sesiones")
    ok(login("alice", "alice-password-1", "blob-storage").status_code == 401, "la contraseña vieja ya no sirve")
    ok(login("alice", "alice-password-2", "blob-storage").status_code == 200, "la nueva sí")

    b = login("bobby", "bobby-password-1", "blob-storage").json()
    bobby_id = c.get("/api/v1/users?tenant_id=t2", headers=admin_h).json()[0]["id"]
    ok(c.patch(f"/api/v1/users/{bobby_id}", json={"is_active": False}, headers=admin_h).json()["is_active"] is False, "admin desactiva usuario")
    ok(c.post("/api/v1/auth/refresh", json={"refresh_token": b["refresh_token"]}).status_code == 401, "usuario desactivado no puede refrescar")
    ok(login("bobby", "bobby-password-1", "blob-storage").status_code == 401, "usuario desactivado no puede entrar")
    root_id = c.get("/api/v1/users/me", headers=admin_h).json()["id"]
    ok(c.patch(f"/api/v1/users/{root_id}", json={"is_active": False}, headers=admin_h).status_code == 400, "el admin no puede desactivarse a sí mismo")
    r = c.post(f"/api/v1/users/{bobby_id}/password", json={"new_password": "bobby-password-2"}, headers=admin_h)
    ok(r.status_code == 204, "admin resetea contraseña")

    old_token = login("alice", "alice-password-2", "blob-storage").json()["access_token"]
    v = verifier("blob-storage")
    v.verify(old_token)
    new_kid = main.keystore.rotate()
    ok(len(c.get("/.well-known/jwks.json").json()["keys"]) == 2, "tras rotar, el JWKS publica 2 llaves")
    new_token = login("alice", "alice-password-2", "blob-storage").json()["access_token"]
    ok(jwt.get_unverified_header(new_token)["kid"] == new_kid, "los tokens nuevos se firman con la llave nueva")
    ok(v.verify(new_token).tid == "t1", "verificador con caché vieja refresca solo ante el kid nuevo")
    ok(v.verify(old_token).tid == "t1", "los tokens firmados con la llave anterior siguen siendo válidos")

    config.LOGIN_USER_LIMIT = 1000
    admin_h = hdr(login("root", ADMIN_PW, "osiris").json()["access_token"])

    def register(username, password="registro-password-1", **extra):
        return c.post("/api/v1/auth/register", json={"username": username, "password": password, **extra})

    def new_invite(**kw):
        r = c.post("/api/v1/invites", json=kw, headers=admin_h)
        assert r.status_code == 201, r.text
        return r.json()

    config.REGISTRATION_MODE = "closed"
    ok(register("zoe").status_code == 403, "modo closed: registro deshabilitado -> 403")

    config.REGISTRATION_MODE = "invite"
    ok(register("zoe").status_code == 403, "modo invite: sin código -> 403")
    ok(register("zoe", invite_code="inv_inventado").status_code == 403, "modo invite: código inventado -> 403")
    ok(c.post("/api/v1/invites", json={}).status_code == 401, "crear invitación sin token -> 401")
    ok(c.post("/api/v1/invites", json={}, headers=hdr(login("alice", "alice-password-2", "osiris").json()["access_token"])).status_code == 403, "usuario normal no puede crear invitaciones -> 403")

    inv = new_invite(tenant_id="acme", roles=["member"], max_uses=2)
    ok(inv["code"].startswith("inv_") and inv["max_uses"] == 2 and inv["uses"] == 0, "admin crea invitación (código visible una vez)")
    ok("code" not in c.get("/api/v1/invites", headers=admin_h).json()[0], "el listado de invitaciones NO expone el código")
    r = register("Carol", invite_code=inv["code"])
    ok(r.status_code == 201 and r.json()["tenant_id"] == "acme" and r.json()["roles"] == ["member"], "registro con invitación: entra al tenant y roles de la invitación")
    carol_tok = login("carol", "registro-password-1", "blob-storage").json()["access_token"]
    ok(v_blob.verify(carol_tok).tid == "acme", "el token de carol lleva tid=acme (lo que usará Holder)")
    ok(register("dave", invite_code=inv["code"]).status_code == 201, "segundo uso de la invitación ok")
    ok(register("erin", invite_code=inv["code"]).status_code == 403, "invitación agotada -> 403")

    inv2 = new_invite(tenant_id="acme", max_uses=1)
    ok(register("carol", invite_code=inv2["code"]).status_code == 409, "username repetido -> 409")
    ok(register("frank", invite_code=inv2["code"]).status_code == 201, "...y esa invitación sigue disponible")

    inv3 = new_invite(tenant_id="acme")
    ok(c.delete(f"/api/v1/invites/{inv3['id']}", headers=admin_h).status_code == 204, "admin revoca invitación")
    ok(register("gina", invite_code=inv3["code"]).status_code == 403, "invitación revocada -> 403")
    inv4 = new_invite(tenant_id="acme")
    with SessionLocal() as db:
        from db import Invite
        db.execute(update(Invite).where(Invite.id == inv4["id"]).values(expires_at=int(time.time()) - 1))
        db.commit()
    ok(register("hank", invite_code=inv4["code"]).status_code == 403, "invitación expirada -> 403")

    inv5 = new_invite(max_uses=2)
    a = register("ivan", invite_code=inv5["code"]).json()
    b = register("judy", invite_code=inv5["code"]).json()
    ok(a["tenant_id"].startswith("personal-") and a["tenant_id"] != b["tenant_id"], "invitación sin tenant: tenant personal por usuario")

    config.REGISTRATION_MODE = "open"
    r = register("kate", **{"roles": ["admin"], "tenant_id": "acme", "is_active": True})
    ok(r.status_code == 201 and r.json()["roles"] == ["user"] and r.json()["tenant_id"].startswith("personal-"),
       "modo open: tenant personal + rol user; los campos roles/tenant_id enviados se ignoran")
    ok(register("liam").json()["tenant_id"] != r.json()["tenant_id"], "modo open: cada usuario, su propio tenant")
    ok(register("mia", invite_code="inv_inventado").status_code == 403, "modo open: un código inválido NO se ignora en silencio")
    ok(register("nora", invite_code=new_invite(tenant_id="acme")["code"]).json()["tenant_id"] == "acme", "modo open: con invitación también se une al tenant")
    ok(register("kate").status_code == 409, "modo open: username repetido -> 409")
    ok(register("olga", password="corta").status_code == 422, "contraseña débil -> 422")
    ok(register("olga-user", password="olga-user").status_code == 422, "contraseña igual al username -> 422")
    ok(register("a").status_code == 422, "username demasiado corto -> 422")
    ok(login("kate", "registro-password-1", "blob-storage").status_code == 200, "el usuario registrado puede hacer login")

    used = len(main.limiter._hits["register:ip:testclient"])
    config.REGISTER_IP_LIMIT = used + 2
    codes = [register(f"spam{i}").status_code for i in range(4)]
    ok(codes == [201, 201, 429, 429], f"rate limit de registro por IP -> {codes}")

print("TODO OK")
