# OSIRIS

Authentication and authorization server. Signs JWTs with EdDSA (Ed25519); services
verify locally with the public key (JWKS), without calling OSIRIS on every request.

## Startup

    nix-shell
    export OSIRIS_ADMIN_USERNAME=admin
    export OSIRIS_ADMIN_PASSWORD='a long password'   # only used if there are no users
    export OSIRIS_AUDIENCES=blob-storage,chat-service
    python src/main.py                               # port 8090

## Endpoints

| Method   | Path                        | Notes                                                                                  |
| -------- | --------------------------- | -------------------------------------------------------------------------------------- |
| POST     | /api/v1/auth/register       | public: `{username, password, invite_code?}` -> user (then, login). See "Registration" |
| POST/GET | /api/v1/invites             | admin: create (the code is shown only once) / list                                     |
| DELETE   | /api/v1/invites/{id}        | admin: revoke invitation                                                               |
| POST     | /api/v1/auth/login          | `{username, password, audience}` -> access (15 min) + refresh (30 days)                |
| POST     | /api/v1/auth/refresh        | `{refresh_token}` -> new pair; the refresh rotates on each use                         |
| POST     | /api/v1/auth/logout         | `{refresh_token}` -> revokes the session (idempotent)                                  |
| POST     | /api/v1/auth/password       | self-service change; revokes all sessions (token with aud=osiris)                      |
| GET      | /.well-known/jwks.json      | also at /api/v1/auth/.well-known/jwks.json                                             |
| POST/GET | /api/v1/users               | admin: create / list                                                                   |
| PATCH    | /api/v1/users/{id}          | admin: tenant, roles, is_active                                                        |
| POST     | /api/v1/users/{id}/password | admin: reset password                                                                  |
| GET      | /api/v1/users/me            | current user                                                                           |

The management API uses tokens with `aud=osiris` (log in with `"audience": "osiris"`).

## Registration

`OSIRIS_REGISTRATION` defines who can register:

- `invite` (default): only with an invitation code created by an admin. The invitation sets the
  tenant (`tenant_id`) and roles; if it doesn't set a tenant, each invitee gets a personal tenant.
- `open`: anyone. Without an invitation they get a personal tenant (`personal-<id>`) and the roles
  from `OSIRIS_DEFAULT_ROLES` (default `user`). With an invitation they join its tenant.
- `closed`: disabled; only an admin creates users (`POST /api/v1/users`).

Registrants never choose tenant or roles (those fields are ignored). Invitations have a
maximum number of uses and an expiration (7 days by default), usage is claimed atomically, and a
registration that fails (e.g. duplicate username) does not consume the invitation. Limit:
`OSIRIS_REGISTER_IP_LIMIT` registrations per hour per IP.

## Access token claims

`iss, sub, aud, iat, nbf, exp, jti` + `tid` (tenant) and `roles`.

## Security in brief

- Passwords with argon2id; identical response and equalized timing for nonexistent user.
- Account lockout after 5 failures (15 min) and rate limiting per IP and per user (in memory, per process).
- Opaque refresh tokens, stored as SHA-256. Rotation on each use: reusing an already-spent one
  revokes the entire session. Absolute session cap: `OSIRIS_SESSION_MAX_SECONDS` (90 days).
- One token = one audience. The refresh is bound to the login audience.
- Logout/deactivation revoke the refresh immediately, but a live access token remains
  valid for up to 15 min (the price of local verification).

## Key rotation

    python keys.py rotate      # the new signing key; the previous one stays published in the JWKS
    python keys.py list

Delete the old key from the directory once more than 15 min have passed since the rotation.
Keys live in `OSIRIS_KEY_DIR` (permissions 600): back them up.

## In a service (e.g. Holder)

Copy `osiris_client.py` and:

    verifier = OsirisVerifier(issuer="osiris-auth-service", audience="blob-storage",
                              jwks_url="http://osiris:8090/.well-known/jwks.json")
    current_claims = bearer_dependency(verifier)   # Depends(current_claims) -> Claims(sub, tid, roles)

## Environment variables

`OSIRIS_ISSUER, OSIRIS_ACCESS_TTL_SECONDS, OSIRIS_REFRESH_TTL_SECONDS, OSIRIS_SESSION_MAX_SECONDS,
OSIRIS_AUDIENCES, OSIRIS_KEY_DIR, OSIRIS_DATABASE_URL, OSIRIS_MAX_FAILED_LOGINS, OSIRIS_LOCKOUT_SECONDS,
OSIRIS_LOGIN_IP_LIMIT, OSIRIS_LOGIN_USER_LIMIT, OSIRIS_REFRESH_IP_LIMIT, OSIRIS_TRUST_FORWARDED_FOR,
OSIRIS_REGISTRATION, OSIRIS_REGISTER_IP_LIMIT, OSIRIS_DEFAULT_ROLES,
OSIRIS_ADMIN_USERNAME, OSIRIS_ADMIN_PASSWORD, OSIRIS_ADMIN_TENANT, OSIRIS_CLEANUP_INTERVAL_SECONDS`

Tests: `python src/smoke_test.py`

## License

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU AGPL for more details. You should have received a copy of the license in the [`LICENSE`](LICENSE) file; if not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

**Network use (AGPL §13):** if you modify OSIRIS and let other people interact with your modified version over a network, you must offer them the corresponding source code of that version under the same license.
