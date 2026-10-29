const b64u = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const randomString = (n) => b64u(crypto.getRandomValues(new Uint8Array(n)));

export class OsirisClient {
  #inflight = null;

  constructor({ issuer, audience, redirectUri }) {
    this.issuer = issuer.replace(/\/+$/, "");
    this.audience = audience;
    this.redirectUri = redirectUri;
    this.key = `osiris:tokens:${audience}`;
  }

  async login() {
    if (!crypto.subtle) {
      throw new Error(
        "PKCE necesita un contexto seguro: usa HTTPS o localhost.",
      );
    }
    const verifier = randomString(32); // 43 caracteres
    const state = randomString(16);
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier),
    );
    sessionStorage.setItem("osiris:pkce", JSON.stringify({ verifier, state }));

    const q = new URLSearchParams({
      response_type: "code",
      audience: this.audience,
      redirect_uri: this.redirectUri,
      code_challenge: b64u(new Uint8Array(digest)),
      code_challenge_method: "S256",
      state,
    });
    location.assign(`${this.issuer}/authorize?${q}`);
  }

  async handleCallback() {
    const p = new URLSearchParams(location.search);
    const saved = JSON.parse(sessionStorage.getItem("osiris:pkce") ?? "null");
    sessionStorage.removeItem("osiris:pkce");
    if (!saved || !p.get("code") || p.get("state") !== saved.state) {
      throw new Error("Respuesta de login inválida (state).");
    }
    history.replaceState(null, "", location.pathname); // quita el code de la URL
    const tokens = await this.#post("/api/v1/auth/token", {
      code: p.get("code"),
      code_verifier: saved.verifier,
      redirect_uri: this.redirectUri,
    });
    this.#store(tokens);
  }

  async getAccessToken() {
    const fresh = (t) => t && t.expires_at - 30_000 > Date.now();
    const t = this.#read();
    if (!t) return null;
    if (fresh(t)) return t.access_token;

    // Un solo refresh a la vez (misma pestaña y entre pestañas): OSIRIS rota los refresh
    // tokens y trata un reuso como robo, revocando toda la sesión.
    this.#inflight ??= (async () => {
      const run = async () => {
        const current = this.#read(); // otra pestaña pudo refrescar mientras esperábamos
        if (!current) return null;
        if (fresh(current)) return current.access_token;
        try {
          const next = await this.#post("/api/v1/auth/refresh", {
            refresh_token: current.refresh_token,
          });
          this.#store(next);
          return next.access_token;
        } catch {
          localStorage.removeItem(this.key);
          return null;
        }
      };
      return navigator.locks ? navigator.locks.request(this.key, run) : run();
    })().finally(() => {
      this.#inflight = null;
    });

    return this.#inflight;
  }

  async logout() {
    const t = this.#read();
    localStorage.removeItem(this.key);
    if (t)
      await this.#post("/api/v1/auth/logout", {
        refresh_token: t.refresh_token,
      }).catch(() => {});
  }

  #read() {
    try {
      return JSON.parse(localStorage.getItem(this.key) ?? "null");
    } catch {
      return null;
    }
  }

  #store(t) {
    localStorage.setItem(
      this.key,
      JSON.stringify({
        access_token: t.access_token,
        refresh_token: t.refresh_token,
        expires_at: Date.now() + t.expires_in * 1000,
      }),
    );
  }

  async #post(path, body) {
    const res = await fetch(this.issuer + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok)
      throw new Error(
        typeof data?.detail === "string" ? data.detail : `HTTP ${res.status}`,
      );
    return data;
  }
}
