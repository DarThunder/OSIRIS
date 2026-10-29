const mode = document.body.dataset.mode;
const $ = (id) => document.getElementById(id);

function msg(text, ok = false) {
  const el = $("msg");
  el.textContent = text;
  el.className = ok ? "ok" : "err";
}

function errText(data, status) {
  if (typeof data?.detail === "string") return data.detail;
  if (status === 422)
    return "Revisa los datos: usuario de 3 a 64 caracteres y contraseña de 10 o más.";
  if (status === 429) return "Demasiados intentos, espera un momento.";
  return "Error inesperado.";
}

async function api(path, { method = "POST", body, token } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new Error(errText(data, res.status));
  return data;
}

async function busy(form, fn) {
  const btn = form.querySelector("button[type=submit]");
  btn.disabled = true;
  msg("");
  try {
    await fn();
  } catch (e) {
    msg(e.message);
  } finally {
    btn.disabled = false;
  }
}

function showTab(which) {
  const login = which === "login";
  $("login-form").hidden = !login;
  $("register-form").hidden = login;
  $("tab-login").classList.toggle("active", login);
  $("tab-register").classList.toggle("active", !login);
  msg("");
}
$("tab-login").addEventListener("click", () => showTab("login"));
$("tab-register").addEventListener("click", () => showTab("register"));

try {
  const { registration } = await (
    await fetch("/osiris/api/v1/auth/config")
  ).json();
  if (registration === "closed") $("tab-register").hidden = true;
  if (registration === "open") $("invite-row").hidden = true;
} catch {}

$("register-form").addEventListener("submit", (e) => {
  e.preventDefault();
  busy(e.target, async () => {
    const username = $("register-username").value.trim();
    const invite = $("register-invite").value.trim();
    await api("/osiris/api/v1/auth/register", {
      body: {
        username,
        password: $("register-password").value,
        invite_code: invite || undefined,
      },
    });
    $("register-password").value = "";
    $("login-username").value = username;
    showTab("login");
    msg("Cuenta creada. Ya puedes entrar.", true);
  });
});

if (mode === "authorize") {
  const p = new URLSearchParams(location.search);
  const ctx = {
    audience: p.get("audience"),
    redirect_uri: p.get("redirect_uri"),
    code_challenge: p.get("code_challenge"),
    code_challenge_method: "S256",
    state: p.get("state") || undefined,
  };
  $("context").textContent =
    `Inicia sesión para continuar en «${ctx.audience}».`;

  $("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    busy(e.target, async () => {
      const data = await api("/osiris/api/v1/auth/authorize", {
        body: {
          username: $("login-username").value,
          password: $("login-password").value,
          ...ctx,
        },
      });
      $("login-password").value = "";
      location.replace(data.redirect_to);
    });
  });
}

if (mode === "account") {
  let session = null;

  async function showAccount() {
    const me = await api("/osiris/api/v1/users/me", {
      method: "GET",
      token: session.access_token,
    });
    $("whoami").textContent = `Sesión iniciada como ${me.username}.`;
    $("guest").hidden = true;
    $("account").hidden = false;
  }

  $("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    busy(e.target, async () => {
      session = await api("/osiris/api/v1/auth/login", {
        body: {
          username: $("login-username").value,
          password: $("login-password").value,
          audience: "osiris",
        },
      });
      $("login-password").value = "";
      await showAccount();
    });
  });

  $("password-form").addEventListener("submit", (e) => {
    e.preventDefault();
    busy(e.target, async () => {
      await api("/osiris/api/v1/auth/password", {
        token: session.access_token,
        body: {
          current_password: $("pw-current").value,
          new_password: $("pw-new").value,
        },
      });
      $("pw-current").value = "";
      $("pw-new").value = "";
      msg(
        "Contraseña cambiada. Se cerraron tus sesiones en todos los servicios.",
        true,
      );
    });
  });

  $("logout").addEventListener("click", async () => {
    try {
      await api("/osiris/api/v1/auth/logout", {
        body: { refresh_token: session.refresh_token },
      });
    } finally {
      location.reload();
    }
  });
}
