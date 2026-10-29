import { OsirisClient } from "/osiris-pkce.js";

const aud = document.getElementById("aud");
const out = document.getElementById("out");
const show = (text) => { out.hidden = false; out.textContent = text; };

const client = () => new OsirisClient({
  issuer: location.origin,
  audience: aud.value.trim(),
  redirectUri: `${location.origin}/callback-test`,
});

const decode = (jwt) =>
  JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));

document.getElementById("start").addEventListener("click", async () => {
  try {
    sessionStorage.setItem("osiris:test-aud", aud.value.trim());
    await client().login();
  } catch (e) {
    show(`Error: ${e.message}`);
  }
});

if (new URLSearchParams(location.search).has("code")) {
  aud.value = sessionStorage.getItem("osiris:test-aud") ?? aud.value;
  try {
    const c = client();
    await c.handleCallback();
    const token = await c.getAccessToken();
    show(`Flujo completo OK. Claims del access token:\n\n${JSON.stringify(decode(token), null, 2)}`);
  } catch (e) {
    show(`Error: ${e.message}`);
  }
}
