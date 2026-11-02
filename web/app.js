// Shared helpers for the web client (Module B).

let CSRF = null;  // the session's CSRF token, sent with every state-changing request (FR-B1)

async function api(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (CSRF && method !== "GET") headers["X-CSRF-Token"] = CSRF;
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const err = new Error((data && data.detail) || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function $(id) { return document.getElementById(id); }
function show(id, on = true) { $(id).classList.toggle("hidden", !on); }
function setError(id, err) { $(id).textContent = err ? (err.message || String(err)) : ""; }

// ---------- base64url <-> bytes, for WebAuthn ----------

function b64uToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
}

function bufToB64u(buf) {
  let s = "";
  new Uint8Array(buf).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------- passkeys ----------

async function createPasskey(options) {
  const publicKey = {
    ...options,
    challenge: b64uToBuf(options.challenge),
    user: { ...options.user, id: b64uToBuf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
  const cred = await navigator.credentials.create({ publicKey });
  const json = {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  if (cred.authenticatorAttachment) json.authenticatorAttachment = cred.authenticatorAttachment;
  return json;
}

async function getPasskey(options) {
  const publicKey = {
    ...options,
    challenge: b64uToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
  const cred = await navigator.credentials.get({ publicKey });
  const json = {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  if (cred.authenticatorAttachment) json.authenticatorAttachment = cred.authenticatorAttachment;
  return json;
}

async function loadSession() {
  const me = await api("/session/me");
  CSRF = me.csrf_token;
  return me;
}

function fmtTime(seconds) { return new Date(seconds * 1000).toLocaleString(); }
