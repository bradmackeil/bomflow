/**
 * SOS Inventory OAuth + API proxy for BOMflow.
 *
 * One POST endpoint, dispatched on `body.action`. Every action carries the
 * caller's BOMflow session (`bfToken`, verified with the same HMAC scheme
 * auth.js signs session tokens with) and the active `companyId` — the SOS
 * connection is held per company, shared by everyone signed into it.
 *
 *   status      { bfToken, companyId }                       -> { connected }
 *   exchange    { bfToken, companyId, code, redirectUri }     -> { connected: true }
 *   disconnect  { bfToken, companyId }                       -> { ok: true }
 *   items       { bfToken, companyId, path }                  -> SOS API response body, passthrough
 *
 * The SOS client secret and the access/refresh tokens never reach the
 * browser — they live here and in Netlify Blobs (store "bomflow-sos", key
 * "token:<companyId>").
 *
 * Env vars (Netlify -> Site settings -> Environment variables):
 *   BF_SECRET          - same secret auth.js signs BOMflow session tokens with (required)
 *   SOS_CLIENT_ID      - SOS Inventory OAuth client id (required for exchange/items)
 *   SOS_CLIENT_SECRET  - SOS Inventory OAuth client secret (required for exchange/items)
 *
 * See sos_api_details.txt for the OAuth flow this implements, and
 * sos_item_details.txt for the /item schema.
 */

const crypto = require('crypto');

const STORE_NAME = 'bomflow-sos';
const SOS_HOST = 'api.sosinventory.com';
// Same allowlist the old token-passthrough proxy used — items and their BOMs only.
const PATH_RE = /^item(\/\d+(\/bom)?)?(\?.*)?$/;
const REFRESH_SKEW_MS = 5 * 60 * 1000; // refresh a bit before actual expiry

const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  body: JSON.stringify(obj),
});

// --- BF session token verification (same HMAC scheme as auth.js's makeToken/readToken) ---
const b64urlDecode = (s) =>
  Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
const sign = (str, secret) => crypto.createHmac('sha256', secret).update(str).digest('hex');
function readBfToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = sign(payload, secret);
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  let data;
  try { data = JSON.parse(b64urlDecode(payload)); } catch { return null; }
  if (!data || typeof data.x !== 'number' || Date.now() > data.x) return null;
  return { email: data.e, role: data.r };
}

// Classic `exports.handler` functions run in Lambda-compatibility mode, where
// Netlify Blobs isn't auto-wired — connectLambda(event) hands it the request
// context it needs (mirrors auth.js's openStore).
async function openStore(event) {
  const blobs = await import('@netlify/blobs');
  if (typeof blobs.connectLambda === 'function') {
    try { blobs.connectLambda(event); } catch (_) { /* already configured */ }
  }
  return blobs.getStore(STORE_NAME);
}

const tokenKey = (companyId) => `token:${companyId || 'default'}`;

async function sosTokenRequest(params) {
  const resp = await fetch(`https://${SOS_HOST}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Host: SOS_HOST },
    body: new URLSearchParams(params).toString(),
  });
  const data = await resp.json().catch(() => null);
  if (!resp.ok || !data || !data.access_token) {
    const msg = (data && (data.error_description || data.error)) || `SOS token request failed (HTTP ${resp.status})`;
    throw new Error(msg);
  }
  return data;
}

const getStoredToken = (store, companyId) => store.get(tokenKey(companyId), { type: 'json' });

async function saveToken(store, companyId, tokenData) {
  const rec = {
    access_token: tokenData.access_token,
    refresh_token: tokenData.refresh_token,
    expires_at: Date.now() + (Number(tokenData.expires_in) || 0) * 1000,
  };
  await store.setJSON(tokenKey(companyId), rec);
  return rec;
}

// Returns a valid access token for this company, refreshing first if it's
// near (or past) expiry. Falls back to the (possibly stale) access token on
// a failed refresh so the caller sees SOS's own 401 rather than a proxy error.
async function getLiveToken(store, companyId, clientId, clientSecret) {
  const rec = await getStoredToken(store, companyId);
  if (!rec || !rec.access_token) return null;
  if (Date.now() < rec.expires_at - REFRESH_SKEW_MS) return rec.access_token;
  if (!rec.refresh_token) return rec.access_token;
  try {
    const fresh = await sosTokenRequest({
      grant_type: 'refresh_token',
      refresh_token: rec.refresh_token,
      client_id: clientId,
      client_secret: clientSecret,
    });
    const saved = await saveToken(store, companyId, fresh);
    return saved.access_token;
  } catch (_) {
    return rec.access_token;
  }
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return json(405, { status: 'error', message: 'Method Not Allowed' });

  const bfSecret = process.env.BF_SECRET;
  const clientId = process.env.SOS_CLIENT_ID;
  const clientSecret = process.env.SOS_CLIENT_SECRET;

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { status: 'error', message: 'Bad request' }); }

  const { action, companyId } = body;

  if (!bfSecret) return json(500, { status: 'error', message: 'Server not configured: BF_SECRET is missing.' });
  if (!readBfToken(body.bfToken, bfSecret)) return json(401, { status: 'error', message: 'Sign in first.' });

  let store;
  try { store = await openStore(event); }
  catch (e) { return json(500, { status: 'error', message: 'Storage unavailable: ' + e.message }); }

  switch (action) {
    case 'status': {
      let rec;
      try { rec = await getStoredToken(store, companyId); }
      catch (e) { return json(500, { status: 'error', message: 'Storage error: ' + e.message }); }
      return json(200, { status: 'ok', connected: !!(rec && rec.access_token) });
    }

    case 'exchange': {
      if (!clientId || !clientSecret) {
        return json(500, { status: 'error', message: 'Server not configured: SOS_CLIENT_ID / SOS_CLIENT_SECRET are missing.' });
      }
      if (!body.code || !body.redirectUri) return json(400, { status: 'error', message: 'Missing code or redirectUri' });
      try {
        const tok = await sosTokenRequest({
          grant_type: 'authorization_code',
          client_id: clientId,
          client_secret: clientSecret,
          code: body.code,
          redirect_uri: body.redirectUri,
        });
        await saveToken(store, companyId, tok);
        return json(200, { status: 'ok', connected: true });
      } catch (e) {
        return json(400, { status: 'error', message: e.message });
      }
    }

    case 'disconnect': {
      try { await store.delete(tokenKey(companyId)); } catch (_) { /* already gone */ }
      return json(200, { status: 'ok' });
    }

    case 'items': {
      if (!clientId || !clientSecret) {
        return json(500, { status: 'error', message: 'Server not configured: SOS_CLIENT_ID / SOS_CLIENT_SECRET are missing.' });
      }
      const path = body.path;
      if (!path || !PATH_RE.test(path)) return json(400, { status: 'error', message: 'Invalid path' });

      let accessToken;
      try { accessToken = await getLiveToken(store, companyId, clientId, clientSecret); }
      catch (e) { return json(500, { status: 'error', message: 'Storage error: ' + e.message }); }
      if (!accessToken) return json(409, { status: 'error', message: 'Not connected to SOS Inventory.' });

      try {
        const resp = await fetch(`https://${SOS_HOST}/api/v2/${path}`, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Host: SOS_HOST,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        });
        const data = await resp.text();
        return {
          statusCode: resp.status,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
          body: data,
        };
      } catch (e) {
        return json(502, { status: 'error', message: e.message });
      }
    }

    default:
      return json(400, { status: 'error', message: 'Unknown action.' });
  }
};
