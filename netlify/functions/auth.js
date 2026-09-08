/**
 * BOMflow auth + user management.
 *
 * One POST endpoint, dispatched on `body.action`:
 *   login       { email, password }             -> { token, user }
 *   verify      { token }                        -> { valid, user }
 *   listUsers   { token }                        -> { users }            (admin)
 *   createUser  { token, email, password, role } -> { ok }               (admin)
 *   deleteUser  { token, email }                 -> { ok }               (admin)
 *   setRole     { token, email, role }           -> { ok }               (admin)
 *   setPassword { token, email, password }       -> { ok }               (admin, or self)
 *
 * Storage: Netlify Blobs (store "bomflow-auth", key "users").
 * Env vars (Netlify -> Site settings -> Environment variables):
 *   BF_SECRET        - random string, signs session tokens (required)
 *   BF_ADMIN_EMAIL   - seeds the first admin when the user store is empty
 *   BF_ADMIN_PASSWORD - password for that seed admin
 */

const crypto = require('crypto');

const STORE_NAME = 'bomflow-auth';
const USERS_KEY = 'users';
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 14; // 14 days
const MIN_PW = 8;

const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(obj),
});

const b64url = (s) =>
  Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlDecode = (s) =>
  Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

const sign = (str, secret) => crypto.createHmac('sha256', secret).update(str).digest('hex');

function makeToken(user, secret) {
  const payload = b64url(JSON.stringify({ e: user.email, r: user.role, x: Date.now() + TOKEN_TTL_MS }));
  return payload + '.' + sign(payload, secret);
}

function readToken(token, secret) {
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

function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  return { salt, hash };
}
function checkPassword(pw, salt, hash) {
  if (!salt || !hash) return false;
  const h = crypto.scryptSync(String(pw), salt, 64).toString('hex');
  return h.length === hash.length && crypto.timingSafeEqual(Buffer.from(h), Buffer.from(hash));
}

const normEmail = (e) => String(e || '').trim().toLowerCase();
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

// Classic `exports.handler` functions run in Lambda-compatibility mode, where
// Netlify Blobs isn't auto-wired — connectLambda(event) hands it the request
// context it needs. Harmless if a newer runtime already configured things.
async function openStore(event) {
  const blobs = await import('@netlify/blobs');
  if (typeof blobs.connectLambda === 'function') {
    try { blobs.connectLambda(event); } catch (_) { /* already configured */ }
  }
  return blobs.getStore(STORE_NAME);
}
async function loadUsers(store) {
  const data = await store.get(USERS_KEY, { type: 'json' });
  return data && Array.isArray(data.users) ? data : { users: [] };
}
const saveUsers = (store, data) => store.setJSON(USERS_KEY, data);

// Bootstrap the first admin from BF_ADMIN_EMAIL / BF_ADMIN_PASSWORD. While that
// admin is the *only* user, the env vars stay authoritative — so if the stored
// password drifts from the env var (e.g. it was seeded during setup and then
// changed), it's re-synced here. Once a second user exists, the env vars are
// ignored and passwords are managed in-app.
async function ensureSeedAdmin(store, data) {
  const email = normEmail(process.env.BF_ADMIN_EMAIL);
  const pw = process.env.BF_ADMIN_PASSWORD;
  if (!validEmail(email) || !pw) return data;

  if (data.users.length === 0) {
    const { salt, hash } = hashPassword(pw);
    data.users.push({ email, salt, hash, role: 'admin', createdAt: Date.now() });
    await saveUsers(store, data);
    return data;
  }

  if (data.users.length === 1) {
    const u = data.users[0];
    if (u.email === email && u.role === 'admin' && !checkPassword(pw, u.salt, u.hash)) {
      const { salt, hash } = hashPassword(pw);
      u.salt = salt; u.hash = hash;
      await saveUsers(store, data);
    }
  }
  return data;
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method Not Allowed' });

  const secret = process.env.BF_SECRET;
  if (!secret) {
    return json(500, {
      error: 'Server not configured: BF_SECRET is missing.',
      diag: {
        context: process.env.CONTEXT || null,
        runsOnNetlify: !!process.env.NETLIFY,
        sees_BF_SECRET: !!process.env.BF_SECRET,
        sees_BF_ADMIN_EMAIL: !!process.env.BF_ADMIN_EMAIL,
        sees_BF_ADMIN_PASSWORD: !!process.env.BF_ADMIN_PASSWORD,
      },
    });
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Bad request.' }); }
  const action = body.action;

  let store;
  try { store = await openStore(event); }
  catch (e) { return json(500, { error: 'User storage unavailable: ' + e.message }); }

  let data;
  try {
    data = await loadUsers(store);
    data = await ensureSeedAdmin(store, data);
  } catch (e) {
    return json(500, { error: 'User storage error: ' + e.message });
  }

  const findUser = (email) => data.users.find((u) => u.email === normEmail(email));
  const publicUser = (u) => ({ email: u.email, role: u.role, createdAt: u.createdAt || null });
  const adminCount = () => data.users.filter((u) => u.role === 'admin').length;

  const caller = readToken(body.token, secret);
  const callerUser = caller ? findUser(caller.email) : null;
  const isAdmin = !!callerUser && callerUser.role === 'admin';

  switch (action) {
    // Unauthenticated setup diagnostic. Goes quiet once any user exists, so it
    // only ever exposes anything while the instance is still unconfigured.
    case 'diag': {
      if (data.users.length > 0) return json(200, { ok: true, configured: true });
      const seedEmail = normEmail(process.env.BF_ADMIN_EMAIL);
      return json(200, {
        configured: false,
        sees_BF_SECRET: !!process.env.BF_SECRET,
        sees_BF_ADMIN_EMAIL: !!process.env.BF_ADMIN_EMAIL,
        sees_BF_ADMIN_PASSWORD: !!process.env.BF_ADMIN_PASSWORD,
        seedEmailValid: validEmail(seedEmail),
        userCount: 0,
        storageOk: true,
      });
    }

    case 'login': {
      const u = findUser(body.email);
      if (!u || !checkPassword(body.password, u.salt, u.hash)) {
        return json(401, {
          error: 'Incorrect email or password.',
          hint: data.users.length === 0
            ? 'No users exist yet — BF_ADMIN_EMAIL / BF_ADMIN_PASSWORD are not reaching the function.'
            : undefined,
        });
      }
      return json(200, { token: makeToken(u, secret), user: publicUser(u) });
    }

    case 'verify': {
      if (!callerUser) return json(401, { valid: false });
      return json(200, { valid: true, user: publicUser(callerUser) });
    }

    case 'listUsers': {
      if (!isAdmin) return json(403, { error: 'Admins only.' });
      return json(200, { users: data.users.map(publicUser) });
    }

    case 'createUser': {
      if (!isAdmin) return json(403, { error: 'Admins only.' });
      const email = normEmail(body.email);
      if (!validEmail(email)) return json(400, { error: 'Enter a valid email address.' });
      if (findUser(email)) return json(409, { error: 'That user already exists.' });
      if (!body.password || String(body.password).length < MIN_PW) {
        return json(400, { error: 'Password must be at least ' + MIN_PW + ' characters.' });
      }
      const role = body.role === 'admin' ? 'admin' : 'user';
      const { salt, hash } = hashPassword(body.password);
      data.users.push({ email, salt, hash, role, createdAt: Date.now() });
      await saveUsers(store, data);
      return json(200, { ok: true, user: publicUser(data.users[data.users.length - 1]) });
    }

    case 'deleteUser': {
      if (!isAdmin) return json(403, { error: 'Admins only.' });
      const email = normEmail(body.email);
      const u = findUser(email);
      if (!u) return json(404, { error: 'No such user.' });
      if (email === callerUser.email) return json(400, { error: 'You can’t delete your own account.' });
      if (u.role === 'admin' && adminCount() <= 1) return json(400, { error: 'Can’t delete the last admin.' });
      data.users = data.users.filter((x) => x.email !== email);
      await saveUsers(store, data);
      return json(200, { ok: true });
    }

    case 'setRole': {
      if (!isAdmin) return json(403, { error: 'Admins only.' });
      const email = normEmail(body.email);
      const u = findUser(email);
      if (!u) return json(404, { error: 'No such user.' });
      const role = body.role === 'admin' ? 'admin' : 'user';
      if (u.role === 'admin' && role !== 'admin' && adminCount() <= 1) {
        return json(400, { error: 'Can’t remove admin from the last admin.' });
      }
      u.role = role;
      await saveUsers(store, data);
      return json(200, { ok: true });
    }

    case 'setPassword': {
      const email = normEmail(body.email);
      const selfService = !!callerUser && callerUser.email === email;
      if (!isAdmin && !selfService) return json(403, { error: 'Not allowed.' });
      const u = findUser(email);
      if (!u) return json(404, { error: 'No such user.' });
      if (!body.password || String(body.password).length < MIN_PW) {
        return json(400, { error: 'Password must be at least ' + MIN_PW + ' characters.' });
      }
      const { salt, hash } = hashPassword(body.password);
      u.salt = salt;
      u.hash = hash;
      await saveUsers(store, data);
      return json(200, { ok: true });
    }

    default:
      return json(400, { error: 'Unknown action.' });
  }
};
