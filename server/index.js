/**
 * Icebreaker MVP server (fixed)
 *
 * Key fixes:
 * - Auth tokens are stateless (HMAC signed) so restarting the server doesn't invalidate sessions.
 * - Catch-all route uses RegExp (avoids path-to-regexp "Missing parameter name" crash).
 * - /api endpoints match the latest HTML.
 * - JSON parsing everywhere (no more "Bad JSON").
 */

const express = require('express');

const { attachPush } = require("./icebreaker_push_addon");
// --- TEST MODE (no paywalls, unlimited actions, reveal profile viewers) ---
// For launch/testing we default to TEST_MODE ON unless explicitly disabled.
// Set TEST_MODE=false in env to re-enable limits/payments later.
// NOTE: For the initial free launch we force TEST_MODE ON.
// When you decide to re-enable limits/payments, change this to read from env again.
const TEST_MODE = true;

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ======= CORS (required when frontend and API are on different domains) =======
const ALLOWED_ORIGINS = new Set([
  'https://icebreakerparty.com',
  'https://www.icebreakerparty.com',
  'http://icebreakerparty.com',
  'http://www.icebreakerparty.com',
]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function normName(n){
  return String(n||"").trim().replace(/^@+/, "").replace(/\s+/g," ").trim().toLowerCase();
}

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

// ======= Storage (simple in-memory + small JSON file for users) =======
const DATA_DIR = path.join(__dirname, '..', '..', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: {} }, null, 2), 'utf8');
}

function readUsers() {
  ensureDataDir();
  const raw = fs.readFileSync(USERS_FILE, 'utf8');
  const parsed = JSON.parse(raw || '{"users":{}}');
  return parsed.users || {};
}

function writeUsers(usersObj) {
  ensureDataDir();
  fs.writeFileSync(USERS_FILE, JSON.stringify({ users: usersObj }, null, 2), 'utf8');
}

// ======= Monetización (MVP): 2 chats (con mensaje) gratis / día =======
// Regla: cuenta 1 cuando envías tu PRIMER mensaje del día a una persona nueva.
// Al llegar al límite, bloqueamos: buscar cercanos + enviar solicitudes + iniciar chats nuevos.
const FREE_CHAT_STARTS_PER_DAY = Number(process.env.FREE_CHAT_STARTS_PER_DAY ?? 2);

// ======= Invites / Rewards (MVP) =======
// Interacciones gratis: base 2 chats iniciados/dia + bonus por invites aceptados.
// Tiers:
//  - 0 invites: +0
//  - 1 invite:  +1
//  - 3 invites: +3
//  - 5 invites: +5
//  - 10 invites: All Night Long 24h (premiumUntil)

function makeInviteCode(){
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  for(let i=0;i<8;i++) out += alphabet[Math.floor(Math.random()*alphabet.length)];
  return out;
}

function inviteBonus(count){
  const n = Number(count||0);
  if(n >= 5) return 5;
  if(n >= 3) return 3;
  if(n >= 1) return 1;
  return 0;
}

function isPremiumUser(u){
  if(!u) return false;
  if(u.premium) return true;
  const pu = Number(u.premiumUntil||0);
  if(Number.isFinite(pu) && pu > Date.now()) return true;
  return false;
}

function ensureInviteFields(users, username){
  const u = ensureUserMeta(users, username);
  if(!u) return null;
  if(!u.invites) u.invites = { code: makeInviteCode(), acceptedCount: 0, acceptedUsers: [] };
  if(!u.invites.code) u.invites.code = makeInviteCode();
  if(typeof u.invites.acceptedCount !== 'number') u.invites.acceptedCount = 0;
  if(!Array.isArray(u.invites.acceptedUsers)) u.invites.acceptedUsers = [];
  if(typeof u.invitedBy !== 'string') u.invitedBy = (u.invitedBy == null ? '' : String(u.invitedBy));
  if(typeof u.premiumUntil !== 'number') u.premiumUntil = 0;
  return u;
}

function dailyLimitFor(u){
  const base = FREE_CHAT_STARTS_PER_DAY;
  if(isPremiumUser(u)) return base;
  const bonus = inviteBonus(u?.invites?.acceptedCount || 0);
  return base + bonus;
}

function maybeGrantAllNightLong(u){
  // If reached 10 accepted invites, grant 24h premium if not already active.
  const count = Number(u?.invites?.acceptedCount || 0);
  if(count >= 10){
    const now = Date.now();
    const cur = Number(u.premiumUntil||0);
    if(!Number.isFinite(cur) || cur < now){
      u.premiumUntil = now + 24*60*60*1000;
    }
  }
}

function findUserByInviteCode(users, code){
  const c = (code||'').toString().trim().toUpperCase();
  if(!c) return null;
  for(const name of Object.keys(users)){
    const u = users[name];
    const uc = (u?.invites?.code || '').toString().trim().toUpperCase();
    if(uc && uc == c) return name;
  }
  return null;
}

function redeemInvite(users, redeemerUsername, code){
  const redeemer = ensureInviteFields(users, redeemerUsername);
  if(!redeemer) return { ok:false, error:'User not found' };
  const c = (code||'').toString().trim().toUpperCase();
  if(!c) return { ok:false, error:'Missing code' };

  const inviterName = findUserByInviteCode(users, c);
  if(!inviterName) return { ok:false, error:'Codigo no valido' };
  if(inviterName === redeemerUsername) return { ok:false, error:'No puedes invitarte a ti mismo' };

  if(redeemer.invitedBy && redeemer.invitedBy.length > 0){
    return { ok:false, error:'Ya has usado un codigo de invitacion' };
  }

  const inviter = ensureInviteFields(users, inviterName);
  if(!inviter) return { ok:false, error:'Inviter not found' };

  // prevent duplicates
  if(inviter.invites.acceptedUsers.includes(redeemerUsername)){
    redeemer.invitedBy = inviterName;
    maybeGrantAllNightLong(inviter);
    return { ok:true, inviter: inviterName, acceptedCount: inviter.invites.acceptedCount };
  }

  inviter.invites.acceptedUsers.push(redeemerUsername);
  inviter.invites.acceptedCount = (inviter.invites.acceptedCount||0) + 1;
  redeemer.invitedBy = inviterName;
  maybeGrantAllNightLong(inviter);

  return { ok:true, inviter: inviterName, acceptedCount: inviter.invites.acceptedCount };
}


function todayKey(){
  // YYYY-MM-DD en hora UTC (suficiente para MVP)
  return new Date().toISOString().slice(0,10);
}

function ensureUserMeta(users, username){
  const u = users[username];
  if(!u) return null;
  if(typeof u.premium !== 'boolean') u.premium = false;
  if(!u.plan) u.plan = null;

  // invites + temporary premium
  if(!u.invites) u.invites = { code: makeInviteCode(), acceptedCount: 0, acceptedUsers: [] };
  if(!u.invites.code) u.invites.code = makeInviteCode();
  if(typeof u.invites.acceptedCount !== 'number') u.invites.acceptedCount = 0;
  if(!Array.isArray(u.invites.acceptedUsers)) u.invites.acceptedUsers = [];
  if(typeof u.invitedBy !== 'string') u.invitedBy = (u.invitedBy == null ? '' : String(u.invitedBy));
  if(typeof u.premiumUntil !== 'number') u.premiumUntil = 0;

  // Guardamos los "chat starts" del día (peers a los que ya les has escrito hoy)
  if(!u.freeChatStarts) u.freeChatStarts = { day: todayKey(), peers: [] };
  if(!u.freeChatStarts.day) u.freeChatStarts.day = todayKey();
  if(!Array.isArray(u.freeChatStarts.peers)) u.freeChatStarts.peers = [];

  // reset diario
  const tk = todayKey();
  if(u.freeChatStarts.day !== tk){
    u.freeChatStarts.day = tk;
    u.freeChatStarts.peers = [];
  }
  return u;
}

function entitlement(users, username){
  // Free launch mode: unlimited, no paywalls.
  // Return a shape compatible with the rest of the code (ok/premium/etc.).
  if (TEST_MODE) {
    return { ok:true, premium:true, limit: 999999, remaining: Infinity, used: 0 };
  }

  const u = ensureUserMeta(users, username);
  if(!u) return { ok:false, error:'User not found' };

  // reset diario (ya lo hace ensureUserMeta) + grants
  maybeGrantAllNightLong(u);

  const used = (u.freeChatStarts.peers || []).length;
  const limit = dailyLimitFor(u);

  if(isPremiumUser(u)){
    return { ok:true, premium:true, limit, remaining: Infinity, used };
  }

  const remaining = Math.max(0, limit - used);
  return { ok:true, premium:false, limit, remaining, used };
}


function dayKey(d=new Date()){
  const y = d.getFullYear();
  const m = String(d.getMonth()+1).padStart(2,'0');
  const da = String(d.getDate()).padStart(2,'0');
  return `${y}-${m}-${da}`;
}

function isBlocked(users, username){
  const e = entitlement(users, username);
  if(!e.ok) return { blocked:false, e };
  if(e.premium) return { blocked:false, e };
  return { blocked: e.remaining <= 0, e };
}


function normalizeUser(u){
  if(!u) return;
  u.viewsLog = Array.isArray(u.viewsLog) ? u.viewsLog : [];
  u.viewsDay = typeof u.viewsDay === 'string' ? u.viewsDay : dayKey();
  u.seenByTonightUnlocked = !!u.seenByTonightUnlocked;
  // reset daily
  const dk = dayKey();
  if(u.viewsDay !== dk){
    u.viewsDay = dk;
    u.viewsLog = [];
    u.seenByTonightUnlocked = false;
  }
}


function chargeChatStartIfNeeded(users, username, other){
  // Free launch mode: don't charge chat starts.
  if (TEST_MODE) return { ok:true, premium:true, limit: 999999, remaining: Infinity, started:false };

  const u = ensureUserMeta(users, username);
  if(!u) return { ok:false, error:'User not found' };
  maybeGrantAllNightLong(u);

  const limit = dailyLimitFor(u);
  if(isPremiumUser(u)) return { ok:true, premium:true, limit, remaining: Infinity, started:false };

  const otherKey = String(other || '');
  const peers = u.freeChatStarts.peers || [];
  if(peers.includes(otherKey)) {
    const e = entitlement(users, username);
    return { ok:true, premium:false, limit: e.limit, remaining: e.remaining, started:false };
  }

  const e = entitlement(users, username);
  if(e.remaining <= 0){
    return { ok:false, paywall:true, limit: e.limit, remaining: e.remaining };
  }

  peers.push(otherKey);
  u.freeChatStarts.peers = peers;
  const e2 = entitlement(users, username);
  return { ok:true, premium:false, limit: e2.limit, remaining: e2.remaining, started:true };
}

// GPS positions: username -> { lat, lon, t }
const positions = new Map();

// requests: toUser -> array of { from, t }
const inbox = new Map();

// matches: username -> Set(other)
const matches = new Map();

// chat: pairKey -> array of { from, text, t }
const chats = new Map();

function pairKey(a, b) {
  return [a, b].sort().join('::');
}

// ======= Auth (stateless token) =======
// IMPORTANT: keep this stable on your machine; you can move to .env later.
const TOKEN_SECRET = process.env.ICEBREAKER_SECRET || 'icebreaker-dev-secret-change-me';

function signToken(username) {
  const u = String(username);
  const payload = Buffer.from(u, 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  // timing safe compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;
  const username = Buffer.from(payload, 'base64url').toString('utf8');
  return username || null;
}

function authRequired(req, res, next) {
  const h = req.headers['authorization'];
  if (!h || typeof h !== 'string') return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const token = m[1];
  const username = verifyToken(token);
  if (!username) return res.status(401).json({ ok: false, error: 'Unauthorized' });

  // Optional: ensure user exists
  const users = readUsers();
  if (!users[username]) return res.status(401).json({ ok: false, error: 'Unauthorized' });

  req.user = username;
  next();
}

// Push notifications (lock-screen)
const push = attachPush(app, authRequired, readUsers, writeUsers);

// Alias used by some patches
const requireAuth = authRequired;

// ======= Middleware =======
// ======= Payments (Stripe) =======
// Plans:
//  - allnight: one-time payment -> premiumUntil = now + 24h
//  - monthly: subscription -> premiumUntil = current_period_end (or now + 30d fallback)
//
// Env required:
//  - STRIPE_SECRET_KEY
//  - STRIPE_WEBHOOK_SECRET
//  - STRIPE_PRICE_ALLNIGHT   (one-time Price ID, €1.99)
//  - STRIPE_PRICE_MONTHLY    (recurring Price ID, e.g. €5.99/€6.99 per month)
// Optional:
//  - PUBLIC_BASE_URL         (e.g. https://xxxx.ngrok-free.app)

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_ALLNIGHT = process.env.STRIPE_PRICE_ALLNIGHT || '';
const STRIPE_PRICE_MONTHLY = process.env.STRIPE_PRICE_MONTHLY || '';
const stripe = STRIPE_SECRET_KEY ? require('stripe')(STRIPE_SECRET_KEY) : null;

function getBaseUrl(req){
  const env = (process.env.PUBLIC_BASE_URL || '').trim();
  if(env) return env.replace(/\/+$/,'');
  // respect reverse proxies like ngrok
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').toString().split(',')[0].trim();
  const host = req.headers['x-forwarded-host'] || req.headers['host'];
  return `${proto}://${host}`.replace(/\/+$/,'');
}

// Stripe webhook MUST use raw body, so define BEFORE express.json()
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  try{
    // Payments disabled while we're in free/unlimited beta.
    if(TEST_MODE){
      return res.status(200).json({ received:true, testMode:true });
    }
    if(!stripe || !STRIPE_WEBHOOK_SECRET){
      return res.status(500).send('Stripe not configured');
    }
    const sig = req.headers['stripe-signature'];
    let event;
    try{
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    }catch(err){
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // We store username in metadata (set in checkout)
    const type = event.type;

    const users = readUsers();

    const setAllNight = (username)=>{
      const u = ensureUserMeta(users, username);
      if(!u) return;
      const now = Date.now();
      const cur = Number(u.premiumUntil||0);
      const base = (Number.isFinite(cur) && cur>now) ? cur : now;
      // extend to keep it generous if they already have time left
      u.premiumUntil = base + 24*60*60*1000;
      u.premium = false; // we rely on premiumUntil for time-boxed access
      writeUsers(users);
    };

    const setMonthlyUntil = (username, untilMs)=>{
      const u = ensureUserMeta(users, username);
      if(!u) return;
      const now = Date.now();
      const cur = Number(u.premiumUntil||0);
      const base = (Number.isFinite(cur) && cur>now) ? cur : now;
      const newUntil = Number(untilMs||0);
      // if we have a concrete period end, use max(base, newUntil)
      if(Number.isFinite(newUntil) && newUntil > now){
        u.premiumUntil = Math.max(base, newUntil);
      }else{
        u.premiumUntil = base + 30*24*60*60*1000; // fallback
      }
      u.premium = false;
      writeUsers(users);
    };

    (async ()=>{
      if(type === 'checkout.session.completed'){
        const session = event.data.object;
        const md = session.metadata || {};
        const username = normName(md.username || '');
        const plan = (md.plan || '').toString();
        if(username){
          if(plan === 'allnight'){
            setAllNight(username);
          }else if(plan === 'monthly'){
            // subscription period end
            try{
              if(session.subscription){
                const sub = await stripe.subscriptions.retrieve(session.subscription);
                const end = (sub.current_period_end ? sub.current_period_end*1000 : 0);
                setMonthlyUntil(username, end);
              }else{
                setMonthlyUntil(username, 0);
              }
            }catch(e){
              setMonthlyUntil(username, 0);
            }
          }
        }
      }else if(type === 'invoice.paid'){
        // Keep monthly active on renewals
        const inv = event.data.object;
        const subId = inv.subscription;
        if(subId){
          try{
            const sub = await stripe.subscriptions.retrieve(subId);
            const md = sub.metadata || {};
            const username = normName(md.username || '');
            if(username){
              const end = (sub.current_period_end ? sub.current_period_end*1000 : 0);
              setMonthlyUntil(username, end);
            }
          }catch(e){}
        }
      }
    })().then(()=>{
      return res.json({ received: true });
    }).catch((e)=>{
      return res.status(500).send(String(e?.message||e));
    });

  }catch(e){
    return res.status(500).send(String(e?.message||e));
  }
});

// Create Stripe Checkout Session
app.post('/api/payments/checkout', authRequired, async (req, res) => {
  try{
    // Payments disabled while we're in free/unlimited beta.
    if(TEST_MODE){
      return res.status(403).json({ ok:false, error:'Payments disabled (free beta)', testMode:true });
    }
    if(!stripe){
      return res.status(500).json({ ok:false, error:'Stripe not configured' });
    }
    const plan = ((req.body||{}).plan || 'allnight').toString();
    const username = normName(req.user);

    let price = '';
    let mode = 'payment';
    if(plan === 'monthly'){
      price = STRIPE_PRICE_MONTHLY;
      mode = 'subscription';
    }else{
      price = STRIPE_PRICE_ALLNIGHT;
      mode = 'payment';
    }
    if(!price){
      return res.status(400).json({ ok:false, error:'Missing Stripe price id for plan' });
    }

    const base = getBaseUrl(req);
    const success = `${base}/?pay=success&plan=${encodeURIComponent(plan)}`;
    const cancel = `${base}/?pay=cancel&plan=${encodeURIComponent(plan)}`;

    const session = await stripe.checkout.sessions.create({
      mode,
      line_items: [{ price, quantity: 1 }],
      success_url: success,
      cancel_url: cancel,
      client_reference_id: username,
      metadata: { username, plan },
      subscription_data: plan === 'monthly' ? { metadata: { username, plan } } : undefined,
    });

    return res.json({ ok:true, url: session.url });
  }catch(e){
    return res.status(500).json({ ok:false, error:String(e?.message||e) });
  }
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static from /public
const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
app.use(express.static(PUBLIC_DIR));

// ======= API =======

// Front-end sends { username, pin }. We also accept { username, password } for backwards-compat.
app.post('/api/auth/register', (req, res) => {
  try {
    const body = req.body || {};
    const username = (body.username || body.user || '').toString().trim();
    const pass = (body.pin || body.pass || body.password || '').toString();
    const gender = (body.gender || '').toString().toLowerCase();
    if (!username || !pass) return res.status(400).json({ ok: false, error: 'Missing username/pin' });
    const users = readUsers();
    if (users[username]) return res.status(409).json({ ok: false, error: 'Username taken' });

    const salt = crypto.randomBytes(12).toString('hex');
    const hash = crypto.createHash('sha256').update(`${salt}:${pass}`).digest('hex');
    users[username] = { salt, hash, createdAt: Date.now(), premium: false, plan: null, freeChatStarts: { day: todayKey(), peers: [] } };
    // ensure meta fields (invites, premiumUntil, resets)
    ensureUserMeta(users, username);

    // optional referral code
    const ref = (body.ref || body.inviteCode || body.code || '').toString().trim();
    if(ref){
      redeemInvite(users, username, ref);
    }
    writeUsers(users);

    const token = signToken(username);
    return res.json({ ok: true, token, user: username });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const body = req.body || {};
    // Accept both {username,pin} and legacy {user,pass}/{user,password}
    const username = (body.username ?? body.user ?? '').toString().trim();
    const pass = (body.pin ?? body.pass ?? body.password ?? '').toString();
    if (!username || !pass) return res.status(400).json({ ok: false, error: 'Missing username/pin' });

    const users = readUsers();
    const u = users[username];
    if (!u) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    const hash = crypto.createHash('sha256').update(`${u.salt}:${pass}`).digest('hex');
    if (hash !== u.hash) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

    const token = signToken(username);
    return res.json({ ok: true, token, user: username });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get('/api/auth/me', authRequired, (req, res) => {
  try{
    const users = readUsers();
    const u = users[req.user];
    if(!u) return res.status(401).json({ ok:false, error:'Unauthorized' });
    return res.json({ ok:true, id: req.user, name: req.user, gender: u.gender || '', photo: u.photo || '' });
  }catch(e){
    return res.status(500).json({ ok:false, error:String(e?.message||e) });
  }
});

// Invite info for current user
app.get('/api/invite/me', authRequired, (req, res) => {
  const users = readUsers();
  const u = ensureInviteFields(users, req.user);
  if(!u) return res.status(404).json({ ok:false, error:'User not found' });
  maybeGrantAllNightLong(u);
  const e = entitlement(users, req.user);
  writeUsers(users);
  return res.json({
    ok: true,
    code: u.invites.code,
    acceptedCount: u.invites.acceptedCount,
    bonus: inviteBonus(u.invites.acceptedCount),
    premiumUntil: u.premiumUntil || 0,
    used: e.used,
    limit: e.limit,
    remaining: e.remaining,
  });
});

// Redeem an invite code (only once per user)
app.post('/api/invite/redeem', authRequired, (req, res) => {
  const body = req.body || {};
  const code = (body.code || body.ref || '').toString().trim();
  if(!code) return res.status(400).json({ ok:false, error:'Missing code' });

  const users = readUsers();
  ensureInviteFields(users, req.user);
  const r = redeemInvite(users, req.user, code);
  if(!r.ok){
    writeUsers(users);
    return res.status(400).json({ ok:false, error: r.error || 'Redeem failed' });
  }
  writeUsers(users);
  return res.json({ ok:true, inviter: r.inviter, acceptedCount: r.acceptedCount });
});


// GPS update
app.post('/api/gps/update', authRequired, (req, res) => {
  const { lat, lon } = req.body || {};
  const latN = Number(lat);
  const lonN = Number(lon);
  if (!Number.isFinite(latN) || !Number.isFinite(lonN)) {
    return res.status(400).json({ ok: false, error: 'Invalid lat/lon' });
  }
  positions.set(req.user, { lat: latN, lon: lonN, t: Date.now() });
  return res.json({ ok: true });
});

// Near users
app.get('/api/near', authRequired, (req, res) => {
  const radius = Number(req.query.radius ?? 500);
  const maxAgeSec = Number(req.query.maxAgeSec ?? 60);
  const now = Date.now();

  const me = req.user;
  // Monetización: si estás bloqueado hoy, no puedes buscar cercanos
  const users = readUsers();
  const blk = isBlocked(users, me);
  if(blk.blocked){
    writeUsers(users);
    return res.status(402).json({ ok:false, paywall:true, error:'Paywall', limit: blk.e.limit, remaining: blk.e.remaining });
  }

  const mePos = positions.get(me);
  const ent0 = entitlement(users, me);
  if (!mePos) {
    return res.json({ ok:true, me, radius, hasMePos:false, near: [], remaining: ent0.remaining, limit: ent0.limit });
  }

  const maxAgeMs = Math.max(1, maxAgeSec) * 1000;
  const out = [];

  for (const [user, pos] of positions.entries()) {
    if (user === me) continue;
    if (!pos || (now - pos.t) > maxAgeMs) continue;

    const d = distanceMeters(mePos.lat, mePos.lon, pos.lat, pos.lon);
    if (d <= radius) {
      const u = users[user] || {};
      out.push({
        username: user,
        distance_m: Math.round(d),
        lastSeen: new Date(pos.t).toISOString(),
        gender: u.gender || '',
        photo: u.photo || ''
      });
    }
  }

  out.sort((a, b) => a.distance_m - b.distance_m);
  const entNear = entitlement(users, me);
  return res.json({ ok:true, me, radius, hasMePos:true, near: out, remaining: entNear.remaining, limit: entNear.limit });
});

// Requests
app.post('/api/request/send', authRequired, (req, res) => {
  const from = req.user;
  const { to } = req.body || {};
  if (!to || typeof to !== 'string') return res.status(400).json({ ok: false, error: 'Missing to' });
  if (to === from) return res.status(400).json({ ok: false, error: 'Cannot request yourself' });

  // Only allow requesting someone who exists (case-insensitive)
  const users = readUsers();
  const toKey = Object.keys(users).find(k => k.toLowerCase() === String(to).toLowerCase());
  if (!toKey) return res.status(404).json({ ok: false, error: 'User not found' });

  // Idempotente: si ya hay solicitud, no consumimos acción
  const list = inbox.get(toKey) || [];
  if (list.some(r => r.from === from)) {
    const ent = entitlement(users, from);
    writeUsers(users);
    return res.json({ ok: true, already: true, remaining: ent.remaining, limit: ent.limit });
  }

  // Monetización: si estás bloqueado hoy, no puedes enviar nuevas solicitudes
  const blk = isBlocked(users, from);
  if(blk.blocked){
    writeUsers(users);
    return res.status(402).json({ ok:false, paywall:true, error:'Paywall', limit: blk.e.limit, remaining: blk.e.remaining });
  }

  list.push({ from, t: Date.now() });
  inbox.set(toKey, list);
  writeUsers(users);
  const ent = entitlement(users, from);
  return res.json({ ok:true, remaining: ent.remaining, limit: ent.limit });
});

app.post('/api/request/respond', authRequired, (req, res) => {
  const me = req.user;

  // Compatibility:
  // - New clients send: { from: 'alice', action: 'accept'|'reject' }
  // - Older clients send: { from: 'alice', accept: true|false }
  const body = req.body || {};
  const from = body.from;
  const action = body.action;
  const accept = body.accept;

  if (!from || typeof from !== 'string') {
    return res.status(400).json({ ok: false, error: 'Missing from' });
  }

  let act = String(action || '').toLowerCase().trim();
  if (!act) {
    if (typeof accept === 'boolean') act = accept ? 'accept' : 'reject';
  }
  if (act !== 'accept' && act !== 'reject') {
    return res.status(400).json({ ok: false, error: 'Invalid action' });
  }

  // Remove the request from inbox (idempotent)
  const list = inbox.get(me) || [];
  const next = list.filter(r => r.from !== from);
  inbox.set(me, next);

  if (act === 'accept') {
    addMatch(me, from);
    addMatch(from, me);
    // Ensure chat array exists
    const k = pairKey(me, from);
    if (!chats.has(k)) chats.set(k, []);
    return res.json({ ok: true, matched: true });
  }

  return res.json({ ok: true, matched: false });
});

// Inbox (compat): older clients used /api/inbox/:me returning a raw array.
// Newer clients use /api/inbox and expect { ok:true, inbox:[...] }.
function inboxPayload(me){
  return { ok: true, inbox: inbox.get(me) || [] };
}

app.get('/api/inbox/:me', authRequired, (req, res) => {
  const me = req.params.me;
  if (me !== req.user) return res.status(403).json({ ok: false, error: 'Forbidden' });
  return res.json(inboxPayload(me));
});

app.get('/api/inbox', authRequired, (req, res) => {
  return res.json(inboxPayload(req.user));
});

function matchesPayload(me){
  const set = matches.get(me) || new Set();
  const arr = Array.from(set);
  return { ok: true, matches: arr, conexiones: arr, conexiónes: arr };
}

app.get('/api/matches/:me', authRequired, (req, res) => {
  const me = req.params.me;
  if (me !== req.user) return res.status(403).json({ ok: false, error: 'Forbidden' });
  return res.json(matchesPayload(me));
});

app.get('/api/matches', authRequired, (req, res) => {
  return res.json(matchesPayload(req.user));
});

// Chat
app.get('/api/chat/messages', authRequired, (req, res) => {
  const me = req.user;
  const other = String(req.query.with || '');
  if (!other) return res.status(400).json({ ok: false, error: 'Missing with' });
  if (!isMatched(me, other)) return res.status(403).json({ ok: false, error: 'Not matched' });
  const k = pairKey(me, other);
  return res.json({ ok: true, with: other, messages: chats.get(k) || [] });
});

app.post('/api/chat/send', authRequired, (req, res) => {
  const me = req.user;
  const { to, text, image, kind } = req.body || {};
  const other = String(to || '');
  const msgText = String(text || '');
  const msgKind = String(kind || (image ? 'image' : 'text'));

  if (!other) return res.status(400).json({ ok: false, error: 'Missing to' });
  if (!isMatched(me, other)) return res.status(403).json({ ok: false, error: 'Not matched' });

  // Validate payload
  let payload = { from: me, ts: Date.now() };
  if (msgKind === 'image') {
    const img = String(image || '');
    if (!img.startsWith('data:image/')) return res.status(400).json({ ok:false, error:'Invalid image' });
    // Limit ~1.5MB base64 string to avoid memory abuse
    if (img.length > 1500000) return res.status(413).json({ ok:false, error:'Image too large' });
    payload.kind = 'image';
    payload.image = img;
    // optional caption
    if (msgText && msgText.trim()) payload.text = msgText.trim().slice(0, 500);
  } else {
    const msg = msgText.trim();
    if (!msg) return res.status(400).json({ ok: false, error: 'Empty message' });
    payload.kind = 'text';
    payload.text = msg.slice(0, 2000);
  }

  const users = readUsers();
  // Monetización: cuenta 1 si es tu primer mensaje del día a este usuario
  const charge = chargeChatStartIfNeeded(users, me, other);
  if(!charge.ok && charge.paywall){
    writeUsers(users);
    return res.status(402).json({ ok:false, paywall:true, error:'Paywall', limit: charge.limit, remaining: charge.remaining });
  }

  const k = pairKey(me, other);
  const arr = chats.get(k) || [];
  arr.push(payload);
  chats.set(k, arr);
  writeUsers(users);
  return res.json({ ok:true, remaining: charge.remaining, limit: charge.limit });
});

// ======= SPA fallback (must be AFTER /api routes) =======
// Express 5 + path-to-regexp can crash on '*' routes. Use RegExp.
app.get(/^\/(?!api)(.*)/, (req, res) => {
  return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// ======= Helpers =======
function addMatch(a, b) {
  const s = matches.get(a) || new Set();
  s.add(b);
  matches.set(a, s);
}

function isMatched(a, b) {
  const s = matches.get(a);
  return !!(s && s.has(b));
}

function distanceMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (x) => (x * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

app.listen(PORT, () => {
  ensureDataDir();
  console.log(`Icebreaker escuchando en http://localhost:${PORT}`);
});

// ---- Profile views ("Who viewed your profile tonight") ----
app.post('/api/profile/view', authRequired, (req, res) => {
  try{
    const me = req.user;
    const { to } = req.body || {};
    if(!to || typeof to !== 'string') return res.status(400).json({ ok:false, error:'Missing "to"' });
    const users = readUsers();
    if(!users[me] || !users[to]) return res.status(404).json({ ok:false, error:'User not found' });
    normalizeUser(users[me]);
    normalizeUser(users[to]);

    // ignore self
    if(me === to) return res.json({ ok:true, ignored:true });

    // de-dup: only one view per viewer per day
    const exists = users[to].viewsLog.some(v => v && v.from === me);
    if(!exists){
      users[to].viewsLog.push({ from: me, ts: Date.now() });
      writeUsers(users);
    }
    return res.json({ ok:true });
  }catch(e){
    return res.status(401).json({ ok:false, error:'Unauthorized' });
  }
});

app.get('/api/profile/views', authRequired, (req, res) => {
  try{
    const me = req.user;
    const users = readUsers();
    if(!users[me]) return res.status(404).json({ ok:false, error:'User not found' });
    normalizeUser(users[me]);

    const count = users[me].viewsLog.length;
    // If premium active, reveal names. Otherwise teaser only.
    const now = Date.now();
    const premiumUntil = users[me].premiumUntil || 0;
    const isPremium = TEST_MODE || (premiumUntil && premiumUntil > now);

    if(isPremium){
      return res.json({
        ok:true,
        count,
        unlocked:true,
        viewers: users[me].viewsLog.map(v => ({ from: v.from, ts: v.ts }))
      });
    }
    return res.json({ ok:true, count, unlocked:false, viewers: [] });
  }catch(e){
    return res.status(401).json({ ok:false, error:'Unauthorized' });
  }
});



// Set gender (bubble color) - one-time or anytime
app.post("/api/profile/gender", requireAuth, (req, res) => {
  const { gender } = req.body || {};
  const g = String(gender || "other").toLowerCase();
  if (!["male","female","other"].includes(g)) return res.status(400).json({ error: "bad_gender" });
  const users = readUsers();
  const me = users[req.user];
  if (!me) return res.status(404).json({ error: 'no_user' });
  me.gender = g;
  writeUsers(users);
  res.json({ ok: true, gender: g });
});

// Save profile photo (base64 data URL). Keep it small (256x256 JPEG from client).
app.post("/api/profile/photo", requireAuth, (req, res) => {
  const { photo } = req.body || {};
  const p = (photo == null) ? '' : String(photo);
  // Allow clearing
  if(p === ''){
    const users = readUsers();
    const me = users[req.user];
    if (!me) return res.status(404).json({ error: 'no_user' });
    delete me.photo;
    writeUsers(users);
    return res.json({ ok:true, photo:'' });
  }
  // Basic validation
  if(!p.startsWith('data:image/')) return res.status(400).json({ error: 'bad_photo' });
  // Hard limit to avoid exploding users.json
  if(p.length > 250000) return res.status(413).json({ error: 'photo_too_large' });
  const users = readUsers();
  const me = users[req.user];
  if (!me) return res.status(404).json({ error: 'no_user' });
  me.photo = p;
  writeUsers(users);
  return res.json({ ok:true, photo: p });
});


// Public config for clients (test phase)
app.get("/api/config", (req, res) => {
  try{
    const users = readUsers();
    let goldUserId = null;
    const target = "traka dev";
    // users can be array or object map depending on build
    const list = Array.isArray(users) ? users : Object.values(users || {});
    const gold = list.find(u => normName(u && u.name) === target);
    if (gold && gold.id) goldUserId = gold.id;
    res.json({ ok:true, goldUserId });
  }catch(e){
    res.json({ ok:false, goldUserId:null });
  }
});
