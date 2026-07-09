const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');
const https = require('https');
const httpModule = require('http');

const app = express();
// Render стоїть за балансувальником: реальний IP клієнта — у X-Forwarded-For.
// Без цього rate-limit бачив би один IP проксі для всіх і різав би всіх гуртом.
app.set('trust proxy', 1);
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
app.use(express.json({ limit: '60mb' }));

// ── Простий in-memory rate-limit (без зовнішніх залежностей) ──────────────
// Один інстанс → лічильники в пам'яті достатньо. Коли буде кілька інстансів —
// винести в Redis (як і sendToUser). Ключ — IP клієнта.
function makeRateLimiter({ windowMs, max }) {
  const hits = new Map(); // ip -> { count, resetAt }
  // періодичне прибирання застарілих записів, щоб мапа не росла
  setInterval(() => {
    const now = Date.now();
    for (const [ip, rec] of hits) if (now > rec.resetAt) hits.delete(ip);
  }, windowMs).unref?.();
  return (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const now = Date.now();
    let rec = hits.get(ip);
    if (!rec || now > rec.resetAt) { rec = { count: 0, resetAt: now + windowMs }; hits.set(ip, rec); }
    rec.count++;
    if (rec.count > max) {
      const retry = Math.ceil((rec.resetAt - now) / 1000);
      res.set('Retry-After', String(retry));
      return res.status(429).json({ ok: false, error: 'Забагато запитів, спробуйте пізніше' });
    }
    next();
  };
}

// Загальний помірний ліміт на всі HTTP-запити
app.use(makeRateLimiter({ windowMs: 60 * 1000, max: 120 }));
// Суворіший ліміт на чутливе (вхід/реєстрація/скидання) — проти brute-force
const authLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
app.use(['/login', '/register', '/request-reset', '/reset-password', '/verify-email'], authLimiter);

// ── Моніторинг ────────────────────────────────────────────────────────────
// Публічний liveness — БЕЗ чутливих даних (його бачить будь-хто): лише «живий».
app.get('/health', (req, res) => res.json({ ok: true }));
// Приватна статистика — лише за секретним токеном з env (STATS_KEY).
app.get('/stats', (req, res) => {
  const key = process.env.STATS_KEY;
  if (!key || req.query.key !== key) return res.status(403).json({ ok: false });
  const mem = process.memoryUsage();
  res.json({
    ok: true,
    online: onlineUsers.size,
    fcmTokens: fcmTokens.size,
    pendingCallOffers: pendingCallOffers.size,
    uptimeSec: Math.floor(process.uptime()),
    memoryMB: Math.round(mem.rss / 1024 / 1024),
    ts: Date.now(),
  });
});


const BCRYPT_ROUNDS = 8;
const REQUIRE_EMAIL_VERIFICATION = false;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const mailer = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com', port: 587,
  auth: { user: process.env.BREVO_LOGIN, pass: process.env.BREVO_PASSWORD },
});
const onlineUsers = new Map();
const resetCodes = new Map();
const pendingRegistrations = new Map();
const verifiedPhones = new Map(); // нормалізований номер -> expires (підтверджені, для реєстрації)
const fcmTokens = new Map();
// nick -> deviceId: щоб не дзвонити/не слати пуш на ТОЙ САМИЙ фізичний
// пристрій (кілька акаунтів на одному телефоні мають спільний FCM-токен,
// інакше дзвінок «сам собі»).
const nickDevices = new Map();
const pendingCallOffers = new Map();
const linkPreviewCache = new Map();

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('Firebase Admin ініціалізовано');
  } catch (e) { console.error('Помилка ініціалізації Firebase Admin:', e.message); }
}

setInterval(() => {
  const now = Date.now();
  for (const [id, data] of pendingCallOffers) if (now > data.expires) pendingCallOffers.delete(id);
  for (const [url, data] of linkPreviewCache) if (now > data.expires) linkPreviewCache.delete(url);
  for (const [p, exp] of verifiedPhones) if (now > exp) verifiedPhones.delete(p);
}, 120000);

// ── Link Preview ──────────────────────────────
app.get('/link-preview', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.json({ ok: false, error: 'url обов\'язковий' });
  const cached = linkPreviewCache.get(url);
  if (cached) return res.json({ ok: true, ...cached.data });
  try {
    const ytMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})/);
    if (ytMatch) {
      const videoId = ytMatch[1];
      let title = null;
      try { const oembed = await fetchJson(`https://www.youtube.com/oembed?url=${encodeURIComponent(url)}&format=json`); title = oembed.title || null; } catch (_) {}
      const preview = { title, description: null, image: `https://img.youtube.com/vi/${videoId}/hqdefault.jpg`, siteName: 'YouTube', domain: 'youtube.com', url };
      linkPreviewCache.set(url, { data: preview, expires: Date.now() + 3600000 });
      return res.json({ ok: true, ...preview });
    }
    const html = await fetchUrl(url);
    const preview = parseOpenGraph(html, url);
    linkPreviewCache.set(url, { data: preview, expires: Date.now() + 3600000 });
    res.json({ ok: true, ...preview });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : httpModule;
    const req = client.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 5000 }, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : httpModule;
    const req = client.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; EIONBot/1.0)', 'Accept': 'text/html' }, timeout: 8000 }, (resp) => {
      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) return fetchUrl(resp.headers.location).then(resolve).catch(reject);
      let data = ''; resp.setEncoding('utf8');
      resp.on('data', chunk => { data += chunk; if (data.length > 100000) { resp.destroy(); resolve(data); } });
      resp.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function parseOpenGraph(html, url) {
  const getMeta = (property) => {
    const match = html.match(new RegExp(`<meta[^>]+(?:property|name)=["']${property}["'][^>]+content=["']([^"']+)["']`, 'i'))
      || html.match(new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']${property}["']`, 'i'));
    return match ? match[1].trim() : null;
  };
  const title = getMeta('og:title') || getMeta('twitter:title') || (html.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1]?.trim() || null;
  const description = getMeta('og:description') || getMeta('twitter:description') || getMeta('description') || null;
  let image = getMeta('og:image') || getMeta('twitter:image') || null;
  if (image && !image.startsWith('http')) { try { const base = new URL(url); image = new URL(image, base.origin).toString(); } catch (_) { image = null; } }
  const siteName = getMeta('og:site_name') || null;
  let domain = url; try { domain = new URL(url).hostname.replace('www.', ''); } catch (_) {}
  return { title, description, image, siteName, domain, url };
}

async function sendCallPush(toNick, fromNick, hasVideo, offer) {
  const token = fcmTokens.get(toNick); if (!token) return;
  const callId = `${fromNick}_${toNick}_${Date.now()}`;
  pendingCallOffers.set(callId, { fromNick, toNick, offer: typeof offer === 'string' ? offer : JSON.stringify(offer), hasVideo, expires: Date.now() + 60000 });
  try {
    await admin.messaging().send({ token, data: { type: 'call_offer', from_nick: fromNick, has_video: hasVideo ? 'true' : 'false', call_id: callId }, android: { priority: 'high', ttl: 30000 } });
    console.log(`FCM push відправлено до ${toNick}, callId=${callId}`);
  } catch (e) {
    console.error(`Помилка FCM push до ${toNick}:`, e.message);
    pendingCallOffers.delete(callId);
    if (e.code === 'messaging/registration-token-not-registered') fcmTokens.delete(toNick);
  }
}

async function sendFcmPush(toNick, data) {
  const token = fcmTokens.get(toNick); if (!token) return;
  // Не шлемо пуш на ВЛАСНИЙ пристрій: якщо адресат — інший акаунт на тому
  // самому телефоні (спільний FCM-токен), сповіщення набридали б власнику.
  // Саме повідомлення вже збережене й буде видиме при відкритті того акаунта.
  const fromNick = data && data.from_nick;
  if (fromNick) {
    const fromDev = nickDevices.get(fromNick);
    const toDev = nickDevices.get(toNick);
    if (fromDev && toDev && fromDev === toDev) {
      console.log(`push skipped: ${fromNick}->${toNick} same device ${fromDev}`);
      return;
    }
  }
  try { await admin.messaging().send({ token, data, android: { priority: 'high', ttl: 10000 } }); }
  catch (e) { console.error(`FCM push error до ${toNick}:`, e.message); if (e.code === 'messaging/registration-token-not-registered') fcmTokens.delete(toNick); }
}

// ── Єдина точка доставки повідомлення одному користувачу ──────────────────
// Уся адресна доставка йде через цю функцію. Коли знадобиться кілька
// інстансів — саме тут (і лише тут) вмикається Redis pub/sub: якщо сокет не на
// цьому інстансі, публікуємо в канал, а інстанс-власник доставить. Решта коду
// не зміниться. Повертає true, якщо доставлено локально.
function sendToUser(nick, payload) {
  const u = onlineUsers.get(nick);
  if (!u || !u.ws || u.ws.readyState !== 1 /* OPEN */) return false;
  try {
    u.ws.send(typeof payload === 'string' ? payload : JSON.stringify(payload));
    return true;
  } catch (_) {
    return false;
  }
}

async function notifyChannelSubscribers(channelId, payload, excludeNick = null) {
  const { data: members } = await supabase.from('channel_members').select('nick').eq('channel_id', channelId);
  const msg = JSON.stringify(payload);
  for (const m of members || []) {
    if (m.nick === excludeNick) continue;
    const t = onlineUsers.get(m.nick);
    // ws.send кидає на мертвому/напіввідкритому сокеті (Render flapping) —
    // не дати одному битому сокету зірвати решту розсилки й сам HTTP-запит.
    if (t) { try { t.ws.send(msg); } catch (_) {} }
  }
}

app.get('/call-offer', (req, res) => {
  const { callId } = req.query; if (!callId) return res.json({ ok: false, error: 'callId обов\'язковий' });
  const data = pendingCallOffers.get(callId); if (!data) return res.json({ ok: false, error: 'Offer не знайдено або застарів' });
  res.json({ ok: true, fromNick: data.fromNick, offer: data.offer, hasVideo: data.hasVideo });
});

app.post('/decline-call', (req, res) => {
  const { fromNick, toNick } = req.body; if (!fromNick || !toNick) return res.json({ ok: false, error: 'Невірні параметри' });
  sendToUser(toNick, { type: 'call_reject', from: fromNick });
  res.json({ ok: true });
});

async function sendEmail(to, subject, text) { await mailer.sendMail({ from: 'EI° <eichatserver@gmail.com>', to, subject, text }); }

// ── OTP: підключюваний відправник SMS ──────────
function httpPostJson(targetUrl, headers, bodyObj) {
  return new Promise((resolve) => {
    try {
      const u = new URL(targetUrl);
      const mod = u.protocol === 'http:' ? httpModule : https;
      const payload = JSON.stringify(bodyObj);
      const r = mod.request(u, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), ...headers },
      }, (resp) => {
        let data = '';
        resp.on('data', (c) => data += c);
        resp.on('end', () => resolve({ status: resp.statusCode, body: data }));
      });
      r.on('error', (e) => resolve({ status: 0, error: e.message }));
      r.write(payload);
      r.end();
    } catch (e) { resolve({ status: 0, error: e.message }); }
  });
}

// Відправляє OTP: спершу Telegram Gateway (дешево, масштабовано), далі SMS-шлюз (резерв).
// Без жодного каналу — dev-режим (лог у консоль).
async function sendOtp(phoneE164, code, text) {
  // 1. Telegram Gateway — основний канал (доставляє НАШ код у Telegram)
  if (process.env.TG_GATEWAY_TOKEN) {
    const tg = await httpPostJson(
      'https://gatewayapi.telegram.org/sendVerificationMessage',
      { 'Authorization': `Bearer ${process.env.TG_GATEWAY_TOKEN}` },
      { phone_number: phoneE164, code: code, ttl: 300 },
    );
    try {
      const body = JSON.parse(tg.body || '{}');
      if (tg.status >= 200 && tg.status < 300 && body.ok === true) return { ok: true, via: 'telegram' };
      console.error('[OTP] Telegram не доставив:', body.error || tg.status, '— пробую SMS-резерв');
    } catch (_) {
      console.error('[OTP] Telegram HTTP', tg.status, '— пробую SMS-резерв');
    }
    // не вдалось — падаємо у SMS-резерв нижче
  }

  // 2. SMS-шлюз (SMSGate) — резерв
  const url = process.env.SMS_GATEWAY_URL;
  if (!url) { console.log(`[OTP dev] -> ${phoneE164}: ${text}`); return { ok: true, dev: true }; }
  const headers = {};
  if (process.env.SMS_GATEWAY_TOKEN) headers['Authorization'] = `Bearer ${process.env.SMS_GATEWAY_TOKEN}`;
  else if (process.env.SMS_GATEWAY_BASIC) headers['Authorization'] = `Basic ${Buffer.from(process.env.SMS_GATEWAY_BASIC).toString('base64')}`;
  // Тіло під актуальний API SMSGate (sms-gate.app): { textMessage:{text}, phoneNumbers:[...] }
  const r = await httpPostJson(url, headers, { textMessage: { text: text }, phoneNumbers: [phoneE164] });
  if (r.status >= 200 && r.status < 300) return { ok: true, via: 'sms' };
  console.error('[OTP] SMS-шлюз помилка', r.status, r.error || r.body);
  return { ok: false };
}

async function isModOrCreator(groupId, nick) {
  const { data } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', nick).single();
  return data && (data.role === 'creator' || data.role === 'moderator');
}

// Чи blockerNick заблокував otherNick (тобто otherNick не повинен мати
// можливості писати/дзвонити blockerNick).
async function isBlockedBy(blockerNick, otherNick) {
  if (!blockerNick || !otherNick) return false;
  const { data } = await supabase.from('blocked_contacts').select('id')
    .eq('blocker_nick', blockerNick).eq('blocked_nick', otherNick).maybeSingle();
  return !!data;
}

async function notifyMembers(groupId, payload, excludeNick = null) {
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  const msg = JSON.stringify(payload);
  for (const m of members || []) { if (m.nick === excludeNick) continue; const t = onlineUsers.get(m.nick); if (t) { try { t.ws.send(msg); } catch (_) {} } }
}

async function sendGroupInvite(groupId, groupName, inviterNick, targetNick) {
  const target = onlineUsers.get(targetNick);
  const payload = { type: 'group_invite', groupId, groupName, inviterNick };
  if (target) target.ws.send(JSON.stringify(payload));
  else await supabase.from('pending_group_invites').upsert({ group_id: groupId, target_nick: targetNick, inviter_nick: inviterNick });
}

// ── Реєстрація / Авторизація ──────────────────
app.post('/register', async (req, res) => {
  const { nick, password, email, color, phone, phoneNormalized } = req.body;
  if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)' });
  if (!password || password.length < 4) return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 4 символи)' });
  if (email && !email.includes('@')) return res.json({ ok: false, error: 'Невірний email' });
  const { data: existing } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
  if (existing) return res.json({ ok: false, error: 'Нік вже зайнятий' });
  if (email) {
    const { data: emailExists } = await supabase.from('users').select('nick').eq('email', email).single();
    if (emailExists) return res.json({ ok: false, error: 'Цей email вже використовується' });
  }
  // Перевіряємо унікальність телефону
  if (phoneNormalized) {
    const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
    if (phoneExists) return res.json({ ok: false, error: 'Цей номер телефону вже зареєстрований в EION' });
  }
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const userData = {
    nick, nick_lower: nick.toLowerCase(), password_hash: passwordHash,
    email, color: color || 4280391411, coins: 50,
    ...(phone ? { phone } : {}),
    ...(phoneNormalized ? { phone_normalized: phoneNormalized, phone_verified: verifiedPhones.has(phoneNormalized) } : {}),
  };
  if (REQUIRE_EMAIL_VERIFICATION) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    pendingRegistrations.set(email, { ...userData, code, expires: Date.now() + 15 * 60 * 1000 });
    try { await sendEmail(email, 'EION — Підтвердження реєстрації', `Ваш код підтвердження: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true, needVerification: true }); }
    catch (e) { res.json({ ok: false, error: 'Помилка відправки email: ' + e.message }); }
  } else {
    const { error } = await supabase.from('users').insert(userData);
    if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
    res.json({ ok: true, needVerification: false });
  }
});

app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email); if (!pending) return res.json({ ok: false, error: 'Реєстрацію не знайдено' });
  if (Date.now() > pending.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (pending.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  const { error } = await supabase.from('users').insert({ nick: pending.nick, nick_lower: pending.nick.toLowerCase(), password_hash: pending.passwordHash, email, color: pending.color, coins: 50 });
  if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
  pendingRegistrations.delete(email); res.json({ ok: true });
});

app.post('/login', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', user.nick).single();
  if (ban) return res.json({ ok: false, error: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}` });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  res.json({ ok: true, nick: user.nick, color: user.color, coins: user.coins || 0, avatar_url: user.avatar_url || null, premium_expires_at: user.premium_expires_at || null, premium_plan: user.premium_plan || null, nick_color: user.nick_color || null });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
  if (!user) return res.json({ ok: false, error: 'Email не знайдено' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  resetCodes.set(email, { code, nick: user.nick, expires: Date.now() + 15 * 60 * 1000 });
  try { await sendEmail(email, 'EION — Відновлення пароля', `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true }); }
  catch (e) { res.json({ ok: false, error: 'Помилка відправки email' }); }
});

app.post('/reset', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const reset = resetCodes.get(email); if (!reset) return res.json({ ok: false, error: 'Код не знайдено' });
  if (Date.now() > reset.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (reset.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Пароль занадто короткий' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', reset.nick.toLowerCase());
  resetCodes.delete(email); res.json({ ok: true });
});

app.post('/update-nick', async (req, res) => {
  const { nick, password, newNick } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newNick || newNick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий' });
  const { data: exists } = await supabase.from('users').select('nick').eq('nick_lower', newNick.toLowerCase()).single();
  if (exists) return res.json({ ok: false, error: 'Нік вже зайнятий' });
  const oldNick = user.nick;
  await supabase.from('users').update({ nick: newNick, nick_lower: newNick.toLowerCase() }).eq('nick_lower', nick.toLowerCase());
  await Promise.all([
    supabase.from('messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('messages').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('group_members').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('group_messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('groups').update({ creator_nick: newNick }).eq('creator_nick', oldNick),
    supabase.from('channel_members').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('channel_messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('channel_comments').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('channel_reactions').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('channel_comment_reactions').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('channels').update({ owner_nick: newNick }).eq('owner_nick', oldNick),
    supabase.from('deleted_messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('deleted_messages').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('pending_reactions').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('pending_reactions').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('call_logs').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('call_logs').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('pending_group_invites').update({ target_nick: newNick }).eq('target_nick', oldNick),
    supabase.from('pending_group_invites').update({ inviter_nick: newNick }).eq('inviter_nick', oldNick),
    supabase.from('pending_channel_invites').update({ target_nick: newNick }).eq('target_nick', oldNick),
    supabase.from('pending_channel_invites').update({ inviter_nick: newNick }).eq('inviter_nick', oldNick),
  ]);
  const userWs = onlineUsers.get(oldNick);
  if (userWs) { onlineUsers.delete(oldNick); onlineUsers.set(newNick, userWs); }
  for (const [n, u] of onlineUsers) if (n !== newNick) u.ws.send(JSON.stringify({ type: 'nick_changed', oldNick, newNick }));
  res.json({ ok: true, newNick });
});

app.post('/update-password', async (req, res) => {
  const { nick, password, newPassword } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Новий пароль занадто короткий' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/update-phone', async (req, res) => {
  const { nick, password, phone, phoneNormalized } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!phoneNormalized) return res.json({ ok: false, error: 'Невірний номер' });
  // Унікальність номера (крім самого себе)
  const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
  if (phoneExists && phoneExists.nick !== user.nick) return res.json({ ok: false, error: 'Цей номер телефону вже зареєстрований в EION' });
  const { error } = await supabase.from('users').update({ phone, phone_normalized: phoneNormalized, phone_verified: verifiedPhones.has(phoneNormalized) }).eq('nick_lower', nick.toLowerCase());
  if (error) return res.json({ ok: false, error: 'Помилка оновлення номера' });
  res.json({ ok: true });
});

// ── Підтвердження номера власним OTP (без Firebase) ──
app.post('/phone/request-code', async (req, res) => {
  const { phone, phoneNormalized } = req.body;
  if (!phoneNormalized || !phone) return res.json({ ok: false, error: 'Невірний номер' });
  // rate-limit: не частіше ніж раз на 60 с
  const { data: existing } = await supabase.from('phone_codes').select('last_sent_at').eq('phone', phoneNormalized).single();
  if (existing && existing.last_sent_at) {
    const elapsed = Date.now() - new Date(existing.last_sent_at).getTime();
    if (elapsed < 60000) return res.json({ ok: false, error: `Зачекайте ${Math.ceil((60000 - elapsed) / 1000)} с` });
  }
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const { error } = await supabase.from('phone_codes').upsert({
    phone: phoneNormalized, code,
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    attempts: 0, last_sent_at: new Date().toISOString(),
  });
  if (error) { console.error('[OTP] phone_codes upsert:', error); return res.json({ ok: false, error: 'Помилка збереження коду' }); }
  const sent = await sendOtp(phone, code, `EION код підтвердження: ${code}`);
  if (!sent.ok) return res.json({ ok: false, error: 'Не вдалося надіслати код' });
  // У dev-режимі (без шлюзу) можна повернути код для тесту, якщо явно дозволено env
  const devCode = (sent.dev && process.env.OTP_DEV_RETURN_CODE === 'true') ? code : undefined;
  res.json({ ok: true, ...(devCode ? { devCode } : {}) });
});

app.post('/phone/verify-code', async (req, res) => {
  const { phone, phoneNormalized, code, nick } = req.body;
  if (!phoneNormalized || !code) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: row } = await supabase.from('phone_codes').select('*').eq('phone', phoneNormalized).single();
  if (!row) return res.json({ ok: false, error: 'Код не знайдено. Запросіть новий' });
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await supabase.from('phone_codes').delete().eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Код протерміновано. Запросіть новий' });
  }
  if (row.attempts >= 5) {
    await supabase.from('phone_codes').delete().eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Забагато спроб. Запросіть новий код' });
  }
  if (row.code !== String(code)) {
    await supabase.from('phone_codes').update({ attempts: row.attempts + 1 }).eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Невірний код' });
  }
  await supabase.from('phone_codes').delete().eq('phone', phoneNormalized); // успіх — код видаляємо
  // Наявний користувач (зміна номера / discovery) — ставимо номер + phone_verified
  if (nick) {
    const { data: user } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
    if (user) {
      const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
      if (phoneExists && phoneExists.nick !== user.nick) return res.json({ ok: false, error: 'Цей номер вже зареєстрований в EION' });
      await supabase.from('users').update({ ...(phone ? { phone } : {}), phone_normalized: phoneNormalized, phone_verified: true }).eq('nick_lower', nick.toLowerCase());
    }
  }
  // Для реєстрації (ще без ніка) — запам'ятовуємо підтверджений номер на 15 хв
  verifiedPhones.set(phoneNormalized, Date.now() + 15 * 60 * 1000);
  res.json({ ok: true, verified: true });
});

app.post('/update-email', async (req, res) => {
  const { nick, password, newEmail } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newEmail || !newEmail.includes('@')) return res.json({ ok: false, error: 'Невірний email' });
  const { data: emailExists } = await supabase.from('users').select('nick').eq('email', newEmail).single();
  if (emailExists) return res.json({ ok: false, error: 'Email вже використовується' });
  await supabase.from('users').update({ email: newEmail }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

// Видача ICE-серверів клієнту. Креди TURN живуть у env сервера, а не в APK —
// інакше їх витягують із застосунку й крадуть relay-трафік. STUN — публічний,
// віддаємо завжди; TURN — лише якщо налаштовані змінні оточення.
app.get('/turn-credentials', (req, res) => {
  const iceServers = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];
  const user = process.env.TURN_USERNAME;
  const cred = process.env.TURN_CREDENTIAL;
  const host = process.env.TURN_HOST || 'global.relay.metered.ca';
  if (user && cred) {
    iceServers.push(
      { urls: `stun:${host}:80` },
      { urls: `turn:${host}:80`, username: user, credential: cred },
      { urls: `turn:${host}:80?transport=tcp`, username: user, credential: cred },
      { urls: `turn:${host}:443`, username: user, credential: cred },
      { urls: `turns:${host}:443?transport=tcp`, username: user, credential: cred },
    );
  }
  res.json({ ok: true, iceServers, ttl: 3600 });
});

app.post('/delete-account', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  await supabase.from('messages').delete().or(`from_nick.eq.${nick},to_nick.eq.${nick}`);
  await supabase.from('users').delete().eq('nick_lower', nick.toLowerCase());
  onlineUsers.delete(nick); fcmTokens.delete(nick);
  res.json({ ok: true });
});

// Приватний presence: повертаємо лише тих із КОНТАКТІВ запитувача, хто онлайн.
// (Раніше GET віддавав список УСІХ онлайн будь-кому — витік ніків + не масштабно.)
app.post('/online-users', (req, res) => {
  const { contacts } = req.body || {};
  if (!Array.isArray(contacts)) return res.json({ ok: true, users: [] });
  const online = contacts.filter(n => typeof n === 'string' && onlineUsers.has(n)).slice(0, 5000);
  res.json({ ok: true, users: online });
});

app.get('/user-info', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  const { data: user } = await supabase.from('users').select('nick, coins, avatar_url, premium_expires_at, premium_plan, nick_color, color').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  res.json({ ok: true, nick: user.nick, coins: user.coins || 0, avatar_url: user.avatar_url || null, premium_expires_at: user.premium_expires_at || null, premium_plan: user.premium_plan || null, nick_color: user.nick_color || null, color: user.color || null });
});

app.get('/search-user', async (req, res) => {
  const { nick } = req.query; if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data } = await supabase.from('users').select('nick').ilike('nick_lower', `%${nick.toLowerCase()}%`).limit(10);
  res.json({ ok: true, users: (data || []).map(u => u.nick) });
});

app.post('/users/by-phones', async (req, res) => {
  const { phones } = req.body;
  if (!phones || !Array.isArray(phones) || phones.length === 0) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data } = await supabase.from('users').select('nick, phone_normalized').not('phone_normalized', 'is', null).eq('phone_verified', true);
  const result = {};
  for (const user of data || []) { if (phones.includes(user.phone_normalized)) result[user.phone_normalized] = user.nick; }
  res.json({ ok: true, users: result });
});

app.post('/unregister', (req, res) => { const { nick } = req.body; if (nick) onlineUsers.delete(nick); res.json({ ok: true }); });
app.post('/register-fcm-token', (req, res) => {
  const { nick, token, deviceId } = req.body; if (!nick || !token) return res.json({ ok: false, error: 'Невірні параметри' });
  fcmTokens.set(nick, token);
  if (deviceId) nickDevices.set(nick, deviceId);
  res.json({ ok: true });
});

app.post('/update-nick-color', async (req, res) => {
  const { nick, nickColor } = req.body; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  await supabase.from('users').update({ nick_color: nickColor || null }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'nick_color_changed', nick, nickColor: nickColor || null }));
  res.json({ ok: true });
});

app.post('/update-avatar', async (req, res) => {
  const { nick, avatarUrl } = req.body; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  await supabase.from('users').update({ avatar_url: avatarUrl || null }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'avatar_changed', nick, avatarUrl: avatarUrl || null }));
  res.json({ ok: true });
});

app.post('/update-status', async (req, res) => {
  const { nick, status } = req.body; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  const newStatus = status && status.trim().length > 0 ? status.trim().substring(0, 60) : null;
  await supabase.from('users').update({ status: newStatus }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'user_status', nick, status: newStatus }));
  res.json({ ok: true, status: newStatus });
});

app.post('/transfer-coins', async (req, res) => {
  const { fromNick, toNick, amount } = req.body;
  if (!fromNick || !toNick || !amount || amount < 1) return res.json({ ok: false, error: 'Невірні параметри' });
  if (fromNick === toNick) return res.json({ ok: false, error: 'Не можна переказати собі' });
  const { data: sender } = await supabase.from('users').select('coins').eq('nick', fromNick).single();
  if (!sender) return res.json({ ok: false, error: 'Відправника не знайдено' });
  if ((sender.coins || 0) < amount) return res.json({ ok: false, error: 'Недостатньо монет' });
  const { data: receiver } = await supabase.from('users').select('coins').eq('nick', toNick).single();
  if (!receiver) return res.json({ ok: false, error: 'Отримувача не знайдено' });
  await supabase.from('users').update({ coins: (sender.coins || 0) - amount }).eq('nick', fromNick);
  const newReceiverCoins = (receiver.coins || 0) + amount;
  await supabase.from('users').update({ coins: newReceiverCoins }).eq('nick', toNick);
  const senderWs = onlineUsers.get(fromNick); if (senderWs) senderWs.ws.send(JSON.stringify({ type: 'coins_update', amount: -amount, total: (sender.coins || 0) - amount }));
  const receiverWs = onlineUsers.get(toNick); if (receiverWs) receiverWs.ws.send(JSON.stringify({ type: 'coins_received', fromNick, amount, total: newReceiverCoins }));
  res.json({ ok: true, newBalance: (sender.coins || 0) - amount });
});

app.post('/call-log', async (req, res) => {
  const { fromNick, toNick, hasVideo, startedAt, durationSeconds, status } = req.body;
  if (!fromNick || !toNick || !startedAt || !status) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('call_logs').insert({ from_nick: fromNick, to_nick: toNick, has_video: hasVideo || false, started_at: startedAt, duration_seconds: durationSeconds || null, status });
  // Realtime: повідомляємо обидві онлайн-сторони перезавантажити логи (each reloads counterpart).
  // Кожен send у try/catch: мертвий сокет першого не має зривати пуш другому.
  const fromWs = onlineUsers.get(fromNick);
  const toWs = onlineUsers.get(toNick);
  console.log(`call-log: ${fromNick}->${toNick} ${status}; push from=${!!fromWs} to=${!!toWs}`);
  try { if (fromWs) fromWs.ws.send(JSON.stringify({ type: 'call_log_new', otherNick: toNick })); } catch (e) { console.log('call-log push from failed:', e.message); }
  try { if (toWs) toWs.ws.send(JSON.stringify({ type: 'call_log_new', otherNick: fromNick })); } catch (e) { console.log('call-log push to failed:', e.message); }
  res.json({ ok: true });
});

app.get('/call-logs', async (req, res) => {
  const { nick, otherNick } = req.query; if (!nick || !otherNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data } = await supabase.from('call_logs').select('*').or(`and(from_nick.eq.${nick},to_nick.eq.${otherNick}),and(from_nick.eq.${otherNick},to_nick.eq.${nick})`).order('started_at', { ascending: true });
  res.json({ ok: true, logs: data || [] });
});

app.delete('/call-logs', async (req, res) => {
  const { nick, otherNick } = req.query; if (!nick || !otherNick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('call_logs').delete().or(`and(from_nick.eq.${nick},to_nick.eq.${otherNick}),and(from_nick.eq.${otherNick},to_nick.eq.${nick})`);
  res.json({ ok: true });
});

// ── Групи ──────────────────────────────────────
app.post('/group/create', async (req, res) => {
  const { name, creatorNick, members, type } = req.body;
  if (!name || name.trim().length < 1) return res.json({ ok: false, error: 'Назва групи порожня' });
  const groupType = type || 'closed';
  const { data: group, error } = await supabase.from('groups').insert({ name: name.trim(), creator_nick: creatorNick, type: groupType }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення групи' });
  await supabase.from('group_members').insert({ group_id: group.id, nick: creatorNick, role: 'creator' });
  for (const nick of (members || [])) { if (nick === creatorNick) continue; await sendGroupInvite(group.id, group.name, creatorNick, nick); }
  res.json({ ok: true, group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: [creatorNick] });
});

app.post('/group/invite-response', async (req, res) => {
  const { groupId, nick, accepted } = req.body;
  if (accepted) {
    const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', nick).single();
    if (!existing) await supabase.from('group_members').insert({ group_id: groupId, nick, role: 'member' });
    const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
    await notifyMembers(groupId, { type: 'group_member_added', groupId, nick }, nick);
    res.json({ ok: true, group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: (members || []).map(m => m.nick) });
  } else res.json({ ok: true });
  await supabase.from('pending_group_invites').delete().eq('group_id', groupId).eq('target_nick', nick);
});

app.get('/group/list', async (req, res) => {
  const { nick } = req.query;
  const { data: memberships } = await supabase.from('group_members').select('group_id, role').eq('nick', nick);
  if (!memberships || memberships.length === 0) return res.json({ ok: true, groups: [] });
  const ids = memberships.map(m => m.group_id);
  const roleMap = Object.fromEntries(memberships.map(m => [m.group_id, m.role]));
  const { data: groups } = await supabase.from('groups').select('*').in('id', ids);
  const result = [];
  for (const g of groups || []) {
    const { data: members } = await supabase.from('group_members').select('nick, role').eq('group_id', g.id);
    result.push({ ...g, members: (members || []).map(m => m.nick), memberRoles: Object.fromEntries((members || []).map(m => [m.nick, m.role])), myRole: roleMap[g.id] });
  }
  res.json({ ok: true, groups: result });
});

app.get('/group/search', async (req, res) => {
  const { query, nick } = req.query;
  if (!query || query.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data: groups } = await supabase.from('groups').select('*').ilike('name', `%${query}%`).in('type', ['open', 'approval']);
  const result = [];
  for (const g of groups || []) {
    const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', g.id).eq('nick', nick).single();
    if (!membership) { const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', g.id); result.push({ ...g, memberCount: (members || []).length }); }
  }
  res.json({ ok: true, groups: result });
});

app.post('/group/join', async (req, res) => {
  const { groupId, nick } = req.body;
  const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
  if (!group) return res.json({ ok: false, error: 'Групу не знайдено' });
  if (group.type === 'closed') return res.json({ ok: false, error: 'Група закрита' });
  const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', nick).single();
  if (existing) return res.json({ ok: false, error: 'Ви вже в групі' });
  if (group.type === 'open') {
    await supabase.from('group_members').insert({ group_id: groupId, nick, role: 'member' });
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
    await notifyMembers(groupId, { type: 'group_member_added', groupId, nick }, nick);
    const t = onlineUsers.get(nick); if (t) t.ws.send(JSON.stringify({ type: 'group_added', group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: (members || []).map(m => m.nick) }));
    return res.json({ ok: true, joined: true });
  }
  if (group.type === 'approval') {
    await supabase.from('group_join_requests').upsert({ group_id: groupId, nick, status: 'pending' });
    const { data: mods } = await supabase.from('group_members').select('nick').eq('group_id', groupId).in('role', ['creator', 'moderator']);
    for (const mod of mods || []) { const t = onlineUsers.get(mod.nick); if (t) t.ws.send(JSON.stringify({ type: 'group_join_request', groupId, groupName: group.name, nick })); }
    return res.json({ ok: true, joined: false, pending: true });
  }
});

app.post('/group/approve', async (req, res) => {
  const { groupId, requesterNick, targetNick, approve } = req.body;
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('group_join_requests').update({ status: approve ? 'approved' : 'rejected' }).eq('group_id', groupId).eq('nick', targetNick);
  const t = onlineUsers.get(targetNick);
  if (approve) {
    const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
    await supabase.from('group_members').insert({ group_id: groupId, nick: targetNick, role: 'member' });
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
    if (t) t.ws.send(JSON.stringify({ type: 'group_added', group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: (members || []).map(m => m.nick) }));
    await notifyMembers(groupId, { type: 'group_member_added', groupId, nick: targetNick }, targetNick);
  } else { if (t) t.ws.send(JSON.stringify({ type: 'group_request_rejected', groupId })); }
  res.json({ ok: true });
});

app.post('/group/set-type', async (req, res) => {
  const { groupId, requesterNick, groupType } = req.body;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може змінювати тип групи' });
  await supabase.from('groups').update({ type: groupType }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_type_changed', groupId, groupType });
  res.json({ ok: true });
});

app.post('/group/set-moderator', async (req, res) => {
  const { groupId, requesterNick, targetNick, isModerator } = req.body;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може призначати модераторів' });
  const newRole = isModerator ? 'moderator' : 'member';
  await supabase.from('group_members').update({ role: newRole }).eq('group_id', groupId).eq('nick', targetNick);
  await notifyMembers(groupId, { type: 'group_role_changed', groupId, nick: targetNick, role: newRole });
  res.json({ ok: true });
});

app.post('/group/add-member', async (req, res) => {
  const { groupId, requesterNick, newNick } = req.body;
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може запрошувати учасників' });
  const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', newNick).single();
  if (existing) return res.json({ ok: false, error: 'Користувач вже в групі' });
  const { data: group } = await supabase.from('groups').select('name').eq('id', groupId).single();
  await sendGroupInvite(groupId, group.name, requesterNick, newNick);
  res.json({ ok: true, invited: true });
});

app.post('/group/remove-member', async (req, res) => {
  const { groupId, requesterNick, targetNick } = req.body;
  if (requesterNick !== targetNick && !(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може видаляти учасників' });
  await supabase.from('group_members').delete().eq('group_id', groupId).eq('nick', targetNick);
  sendToUser(targetNick, { type: 'group_removed', groupId });
  await notifyMembers(groupId, { type: 'group_member_removed', groupId, nick: targetNick });
  res.json({ ok: true });
});

app.get('/group/join-requests', async (req, res) => {
  const { groupId, nick } = req.query;
  if (!(await isModOrCreator(groupId, nick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data } = await supabase.from('group_join_requests').select('*').eq('group_id', groupId).eq('status', 'pending');
  res.json({ ok: true, requests: data || [] });
});

app.post('/group/delete', async (req, res) => {
  const { groupId, requesterNick } = req.body;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може видалити групу' });
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  await supabase.from('group_messages').delete().eq('group_id', groupId);
  await supabase.from('group_members').delete().eq('group_id', groupId);
  await supabase.from('group_join_requests').delete().eq('group_id', groupId);
  await supabase.from('pending_group_invites').delete().eq('group_id', groupId);
  await supabase.from('groups').delete().eq('id', groupId);
  for (const m of members || []) { const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify({ type: 'group_deleted', groupId })); }
  res.json({ ok: true });
});

// ═══ Блокування контактів (direct: повідомлення + дзвінки) ═══
app.post('/contact/block', async (req, res) => {
  const { nick, targetNick } = req.body;
  if (!nick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  if (nick === targetNick) return res.json({ ok: false, error: 'Не можна заблокувати самого себе' });
  await supabase.from('blocked_contacts').upsert(
    { blocker_nick: nick, blocked_nick: targetNick, blocked_at: Date.now() },
    { onConflict: 'blocker_nick,blocked_nick' });
  res.json({ ok: true });
});

app.post('/contact/unblock', async (req, res) => {
  const { nick, targetNick } = req.body;
  if (!nick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('blocked_contacts').delete().eq('blocker_nick', nick).eq('blocked_nick', targetNick);
  res.json({ ok: true });
});

app.get('/contact/blocked-list', async (req, res) => {
  const { nick } = req.query;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data } = await supabase.from('blocked_contacts').select('blocked_nick, blocked_at').eq('blocker_nick', nick);
  res.json({ ok: true, blocked: (data || []).map(r => r.blocked_nick) });
});

app.get('/direct/reactions', async (req, res) => {
  const { me, other } = req.query;
  if (!me || !other) return res.json({ ok: false, error: 'Невірні параметри' });
  const pairKey = [me, other].sort().join('|');
  const { data } = await supabase.from('direct_message_reactions').select('msg_id, emoji, from_nick').eq('pair_key', pairKey);
  const byMsg = {};
  for (const r of data || []) {
    if (!byMsg[r.msg_id]) byMsg[r.msg_id] = {};
    if (!byMsg[r.msg_id][r.emoji]) byMsg[r.msg_id][r.emoji] = [];
    byMsg[r.msg_id][r.emoji].push(r.from_nick);
  }
  res.json({ ok: true, reactions: byMsg });
});

app.get('/group/messages', async (req, res) => {
  const { groupId, nick, before } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 100, 200);
  let clearedAt = 0;
  if (nick) {
    const { data: clRows } = await supabase.from('group_history_cleared').select('cleared_at').eq('nick', nick).eq('group_id', groupId).limit(1);
    if (clRows && clRows[0] && clRows[0].cleared_at) clearedAt = Number(clRows[0].cleared_at);
  }
  // Беремо ОСТАННІ limit повідомлень (descending + limit), потім розвертаємо в
  // ascending — порядок на виході той самий, що був, тож клієнт сумісний.
  // before (timestamp) — для підвантаження старіших (Б2, прокрутка вгору).
  let q = supabase.from('group_messages').select('*').eq('group_id', groupId);
  if (before) q = q.lt('timestamp', Number(before));
  if (clearedAt) q = q.gt('timestamp', clearedAt);
  q = q.order('timestamp', { ascending: false }).limit(limit + 1);
  const { data: rawDesc } = await q;
  const rows = rawDesc || [];
  const hasMore = rows.length > limit;        // є ще старіші
  const page = hasMore ? rows.slice(0, limit) : rows;
  const visible = page.slice().reverse();     // назад в ascending
  console.log(`[group/messages] groupId=${groupId} before=${before || '-'} limit=${limit} → returned=${visible.length} hasMore=${hasMore}`);
  const msgIds = visible.map(m => m.msg_id).filter(Boolean);
  const reactionsByMsg = {};
  if (msgIds.length) {
    const { data: reacts } = await supabase.from('group_message_reactions').select('msg_id, emoji, nick').eq('group_id', groupId).in('msg_id', msgIds);
    for (const r of reacts || []) {
      if (!reactionsByMsg[r.msg_id]) reactionsByMsg[r.msg_id] = {};
      if (!reactionsByMsg[r.msg_id][r.emoji]) reactionsByMsg[r.msg_id][r.emoji] = [];
      reactionsByMsg[r.msg_id][r.emoji].push(r.nick);
    }
  }
  res.json({ ok: true, hasMore, oldest: visible[0]?.timestamp ?? null, messages: visible.map(m => ({ ...m, type: m.type || 'text', file_name: m.file_name || null, file_data: m.file_data || null, waveform: m.waveform || null, duration_sec: m.duration_sec || null, replyToMsgId: m.reply_to_msg_id || null, replyToText: m.reply_to_text || null, replyToFrom: m.reply_to_from || null, replyToImage: m.reply_to_image || null, reactions: reactionsByMsg[m.msg_id] || {} })) });
});

// Очистити історію групи лише для себе (персистентний маркер часу)
app.post('/group/clear-history', async (req, res) => {
  const { groupId, nick } = req.body;
  if (!groupId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('group_history_cleared').upsert({ nick, group_id: groupId, cleared_at: Date.now() }, { onConflict: 'nick,group_id' });
  res.json({ ok: true });
});

app.get('/check-phone', async (req, res) => {
  const { phoneNormalized } = req.query;
  if (!phoneNormalized) return res.json({ exists: false });
  const { data } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
  res.json({ exists: !!data });
});

// ── Магазин Premium ──────────────────────────
app.post('/shop/buy-premium', async (req, res) => {
  const { nick, plan } = req.body;
  if (!nick || !plan) return res.json({ ok: false, error: 'Невірні параметри' });
  const PRICES = { monthly: 500, yearly: 4200 };
  const price = PRICES[plan];
  if (!price) return res.json({ ok: false, error: 'Невідомий план' });
  const { data: user } = await supabase.from('users').select('coins, premium_expires_at').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if ((user.coins || 0) < price) return res.json({ ok: false, error: `Недостатньо EION (потрібно ${price})` });
  const now = new Date();
  let expiresAt = (user.premium_expires_at && new Date(user.premium_expires_at) > now)
    ? new Date(user.premium_expires_at) : new Date(now);
  if (plan === 'monthly') expiresAt.setMonth(expiresAt.getMonth() + 1);
  else expiresAt.setFullYear(expiresAt.getFullYear() + 1);
  const newBalance = (user.coins || 0) - price;
  await supabase.from('users').update({ coins: newBalance, premium_expires_at: expiresAt.toISOString(), premium_plan: plan }).eq('nick', nick);
  const ws = onlineUsers.get(nick);
  if (ws) ws.ws.send(JSON.stringify({ type: 'coins_update', amount: -price, total: newBalance }));
  res.json({ ok: true, newBalance, expiresAt: expiresAt.toISOString(), plan });
});

// ── Оновлення групи (аватар, назва) ──────────
app.post('/group/update', async (req, res) => {
  const { groupId, requesterNick, name, avatarUrl } = req.body;
  if (!groupId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || !['creator', 'moderator'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const updates = {};
  if (name !== undefined && name.trim().length > 0) updates.name = name.trim();
  if (avatarUrl !== undefined) updates.avatar_url = avatarUrl;
  if (Object.keys(updates).length === 0) return res.json({ ok: false, error: 'Нічого оновлювати' });
  await supabase.from('groups').update(updates).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_updated', groupId, ...updates });
  res.json({ ok: true });
});

app.get('/ping', (req, res) => res.json({ ok: true }));

// ── Закріплені повідомлення груп ──────────────────────────────
// Закріпити (creator/moderator). Клієнт шле прев'ю (text) + автора (from) + msgId.
app.post('/group/pin', async (req, res) => {
  const { groupId, requesterNick, msgId, text, from } = req.body;
  if (!groupId || !requesterNick || !msgId) return res.json({ ok: false, error: 'Невірні параметри' });
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  const pinnedAt = Date.now();
  await supabase.from('groups').update({ pinned_msg_id: msgId, pinned_text: text || null, pinned_from: from || null, pinned_at: pinnedAt }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_pinned', groupId: Number(groupId), msgId, text: text || null, from: from || null, pinnedAt });
  res.json({ ok: true });
});

// Відкріпити (creator/moderator)
app.post('/group/unpin', async (req, res) => {
  const { groupId, requesterNick } = req.body;
  if (!groupId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('groups').update({ pinned_msg_id: null, pinned_text: null, pinned_from: null, pinned_at: null }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_unpinned', groupId: Number(groupId) });
  res.json({ ok: true });
});


// ── Закріплені пости каналів (owner/admin) ──────────────────────────────
app.post('/channel/pin', async (req, res) => {
  const { channelId, requesterNick, postId, text, from } = req.body;
  if (!channelId || !requesterNick || !postId) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const pinnedAt = Date.now();
  await supabase.from('channels').update({ pinned_post_id: String(postId), pinned_text: text || null, pinned_from: from || null, pinned_at: pinnedAt }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_pinned', channelId: Number(channelId), postId: String(postId), text: text || null, from: from || null, pinnedAt }, null);
  res.json({ ok: true });
});

app.post('/channel/unpin', async (req, res) => {
  const { channelId, requesterNick } = req.body;
  if (!channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channels').update({ pinned_post_id: null, pinned_text: null, pinned_from: null, pinned_at: null }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_unpinned', channelId: Number(channelId) }, null);
  res.json({ ok: true });
});


// ── Канали ──────────────────────────────────────
app.post('/channel/create', async (req, res) => {
  const { ownerNick, name, description, type, subscribers } = req.body;
  if (!ownerNick || !name || name.trim().length < 1) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: channel, error } = await supabase.from('channels').insert({
    name: name.trim(), description: description || null,
    owner_nick: ownerNick, type: type || 'public',
    created_at: Date.now(), last_post_at: null, last_post_text: null,
  }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення каналу' });
  await supabase.from('channel_members').insert({ channel_id: channel.id, nick: ownerNick, role: 'owner' });
  for (const nick of (subscribers || [])) {
    if (nick === ownerNick) continue;
    const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channel.id).eq('nick', nick).single();
    if (!blocked) await supabase.from('channel_members').insert({ channel_id: channel.id, nick, role: 'subscriber' }).catch(() => {});
  }
  res.json({ ok: true, channel: { ...channel, myRole: 'owner', subscriberCount: 1 + (subscribers || []).length, lastPostAt: null, lastPostText: null } });
});

app.get('/channel/list', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'nick обов\'язковий' });
  const { data: memberships } = await supabase.from('channel_members').select('channel_id, role').eq('nick', nick);
  if (!memberships || memberships.length === 0) return res.json({ ok: true, channels: [] });
  const ids = memberships.map(m => m.channel_id);
  const roleMap = Object.fromEntries(memberships.map(m => [m.channel_id, m.role]));
  const { data: channels } = await supabase.from('channels').select('*').in('id', ids);
  const result = [];
  for (const c of channels || []) {
    const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', c.id);
    const { data: lastPosts } = await supabase.from('channel_messages').select('content, image_url, file_name, timestamp').eq('channel_id', c.id).order('timestamp', { ascending: false }).limit(1);
    const lastPost = lastPosts && lastPosts.length > 0 ? lastPosts[0] : null;
    const lastPostAt = lastPost ? lastPost.timestamp : (c.last_post_at || c.created_at || null);
    const lastPostText = lastPost ? (lastPost.content ? lastPost.content.substring(0, 50) : (lastPost.image_url ? '🖼 Зображення' : (lastPost.file_name ? '📎 ' + lastPost.file_name.substring(0, 30) : ''))) : null;
    result.push({ ...c, myRole: roleMap[c.id], subscriberCount: count || 0, lastPostAt, lastPostText });
  }
  result.sort((a, b) => (b.lastPostAt || 0) - (a.lastPostAt || 0));
  res.json({ ok: true, channels: result });
});

app.get('/channel/search', async (req, res) => {
  const { query, nick } = req.query;
  if (!query || query.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  // Шукаємо публічні канали — nick може бути відсутній (незареєстрований пошук)
  const { data: channels } = await supabase.from('channels').select('*').ilike('name', `%${query}%`).eq('type', 'public');
  const result = [];
  for (const c of channels || []) {
    const { data: membership } = nick ? await supabase.from('channel_members').select('role').eq('channel_id', c.id).eq('nick', nick).single() : { data: null };
    const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', c.id);
    result.push({ ...c, myRole: membership?.role || null, subscriberCount: count || 0 });
  }
  res.json({ ok: true, channels: result });
});

app.post('/channel/subscribe', async (req, res) => {
  const { channelId, nick } = req.body; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: channel } = await supabase.from('channels').select('type').eq('id', channelId).single();
  if (!channel) return res.json({ ok: false, error: 'Канал не знайдено' });
  if (channel.type === 'private') return res.json({ ok: false, error: 'Приватний канал — тільки за запрошенням' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (existing) return res.json({ ok: false, error: 'Ви вже підписані' });
  await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  res.json({ ok: true });
});

app.post('/channel/unsubscribe', async (req, res) => {
  const { channelId, nick } = req.body; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!member) return res.json({ ok: false, error: 'Ви не підписані' });
  if (member.role === 'owner') return res.json({ ok: false, error: 'Власник не може відписатись — видаліть канал' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', nick);
  res.json({ ok: true });
});

app.get('/channel/messages', async (req, res) => {
  const { channelId, nick } = req.query; if (!channelId) return res.json({ ok: false, error: 'channelId обов\'язковий' });
  // Гейт платного каналу: доступ мають власник/адмін або активна підписка
  const { data: paidCh } = await supabase.from('channels').select('is_paid, price, sub_days').eq('id', channelId).single();
  if (paidCh && paidCh.is_paid) {
    let hasAccess = false;
    if (nick) {
      const { data: mem } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
      if (mem && ['owner', 'admin'].includes(mem.role)) hasAccess = true;
      if (!hasAccess) {
        const { data: psubArr } = await supabase.from('channel_paid_subs').select('expires_at').eq('channel_id', channelId).eq('nick', nick).order('expires_at', { ascending: false }).limit(1);
        if (psubArr && psubArr[0] && Number(psubArr[0].expires_at) > Date.now()) hasAccess = true;
      }
    }
    if (!hasAccess) return res.json({ ok: true, locked: true, price: paidCh.price || 0, subDays: paidCh.sub_days || 30, messages: [] });
  }
  const { data: posts } = await supabase.from('channel_messages').select('*').eq('channel_id', channelId).order('timestamp', { ascending: true });
  if (!posts || posts.length === 0) return res.json({ ok: true, messages: [] });
  const postIds = posts.map(p => p.id);
  // Завантажуємо всі коментарі і реакції одним запитом
  const [commentsRes, reactionsRes] = await Promise.all([
    supabase.from('channel_comments').select('post_id, from_nick').in('post_id', postIds).order('timestamp', { ascending: false }),
    supabase.from('channel_reactions').select('post_id, emoji, nick').in('post_id', postIds),
  ]);
  const allComments = commentsRes.data || [];
  const allReactions = reactionsRes.data || [];
  const result = posts.map(p => {
    const postComments = allComments.filter(c => c.post_id === p.id);
    const postReactions = allReactions.filter(r => r.post_id === p.id);
    const topCommenters = [...new Set(postComments.map(c => c.from_nick))].slice(0, 3);
    return { ...p, commentCount: postComments.length, reactions: postReactions, topCommenters };
  });
  res.json({ ok: true, messages: result });
});

// POST /channel/message — підтримує text, imageUrl, fileData, fileName
app.post('/channel/message', async (req, res) => {
  const { channelId, fromNick, text, imageUrl, fileData, fileName, waveform, durationSec, forwardedFrom } = req.body;
  if (!channelId || !fromNick || (!text && !imageUrl && !fileData)) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Тільки власник або адмін може писати' });
  const ts = Date.now(); const msgId = `ch_${channelId}_${ts}`;
  const isVideo = fileName && /\.(mp4|mov|avi|mkv|webm)$/i.test(fileName);
  const isVoice = fileName && fileName.startsWith('voice_');
  const { data: msg } = await supabase.from('channel_messages').insert({
    channel_id: channelId, from_nick: fromNick,
    content: text || null,
    image_url: imageUrl || null,
    file_data: fileData || null,
    file_name: fileName || null,
    timestamp: ts, msg_id: msgId,
    ...(forwardedFrom ? { forwarded_from: forwardedFrom } : {}),
    ...(waveform ? { waveform: JSON.stringify(waveform) } : {}),
    ...(durationSec != null ? { duration_sec: durationSec } : {}),
  }).select().single();
  const lastText = text ? text.substring(0, 50) : (imageUrl ? '🖼 Зображення' : (isVideo ? '🎬 Відео' : (isVoice ? '🎤 Голосове' : (fileName ? '📎 ' + fileName.substring(0, 30) : ''))));
  await supabase.from('channels').update({ last_post_at: ts, last_post_text: lastText }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_message', channelId, postId: msg.id, from: fromNick, text: text || null, imageUrl: imageUrl || null, fileName: fileName || null, timestamp: ts, msgId, ...(forwardedFrom ? { forwardedFrom } : {}), message: { ...msg, commentCount: 0, reactions: [], topCommenters: [] } }, fromNick);
  res.json({ ok: true, message: { ...msg, commentCount: 0, reactions: [], topCommenters: [], waveform: waveform || null, duration_sec: durationSec || null } });
});

// Редагування поста (обидва шляхи для сумісності)
app.post('/channel/message/edit', async (req, res) => {
  const { channelId, postId, nick, content } = req.body;
  if (!channelId || !postId || !nick || !content) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canEdit = post.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_messages').update({ content, edited: true, edited_at: Date.now() }).eq('id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_edited', channelId, postId, text: content }, null);
  res.json({ ok: true });
});

app.post('/channel/edit-message', async (req, res) => {
  const { channelId, postId, fromNick, text } = req.body;
  if (!channelId || !postId || !fromNick || !text) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canEdit = post.from_nick === fromNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_messages').update({ content: text, edited: true, edited_at: Date.now() }).eq('id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_edited', channelId, postId, text }, null);
  res.json({ ok: true });
});

// Видалення поста (обидва шляхи)
app.post('/channel/message/delete', async (req, res) => {
  const { channelId, postId, nick } = req.body;
  if (!postId || !channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick, image_url, file_data').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canDelete = post.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: postComments } = await supabase.from('channel_comments').select('file_data').eq('post_id', postId);
  await supabase.from('channel_comments').delete().eq('post_id', postId);
  await supabase.from('channel_reactions').delete().eq('post_id', postId);
  await supabase.from('channel_messages').delete().eq('id', postId);
  await removeChannelFile(post.image_url, post.file_data);
  for (const c of (postComments || [])) await removeChannelFile(c.file_data);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_deleted', channelId, postId }, null);
  res.json({ ok: true });
});

app.delete('/channel/post', async (req, res) => {
  const { postId, channelId, requesterNick } = req.body;
  if (!postId || !channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick, image_url, file_data').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canDelete = post.from_nick === requesterNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: postComments } = await supabase.from('channel_comments').select('file_data').eq('post_id', postId);
  await supabase.from('channel_comments').delete().eq('post_id', postId);
  await supabase.from('channel_reactions').delete().eq('post_id', postId);
  await supabase.from('channel_messages').delete().eq('id', postId);
  await removeChannelFile(post.image_url, post.file_data);
  for (const c of (postComments || [])) await removeChannelFile(c.file_data);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_deleted', channelId, postId }, null);
  res.json({ ok: true });
});

// Коментарі
app.get('/channel/comments', async (req, res) => {
  const { postId, before } = req.query; if (!postId) return res.json({ ok: false, error: 'postId обов\'язковий' });
  const limit = Math.min(parseInt(req.query.limit) || 100, 200);
  // Той самий двигун, що й /group/messages: беремо ОСТАННІ limit коментарів
  // (descending + limit), потім розвертаємо в ascending. before (timestamp) —
  // для довантаження старіших при скролі вгору.
  let q = supabase.from('channel_comments').select('*').eq('post_id', postId);
  if (before) q = q.lt('timestamp', Number(before));
  q = q.order('timestamp', { ascending: false }).limit(limit + 1);
  const { data: rawDesc } = await q;
  const rows = rawDesc || [];
  const hasMore = rows.length > limit;        // є ще старіші
  const page = hasMore ? rows.slice(0, limit) : rows;
  const comments = page.slice().reverse();    // назад в ascending
  console.log(`[channel/comments] postId=${postId} before=${before || '-'} limit=${limit} → returned=${comments.length} hasMore=${hasMore}`);
  const ids = comments.map(c => c.id);
  const reactionsByComment = {};
  if (ids.length > 0) {
    const { data: reacts } = await supabase.from('channel_comment_reactions').select('comment_id, emoji, nick').in('comment_id', ids);
    for (const r of reacts || []) {
      if (!reactionsByComment[r.comment_id]) reactionsByComment[r.comment_id] = [];
      reactionsByComment[r.comment_id].push({ emoji: r.emoji, nick: r.nick });
    }
  }
  const parseWf = (w) => { if (!w) return null; if (Array.isArray(w)) return w; try { return JSON.parse(w); } catch { return null; } };
  res.json({ ok: true, hasMore, oldest: comments[0]?.timestamp ?? null, comments: comments.map(c => ({ ...c, waveform: parseWf(c.waveform), reactions: reactionsByComment[c.id] || [] })) });
});

app.post('/channel/comment', async (req, res) => {
  const { channelId, postId, fromNick, text, fileData, fileName, waveform, durationSec, replyToNick, replyToText, replyToImage, replyToId } = req.body;
  if (!channelId || !postId || !fromNick || (!text && !fileData)) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member) return res.json({ ok: false, error: 'Підпишіться на канал щоб коментувати' });
  const { data: postRow } = await supabase.from('channel_messages').select('comments_enabled').eq('id', postId).single();
  if (postRow && postRow.comments_enabled === false) return res.json({ ok: false, error: 'Коментарі вимкнені' });
  if (fileData) { const { data: chRow } = await supabase.from('channels').select('comments_allow_media').eq('id', channelId).single(); if (chRow && chRow.comments_allow_media === false) return res.json({ ok: false, error: 'Медіа в коментарях вимкнено' }); }
  const ts = Date.now();
  const { data: comment } = await supabase.from('channel_comments').insert({ channel_id: channelId, post_id: postId, from_nick: fromNick, content: text || fileName || '', file_data: fileData || null, file_name: fileName || null, timestamp: ts, reply_to_nick: replyToNick || null, reply_to_text: replyToText || null, reply_to_image: replyToImage || null, reply_to_id: replyToId || null, waveform: waveform ? JSON.stringify(waveform) : null, duration_sec: durationSec || null }).select().single();
  const { count: commentCount } = await supabase.from('channel_comments').select('*', { count: 'exact', head: true }).eq('post_id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_comment', channelId, postId, from: fromNick, text: text || null, timestamp: ts, commentId: comment.id, commentCount: commentCount || 0, comment }, fromNick);
  res.json({ ok: true, comment: { ...comment, waveform: waveform || null } });
});

app.post('/channel/post/comments-toggle', async (req, res) => {
  const { channelId, postId, requesterNick, enabled } = req.body;
  if (!channelId || !postId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_messages').update({ comments_enabled: !!enabled }).eq('id', postId);
  res.json({ ok: true });
});

app.delete('/channel/comment', async (req, res) => {
  const { commentId, channelId, requesterNick } = req.body;
  if (!commentId || !channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: comment } = await supabase.from('channel_comments').select('from_nick, file_data').eq('id', commentId).single();
  if (!comment) return res.json({ ok: false, error: 'Коментар не знайдено' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  const canDelete = comment.from_nick === requesterNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_comment_reactions').delete().eq('comment_id', commentId);
  await supabase.from('channel_comments').delete().eq('id', commentId);
  await removeChannelFile(comment.file_data);
  res.json({ ok: true });
});

// Реакція на коментар (toggle) — дзеркало /channel/reaction
app.post('/channel/comment/reaction', async (req, res) => {
  const { commentId, channelId, nick, emoji } = req.body;
  if (!commentId || !channelId || !nick || !emoji) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані' });
  const { data: existing } = await supabase.from('channel_comment_reactions').select('id').eq('comment_id', commentId).eq('nick', nick).eq('emoji', emoji).single();
  if (existing) { await supabase.from('channel_comment_reactions').delete().eq('id', existing.id); }
  else {
    await supabase.from('channel_comment_reactions').delete().eq('comment_id', commentId).eq('nick', nick);
    await supabase.from('channel_comment_reactions').insert({ comment_id: commentId, nick, emoji });
  }
  const { data: reactions } = await supabase.from('channel_comment_reactions').select('emoji, nick').eq('comment_id', commentId);
  const { data: c } = await supabase.from('channel_comments').select('post_id').eq('id', commentId).single();
  await notifyChannelSubscribers(channelId, { type: 'channel_comment_reaction', channelId, postId: c ? c.post_id : null, commentId, reactions }, null);
  res.json({ ok: true, reactions: reactions || [] });
});

// Редагування коментаря (свій або owner/admin) — дзеркало /channel/message/edit
app.post('/channel/comment/edit', async (req, res) => {
  const { channelId, commentId, nick, content } = req.body;
  if (!channelId || !commentId || !nick || !content) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: comment } = await supabase.from('channel_comments').select('from_nick, post_id').eq('id', commentId).single();
  if (!comment) return res.json({ ok: false, error: 'Коментар не знайдено' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const canEdit = comment.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав' });
  const editedAt = Date.now();
  await supabase.from('channel_comments').update({ content, edited: true, edited_at: editedAt }).eq('id', commentId);
  await notifyChannelSubscribers(channelId, { type: 'channel_comment_edited', channelId, postId: comment.post_id, commentId, text: content, editedAt }, null);
  res.json({ ok: true });
});

// Інкремент переглядів поста
app.post('/channel/view', async (req, res) => {
  const { postId, nick } = req.body;
  if (!postId) return res.json({ ok: false });
  const { data: post } = await supabase.from('channel_messages').select('view_count, channel_id').eq('id', postId).single();
  if (!post) return res.json({ ok: false });
  // Рахуємо лише унікальних глядачів: 1 людина = 1 перегляд.
  if (nick) {
    const { data: seen } = await supabase.from('channel_post_views').select('id').eq('post_id', postId).eq('nick', nick).maybeSingle();
    if (seen) return res.json({ ok: true, viewCount: post.view_count || 0, counted: false });
    await supabase.from('channel_post_views').insert({ post_id: postId, nick });
  }
  const newCount = (post.view_count || 0) + 1;
  await supabase.from('channel_messages').update({ view_count: newCount }).eq('id', postId);
  // Розсилаємо новий лічильник переглядів усім підписникам (real-time)
  await notifyChannelSubscribers(post.channel_id, { type: 'channel_view', channelId: post.channel_id, postId, viewCount: newCount }, null);
  res.json({ ok: true, viewCount: newCount, counted: true });
});

// Реакції
app.post('/channel/reaction', async (req, res) => {
  const { postId, channelId, nick, emoji } = req.body;
  if (!postId || !channelId || !nick || !emoji) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані' });
  const { data: existing } = await supabase.from('channel_reactions').select('id').eq('post_id', postId).eq('nick', nick).eq('emoji', emoji).single();
  if (existing) { await supabase.from('channel_reactions').delete().eq('id', existing.id); }
  else {
    await supabase.from('channel_reactions').delete().eq('post_id', postId).eq('nick', nick);
    await supabase.from('channel_reactions').insert({ post_id: postId, nick, emoji });
  }
  const { data: reactions } = await supabase.from('channel_reactions').select('emoji, nick').eq('post_id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_reaction', channelId, postId, reactions }, null);
  res.json({ ok: true, reactions: reactions || [] });
});

// Модерація каналу
app.post('/channel/block-subscriber', async (req, res) => {
  const { channelId, ownerNick, targetNick } = req.body;
  if (!channelId || !ownerNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_blocked').upsert({ channel_id: channelId, nick: targetNick, blocked_at: Date.now() });
  res.json({ ok: true });
});

app.get('/channel/blocked-list', async (req, res) => {
  const { channelId, ownerNick } = req.query;
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: blocked } = await supabase.from('channel_blocked').select('nick, blocked_at').eq('channel_id', channelId).order('blocked_at', { ascending: false });
  res.json({ ok: true, blocked: blocked || [] });
});

app.post('/channel/unblock-subscriber', async (req, res) => {
  const { channelId, ownerNick, targetNick } = req.body;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId).eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/channel/remove-subscriber', async (req, res) => {
  const { channelId, ownerNick, targetNick } = req.body;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', targetNick);
  sendToUser(targetNick, { type: 'channel_removed', channelId });
  res.json({ ok: true });
});

app.post('/channel/set-admin', async (req, res) => {
  const { channelId, ownerNick, targetNick, isAdmin } = req.body;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Тільки власник може призначати адмінів' });
  await supabase.from('channel_members').update({ role: isAdmin ? 'admin' : 'subscriber' }).eq('channel_id', channelId).eq('nick', targetNick);
  res.json({ ok: true });
});

app.get('/channel/subscribers', async (req, res) => {
  const { channelId, ownerNick } = req.query;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: members } = await supabase.from('channel_members').select('nick, role, joined_at').eq('channel_id', channelId).order('joined_at', { ascending: true });
  const { data: blocked } = await supabase.from('channel_blocked').select('nick').eq('channel_id', channelId);
  const blockedSet = new Set((blocked || []).map(b => b.nick));
  res.json({ ok: true, subscribers: (members || []).map(m => ({ ...m, isBlocked: blockedSet.has(m.nick) })) });
});

app.post('/channel/invite', async (req, res) => {
  const { channelId, ownerNick, targetNick } = req.body;
  if (!channelId || !ownerNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', targetNick).single();
  if (existing) return res.json({ ok: false, error: 'Користувач вже є підписником' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', targetNick).single();
  if (blocked) return res.json({ ok: false, error: 'Цей користувач заблокований у каналі' });
  const { data: targetUser } = await supabase.from('users').select('nick').eq('nick', targetNick).single();
  if (!targetUser) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const { data: channel } = await supabase.from('channels').select('name').eq('id', channelId).single();
  // Надсилаємо ЗАПРОШЕННЯ — користувач має підтвердити
  const targetWs = onlineUsers.get(targetNick);
  if (targetWs) {
    targetWs.ws.send(JSON.stringify({ type: 'channel_invite_request', channelId, channelName: channel?.name, byNick: ownerNick }));
  } else {
    await supabase.from('pending_channel_invites').upsert({ channel_id: channelId, target_nick: targetNick, inviter_nick: ownerNick });
  }
  res.json({ ok: true, pending: true });
});

app.post('/channel/invite-response', async (req, res) => {
  const { channelId, nick, accepted } = req.body;
  if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('pending_channel_invites').delete().eq('channel_id', channelId).eq('target_nick', nick);
  if (!accepted) return res.json({ ok: true });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!existing) await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  const { data: channel } = await supabase.from('channels').select('*').eq('id', channelId).single();
  const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', channelId);
  res.json({ ok: true, channel: { ...channel, myRole: 'subscriber', subscriberCount: count || 0 } });
});



app.post('/channel/contact-owner', async (req, res) => {
  const { channelId, fromNick } = req.body;
  if (!channelId || !fromNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const CONTACT_PRICE = 100; const OWNER_SHARE = 70; const COMPANY_SHARE = 30; const COMPANY_NICK = 'eion_company';
  const { data: channel } = await supabase.from('channels').select('owner_nick').eq('id', channelId).single();
  if (!channel) return res.json({ ok: false, error: 'Канал не знайдено' });
  if (channel.owner_nick === fromNick) return res.json({ ok: false, error: 'Ви є власником каналу' });
  const { data: sender } = await supabase.from('users').select('coins').eq('nick', fromNick).single();
  if (!sender || (sender.coins || 0) < CONTACT_PRICE) return res.json({ ok: false, error: 'Недостатньо EION монет (потрібно 100)' });
  const { data: owner } = await supabase.from('users').select('coins').eq('nick', channel.owner_nick).single();
  if (!owner) return res.json({ ok: false, error: 'Власника каналу не знайдено' });
  await supabase.from('users').update({ coins: (sender.coins || 0) - CONTACT_PRICE }).eq('nick', fromNick);
  await supabase.from('users').update({ coins: (owner.coins || 0) + OWNER_SHARE }).eq('nick', channel.owner_nick);
  const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
  if (company) await supabase.from('users').update({ coins: (company.coins || 0) + COMPANY_SHARE }).eq('nick', COMPANY_NICK);
  const senderWs = onlineUsers.get(fromNick); if (senderWs) senderWs.ws.send(JSON.stringify({ type: 'coins_update', amount: -CONTACT_PRICE, total: (sender.coins || 0) - CONTACT_PRICE }));
  const ownerWs = onlineUsers.get(channel.owner_nick); if (ownerWs) ownerWs.ws.send(JSON.stringify({ type: 'coins_received', fromNick, amount: OWNER_SHARE, total: (owner.coins || 0) + OWNER_SHARE }));
  res.json({ ok: true, ownerNick: channel.owner_nick });
});

// ── Платна підписка на канал (монети, комісія 30% платформі) ──────────────
app.post('/channel/subscribe-paid', async (req, res) => {
  const { channelId, nick } = req.body;
  if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const COMPANY_NICK = 'eion_company'; const FEE_PCT = 30;
  const { data: ch } = await supabase.from('channels').select('owner_nick, is_paid, price, sub_days').eq('id', channelId).single();
  if (!ch) return res.json({ ok: false, error: 'Канал не знайдено' });
  if (!ch.is_paid) return res.json({ ok: false, error: 'Канал безкоштовний' });
  // Вже є активна підписка — не списувати повторно
  const { data: curArr } = await supabase.from('channel_paid_subs').select('expires_at').eq('channel_id', channelId).eq('nick', nick).order('expires_at', { ascending: false }).limit(1);
  if (curArr && curArr[0] && Number(curArr[0].expires_at) > Date.now()) return res.json({ ok: true, alreadySubscribed: true, expiresAt: Number(curArr[0].expires_at) });
  const price = ch.price || 0;
  const { data: user } = await supabase.from('users').select('coins').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if ((user.coins || 0) < price) return res.json({ ok: false, error: `Недостатньо EION (потрібно ${price})` });
  const companyShare = Math.floor(price * FEE_PCT / 100);
  const ownerShare = price - companyShare;
  const newBalance = (user.coins || 0) - price;
  await supabase.from('users').update({ coins: newBalance }).eq('nick', nick);
  if (ch.owner_nick && ch.owner_nick !== nick) {
    const { data: owner } = await supabase.from('users').select('coins').eq('nick', ch.owner_nick).single();
    if (owner) {
      const ownerNew = (owner.coins || 0) + ownerShare;
      await supabase.from('users').update({ coins: ownerNew }).eq('nick', ch.owner_nick);
      const ownerWs = onlineUsers.get(ch.owner_nick);
      if (ownerWs) ownerWs.ws.send(JSON.stringify({ type: 'coins_received', fromNick: nick, amount: ownerShare, total: ownerNew }));
    }
  }
  const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
  if (company) await supabase.from('users').update({ coins: (company.coins || 0) + companyShare }).eq('nick', COMPANY_NICK);
  const subDays = ch.sub_days || 30;
  const expiresAt = Date.now() + subDays * 86400000;
  // Запис підписки БЕЗ залежності від unique-констрейнта (upsert+onConflict міг тихо падати)
  const { data: existArr, error: existErr } = await supabase.from('channel_paid_subs').select('nick').eq('channel_id', channelId).eq('nick', nick).limit(1);
  if (existErr) console.error('[paid-sub] existArr ERROR:', JSON.stringify(existErr));
  const subBranch = (existArr && existArr.length > 0) ? 'update' : 'insert';
  let subWriteErr = null;
  if (subBranch === 'update') {
    const { error } = await supabase.from('channel_paid_subs').update({ expires_at: expiresAt }).eq('channel_id', channelId).eq('nick', nick);
    subWriteErr = error;
  } else {
    const { error } = await supabase.from('channel_paid_subs').insert({ channel_id: Number(channelId), nick, expires_at: expiresAt });
    subWriteErr = error;
  }
  if (subWriteErr) console.error('[paid-sub] WRITE ERROR:', JSON.stringify(subWriteErr));
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!existing) await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  const subWs = onlineUsers.get(nick);
  if (subWs) subWs.ws.send(JSON.stringify({ type: 'coins_update', amount: -price, total: newBalance }));
  res.json({ ok: true, newBalance, expiresAt });
});

// Власник вмикає/вимикає платність і ставить ціну/період
app.post('/channel/set-paid', async (req, res) => {
  const { channelId, requesterNick, isPaid, price, subDays } = req.body;
  if (!channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Лише власник' });
  await supabase.from('channels').update({ is_paid: !!isPaid, price: Math.max(0, parseInt(price) || 0), sub_days: Math.max(1, parseInt(subDays) || 30) }).eq('id', channelId);
  res.json({ ok: true });
});

app.post('/channel/update', async (req, res) => {
  const { channelId, ownerNick, name, description, type, avatar_url, comments_allow_media } = req.body;
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const updates = {};
  if (name !== undefined) updates.name = name;
  if (description !== undefined) updates.description = description;
  if (type !== undefined) updates.type = type;
  if (avatar_url !== undefined) updates.avatar_url = avatar_url;
  if (comments_allow_media !== undefined) updates.comments_allow_media = comments_allow_media;
  if (Object.keys(updates).length === 0) return res.json({ ok: false, error: 'Нічого оновлювати' });
  await supabase.from('channels').update(updates).eq('id', channelId);
  res.json({ ok: true });
});

app.post('/channel/delete', async (req, res) => {
  const { channelId, ownerNick } = req.body;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Тільки власник може видалити канал' });
  // Збираємо файли постів і коментарів перед видаленням — щоб прибрати зі Storage.
  const { data: chPosts } = await supabase.from('channel_messages').select('id, image_url, file_data').eq('channel_id', channelId);
  const { data: chComments } = await supabase.from('channel_comments').select('file_data').eq('channel_id', channelId);
  await supabase.from('channel_comments').delete().eq('channel_id', channelId);
  await supabase.from('channel_reactions').delete().in('post_id', (chPosts || []).map(m => m.id));
  await supabase.from('channel_messages').delete().eq('channel_id', channelId);
  await supabase.from('channel_members').delete().eq('channel_id', channelId);
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId);
  await supabase.from('channels').delete().eq('id', channelId);
  for (const p of (chPosts || [])) await removeChannelFile(p.image_url, p.file_data);
  for (const c of (chComments || [])) await removeChannelFile(c.file_data);
  res.json({ ok: true });
});

// ── Модерація платформи ────────────────────────
app.post('/report', async (req, res) => {
  const { reporterNick, targetNick, reason, context } = req.body;
  if (!reporterNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('reports').insert({ reporter_nick: reporterNick, target_nick: targetNick, reason: reason || null, context: context || null, created_at: Date.now() });
  res.json({ ok: true });
});

app.get('/admin/reports', async (req, res) => {
  const { adminNick } = req.query;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  const { data } = await supabase.from('reports').select('*').eq('status', 'pending').order('created_at', { ascending: false });
  res.json({ ok: true, reports: data || [] });
});

app.post('/admin/ban', async (req, res) => {
  const { adminNick, targetNick, reason } = req.body;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  await supabase.from('platform_bans').upsert({ nick: targetNick, reason: reason || null, banned_at: Date.now(), banned_by: adminNick });
  const t = onlineUsers.get(targetNick); if (t) { t.ws.send(JSON.stringify({ type: 'kicked', reason: 'Акаунт заблоковано' })); t.ws.close(); }
  res.json({ ok: true });
});

app.post('/admin/unban', async (req, res) => {
  const { adminNick, targetNick } = req.body;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  await supabase.from('platform_bans').delete().eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/admin/resolve-report', async (req, res) => {
  const { adminNick, reportId } = req.body;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  await supabase.from('reports').update({ status: 'resolved' }).eq('id', reportId);
  res.json({ ok: true });
});

// ── WebSocket ────────────────────────────────
wss.on('connection', (ws) => {
  let userNick = null;
  // Серверний heartbeat (проти code=1006: мертвий транспорт виявляємо швидко).
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; if (userNick && onlineUsers.has(userNick)) onlineUsers.get(userNick).lastSeen = Date.now(); });
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'login') {
        userNick = msg.nick;
        const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', userNick).single();
        if (ban) { ws.send(JSON.stringify({ type: 'kicked', reason: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}` })); ws.close(); return; }
        if (onlineUsers.has(userNick)) { const old = onlineUsers.get(userNick); old.ws.send(JSON.stringify({ type: 'kicked', reason: 'Новий пристрій підключився' })); old.ws.close(); }
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        ws.send(JSON.stringify({ type: 'login_ok' }));
        for (const [nick, user] of onlineUsers) { if (nick !== userNick) user.ws.send(JSON.stringify({ type: 'user_online', nick: userNick })); }

        const { data: pendingDeletes } = await supabase.from('deleted_messages').select('msg_id, from_nick').eq('to_nick', userNick);
        if (pendingDeletes && pendingDeletes.length > 0) {
          const delIds = pendingDeletes.map(d => d.msg_id).filter(Boolean);
          if (delIds.length > 0) await supabase.from('messages').delete().eq('to_nick', userNick).in('msg_id', delIds);
          for (const d of pendingDeletes) ws.send(JSON.stringify({ type: 'delete_message', from: d.from_nick, msgId: d.msg_id }));
          await supabase.from('deleted_messages').delete().eq('to_nick', userNick);
        }

        const { data: toDeliver } = await supabase.from('messages').select('id, from_nick, msg_id').eq('to_nick', userNick).eq('status', 'sent');
        if (toDeliver && toDeliver.length > 0) {
          await supabase.from('messages').update({ status: 'delivered' }).eq('to_nick', userNick).eq('status', 'sent');
          const senders = [...new Set(toDeliver.map(m => m.from_nick))];
          for (const sender of senders) { const senderWs = onlineUsers.get(sender); if (senderWs) { const msgIds = toDeliver.filter(m => m.from_nick === sender).map(m => m.msg_id).filter(Boolean); if (msgIds.length > 0) senderWs.ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds })); } }
        }

        const { data: myStatuses } = await supabase.from('messages').select('msg_id, status').eq('from_nick', userNick).neq('status', 'sent').not('msg_id', 'is', null);
        if (myStatuses && myStatuses.length > 0) ws.send(JSON.stringify({ type: 'status_sync', statuses: myStatuses }));

        const { data: pending } = await supabase.from('messages').select('*').eq('to_nick', userNick).eq('delivered', false).order('timestamp', { ascending: true });
        if (pending && pending.length > 0) {
          for (const m of pending) ws.send(JSON.stringify(m.type === 'file' ? { type: 'file_message', from: m.from_nick, fileName: m.file_name, ...(m.file_data && m.file_data.startsWith('http') ? { fileUrl: m.file_data } : { data: m.file_data }), timestamp: m.timestamp, msgId: m.msg_id, ...(m.waveform ? { waveform: JSON.parse(m.waveform) } : {}), ...(m.duration_sec != null ? { durationSec: m.duration_sec } : {}) } : { type: 'chat_message', from: m.from_nick, text: m.content, msgId: m.msg_id, timestamp: m.timestamp, ...(m.reply_to_msg_id ? { replyToMsgId: m.reply_to_msg_id } : {}), ...(m.reply_to_text ? { replyToText: m.reply_to_text } : {}), ...(m.reply_to_from ? { replyToFrom: m.reply_to_from } : {}), ...(m.reply_to_image ? { replyToImage: m.reply_to_image } : {}) }));
          await supabase.from('messages').update({ delivered: true }).eq('to_nick', userNick).eq('delivered', false);
        }

        const { data: myGroups } = await supabase.from('group_members').select('group_id').eq('nick', userNick);
        if (myGroups && myGroups.length > 0) {
          for (const gm of myGroups) {
            const { data: pendingGroup } = await supabase.from('group_messages').select('*').eq('group_id', gm.group_id).not('delivered_to', 'cs', `{"${userNick}"}`).order('timestamp', { ascending: true });
            if (pendingGroup && pendingGroup.length > 0) { for (const m of pendingGroup) {
              if (m.type === 'file') ws.send(JSON.stringify({ type: 'file_message', groupId: m.group_id, from: m.from_nick, fileName: m.file_name, ...(m.file_data && m.file_data.startsWith('http') ? { fileUrl: m.file_data } : { data: m.file_data }), timestamp: m.timestamp, msgId: m.msg_id, ...(m.waveform ? { waveform: m.waveform } : {}), ...(m.duration_sec != null ? { durationSec: m.duration_sec } : {}) }));
              else ws.send(JSON.stringify({ type: 'group_message', groupId: m.group_id, from: m.from_nick, text: m.content, timestamp: m.timestamp, msgId: m.msg_id }));
              await supabase.from('group_messages').update({ delivered_to: [...(m.delivered_to || []), userNick] }).eq('id', m.id);
            } }
          }
        }

        const { data: pendingReactions } = await supabase.from('pending_reactions').select('*').eq('to_nick', userNick);
        if (pendingReactions && pendingReactions.length > 0) { for (const r of pendingReactions) ws.send(JSON.stringify({ type: 'reaction', msgId: r.msg_id, emoji: r.emoji, from: r.from_nick, chatNick: r.chat_nick, groupId: r.group_id })); await supabase.from('pending_reactions').delete().eq('to_nick', userNick); }

        const { data: modGroups } = await supabase.from('group_members').select('group_id').eq('nick', userNick).in('role', ['creator', 'moderator']);
        if (modGroups && modGroups.length > 0) { for (const gm of modGroups) { const { data: reqs } = await supabase.from('group_join_requests').select('nick').eq('group_id', gm.group_id).eq('status', 'pending'); if (reqs && reqs.length > 0) { const { data: g } = await supabase.from('groups').select('name').eq('id', gm.group_id).single(); for (const r of reqs) ws.send(JSON.stringify({ type: 'group_join_request', groupId: gm.group_id, groupName: g?.name, nick: r.nick })); } } }

        const { data: groupInvites } = await supabase.from('pending_group_invites').select('*').eq('target_nick', userNick);
        if (groupInvites && groupInvites.length > 0) {
          for (const inv of groupInvites) { const { data: g } = await supabase.from('groups').select('name').eq('id', inv.group_id).single(); if (g) ws.send(JSON.stringify({ type: 'group_invite', groupId: inv.group_id, groupName: g.name, inviterNick: inv.inviter_nick })); }
        }

        // Pending channel invites
        const { data: channelInvites } = await supabase.from('pending_channel_invites').select('*').eq('target_nick', userNick);
        if (channelInvites && channelInvites.length > 0) {
          for (const inv of channelInvites) {
            const { data: ch } = await supabase.from('channels').select('name').eq('id', inv.channel_id).single();
            if (ch) ws.send(JSON.stringify({ type: 'channel_invite_request', channelId: inv.channel_id, channelName: ch.name, byNick: inv.inviter_nick }));
          }
        }
      }

      if (msg.type === 'register_fcm_token') { if (userNick && msg.token) { fcmTokens.set(userNick, msg.token); if (msg.deviceId) nickDevices.set(userNick, msg.deviceId); } }
      if (msg.type === 'check_online') ws.send(JSON.stringify({ type: 'online_status', nick: msg.nick, online: onlineUsers.has(msg.nick) }));
      if (msg.type === 'connect_request') { if (!sendToUser(msg.to, { type: 'connect_request', from: userNick })) ws.send(JSON.stringify({ type: 'error', error: `${msg.to} не в мережі` })); }
      if (msg.type === 'connect_response') { sendToUser(msg.to, { type: 'connect_response', from: userNick, accepted: msg.accepted }); }

      if (msg.type === 'chat_message') {
        // Якщо адресат заблокував відправника — повідомлення не зберігається
        // і не доставляється (мовчки, без сигналу відправнику).
        if (await isBlockedBy(msg.to, userNick)) return;
        const ts = (typeof msg.timestamp === 'number' && msg.timestamp > 0 && msg.timestamp <= Date.now() + 60000) ? msg.timestamp : Date.now(); const target = onlineUsers.get(msg.to); const msgId = msg.msgId || null;
        const status = target ? 'delivered' : 'sent';
        const hasFile = msg.isFile && (msg.fileData || msg.fileUrl);
        await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: hasFile ? 'file' : 'text', content: msg.text, timestamp: ts, delivered: !!target, msg_id: msgId, status, ...(hasFile ? { file_name: msg.fileName, file_data: msg.fileData || msg.fileUrl } : {}), ...(msg.replyToMsgId ? { reply_to_msg_id: msg.replyToMsgId } : {}), ...(msg.replyToText ? { reply_to_text: msg.replyToText } : {}), ...(msg.replyToFrom ? { reply_to_from: msg.replyToFrom } : {}), ...(msg.replyToImage ? { reply_to_image: msg.replyToImage } : {}) });
        if (target) { target.ws.send(JSON.stringify({ type: 'chat_message', from: userNick, text: msg.text, timestamp: ts, msgId, ...(msg.isFile ? { isFile: true } : {}), ...(msg.isVoice ? { isVoice: true } : {}), ...(msg.fileName ? { fileName: msg.fileName } : {}), ...(msg.fileData ? { fileData: msg.fileData } : {}), ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : {}), ...(msg.replyToMsgId ? { replyToMsgId: msg.replyToMsgId } : {}), ...(msg.replyToText ? { replyToText: msg.replyToText } : {}), ...(msg.replyToFrom ? { replyToFrom: msg.replyToFrom } : {}), ...(msg.replyToImage ? { replyToImage: msg.replyToImage } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) })); if (msgId && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds: [msgId] })); }
        else {
          // Безтілесний push (приватність): лише сигнал + нік, без тексту.
          sendFcmPush(msg.to, { type: 'message', from_nick: userNick });
        }
      }

      if (msg.type === 'file_message') {
        const ts = (typeof msg.timestamp === 'number' && msg.timestamp > 0 && msg.timestamp <= Date.now() + 60000) ? msg.timestamp : Date.now(); const msgId = msg.msgId || null;
        const fileData = msg.fileUrl || msg.data || null;
        if (msg.groupId) {
          const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
          if (!membership) return;
          const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
          const onlineMembers = (members || []).map(m => m.nick).filter(n => n !== userNick && onlineUsers.has(n));
          await supabase.from('group_messages').insert({ group_id: msg.groupId, from_nick: userNick, content: msg.fileName, timestamp: ts, msg_id: msgId, delivered_to: [userNick, ...onlineMembers], type: 'file', file_name: msg.fileName, file_data: fileData, ...(msg.waveform ? { waveform: msg.waveform } : {}), ...(msg.durationSec != null ? { duration_sec: msg.durationSec } : {}) });
          await trackFileObject(fileData, (members || []).map(m => m.nick).filter(n => n !== userNick)); // 2C
          for (const nick of onlineMembers) onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'file_message', groupId: msg.groupId, from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : { data: msg.data }), timestamp: ts, msgId, ...(msg.waveform ? { waveform: msg.waveform } : {}), ...(msg.durationSec != null ? { durationSec: msg.durationSec } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) }));
        } else {
          const target = onlineUsers.get(msg.to); const status = target ? 'delivered' : 'sent';
          await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: 'file', content: msg.fileName, file_name: msg.fileName, file_data: fileData, timestamp: ts, delivered: !!target, msg_id: msgId, status, ...(msg.waveform ? { waveform: JSON.stringify(msg.waveform) } : {}), ...(msg.durationSec != null ? { duration_sec: msg.durationSec } : {}) });
          await trackFileObject(fileData, [msg.to]); // 2C
          if (target) { target.ws.send(JSON.stringify({ type: 'file_message', from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : { data: msg.data }), timestamp: ts, msgId, ...(msg.waveform ? { waveform: msg.waveform } : {}), ...(msg.durationSec != null ? { durationSec: msg.durationSec } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) })); if (msgId && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds: [msgId] })); }
          else { sendFcmPush(msg.to, { type: 'message', from_nick: userNick }); }
        }
      }

      if (msg.type === 'file_downloaded') {
        const path = storagePathFromUrl(msg.fileUrl || msg.path || msg.fileData || '');
        if (path && userNick) {
          try {
            const { data: rows } = await supabase.from('file_objects').select('downloaded_by').eq('storage_path', path).limit(1);
            if (rows && rows.length) {
              const set = new Set(rows[0].downloaded_by || []);
              if (!set.has(userNick)) { set.add(userNick); await supabase.from('file_objects').update({ downloaded_by: [...set] }).eq('storage_path', path); }
            }
          } catch (e) { console.log('[2C] file_downloaded error:', e.message); }
        }
      }

      if (msg.type === 'group_message') {
        const ts = (typeof msg.timestamp === 'number' && msg.timestamp > 0 && msg.timestamp <= Date.now() + 60000) ? msg.timestamp : Date.now(); const msgId = msg.msgId || `${userNick}_g${msg.groupId}_${ts}`;
        const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
        if (!membership) return;
        const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
        const onlineMembers = (members || []).map(m => m.nick).filter(n => n !== userNick && onlineUsers.has(n));
        await supabase.from('group_messages').insert({ group_id: msg.groupId, from_nick: userNick, content: msg.text, timestamp: ts, msg_id: msgId, delivered_to: [userNick, ...onlineMembers], ...(msg.isFile ? { type: 'file', file_name: msg.fileName, file_data: msg.fileData || msg.fileUrl } : {}), ...(msg.replyToMsgId ? { reply_to_msg_id: msg.replyToMsgId } : {}), ...(msg.replyToText ? { reply_to_text: msg.replyToText } : {}), ...(msg.replyToFrom ? { reply_to_from: msg.replyToFrom } : {}), ...(msg.replyToImage ? { reply_to_image: msg.replyToImage } : {}) });
        for (const nick of onlineMembers) onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'group_message', groupId: msg.groupId, from: userNick, text: msg.text, timestamp: ts, msgId, ...(msg.isFile ? { isFile: true } : {}), ...(msg.isVoice ? { isVoice: true } : {}), ...(msg.fileName ? { fileName: msg.fileName } : {}), ...(msg.fileData ? { fileData: msg.fileData } : {}), ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : {}), ...(msg.replyToMsgId ? { replyToMsgId: msg.replyToMsgId } : {}), ...(msg.replyToText ? { replyToText: msg.replyToText } : {}), ...(msg.replyToFrom ? { replyToFrom: msg.replyToFrom } : {}), ...(msg.replyToImage ? { replyToImage: msg.replyToImage } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) }));
      }

      if (msg.type === 'ei_message') { /* нарахування прибрано */ }
      if (msg.type === 'group_typing') { const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId); for (const m of members || []) { if (m.nick !== userNick) { const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify({ type: 'group_typing', groupId: msg.groupId, from: userNick })); } } }
      if (msg.type === 'reaction') { const { msgId, emoji, chatNick, groupId } = msg; const payload = { type: 'reaction', msgId, emoji, from: userNick, chatNick, groupId }; if (groupId) { const { data: ex } = await supabase.from('group_message_reactions').select('id').eq('msg_id', msgId).eq('group_id', groupId).eq('nick', userNick).eq('emoji', emoji).maybeSingle(); if (ex) { await supabase.from('group_message_reactions').delete().eq('id', ex.id); } else { await supabase.from('group_message_reactions').delete().eq('msg_id', msgId).eq('group_id', groupId).eq('nick', userNick); await supabase.from('group_message_reactions').insert({ msg_id: msgId, group_id: groupId, nick: userNick, emoji }); } const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId); for (const m of members || []) { if (m.nick === userNick) continue; const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify(payload)); else await supabase.from('pending_reactions').insert({ msg_id: msgId, emoji, from_nick: userNick, to_nick: m.nick, group_id: groupId, chat_nick: null }); } } else if (chatNick) { const pairKey = [userNick, chatNick].sort().join('|'); const { data: dex } = await supabase.from('direct_message_reactions').select('id').eq('msg_id', msgId).eq('from_nick', userNick).eq('emoji', emoji).maybeSingle(); if (dex) { await supabase.from('direct_message_reactions').delete().eq('id', dex.id); } else { await supabase.from('direct_message_reactions').delete().eq('msg_id', msgId).eq('from_nick', userNick).eq('pair_key', pairKey); await supabase.from('direct_message_reactions').insert({ msg_id: msgId, from_nick: userNick, emoji, pair_key: pairKey }); } const target = onlineUsers.get(chatNick); if (target) target.ws.send(JSON.stringify(payload)); else await supabase.from('pending_reactions').insert({ msg_id: msgId, emoji, from_nick: userNick, to_nick: chatNick, chat_nick: chatNick, group_id: null }); } }
      if (msg.type === 'edit_message') { await supabase.from('messages').update({ content: msg.text }).eq('msg_id', msg.msgId).eq('from_nick', userNick); sendToUser(msg.to, { type: 'edit_message', from: userNick, msgId: msg.msgId, text: msg.text }); }
      if (msg.type === 'edit_group_message') { const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single(); if (!membership) return; await supabase.from('group_messages').update({ content: msg.text }).eq('msg_id', msg.msgId).eq('group_id', msg.groupId).eq('from_nick', userNick); await notifyMembers(msg.groupId, { type: 'edit_group_message', groupId: msg.groupId, msgId: msg.msgId, text: msg.text }, userNick); }
      if (msg.type === 'delete_group_message') { const { data: gMsg } = await supabase.from('group_messages').select('from_nick').eq('msg_id', msg.msgId).single(); if (!gMsg || (gMsg.from_nick !== userNick && !(await isModOrCreator(msg.groupId, userNick)))) return; await supabase.from('group_messages').delete().eq('msg_id', msg.msgId); await notifyMembers(msg.groupId, { type: 'delete_group_message', groupId: msg.groupId, msgId: msg.msgId }, userNick); }
      if (msg.type === 'delete_comment') {
        const { data: c } = await supabase.from('channel_comments').select('from_nick, channel_id, post_id, file_data').eq('id', msg.commentId).single();
        if (!c) return;
        const { data: cm } = await supabase.from('channel_members').select('role').eq('channel_id', c.channel_id).eq('nick', userNick).single();
        const canDel = c.from_nick === userNick || (cm && ['owner', 'admin'].includes(cm.role));
        if (!canDel) return;
        await supabase.from('channel_comment_reactions').delete().eq('comment_id', msg.commentId);
        await supabase.from('channel_comments').delete().eq('id', msg.commentId);
        await removeChannelFile(c.file_data);
        await notifyChannelSubscribers(c.channel_id, { type: 'channel_comment_deleted', channelId: c.channel_id, postId: c.post_id, commentId: msg.commentId }, userNick);
      }
      if (msg.type === 'read_receipt') { await supabase.from('messages').update({ status: 'read' }).eq('to_nick', userNick).eq('from_nick', msg.to); const target = onlineUsers.get(msg.to); if (target) { const { data: readMsgs } = await supabase.from('messages').select('msg_id').eq('to_nick', userNick).eq('from_nick', msg.to).not('msg_id', 'is', null); target.ws.send(JSON.stringify({ type: 'read_receipt', from: userNick, msgIds: (readMsgs || []).map(m => m.msg_id).filter(Boolean) })); } }
      if (msg.type === 'delete_message') { if (!sendToUser(msg.to, { type: 'delete_message', from: userNick, msgId: msg.msgId })) await supabase.from('deleted_messages').insert({ msg_id: msg.msgId, from_nick: userNick, to_nick: msg.to }); }
      if (msg.type === 'typing') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'typing', from: userNick })); }
      if (msg.type === 'ping') { if (userNick && onlineUsers.has(userNick)) onlineUsers.get(userNick).lastSeen = Date.now(); ws.send(JSON.stringify({ type: 'pong' })); }

      if (msg.type === 'call_offer') {
        // Якщо адресат заблокував того, хто дзвонить — не з'єднуємо. Той самий
        // сигнал call_error, що й для інших "недоступний" сценаріїв.
        if (await isBlockedBy(msg.to, userNick)) {
          ws.send(JSON.stringify({ type: 'call_error', error: 'Абонент недоступний' }));
          return;
        }
        // Захист від «дзвінка самому собі»: якщо адресат — інший акаунт на
        // ТОМУ САМОМУ пристрої (спільний FCM-токен), не доставляємо ні WS, ні пуш.
        const fromDev = nickDevices.get(userNick);
        const toDev = nickDevices.get(msg.to);
        if (fromDev && toDev && fromDev === toDev) {
          console.log(`call_offer blocked: ${userNick}->${msg.to} same device ${fromDev}`);
          ws.send(JSON.stringify({ type: 'call_error', error: 'Неможливо дзвонити на цей самий пристрій' }));
          return;
        }
        const target = onlineUsers.get(msg.to);
        // ВАЖЛИВО: сокет міг «померти» (клієнт пішов у фон, code=1006), але ще
        // не бути прибраним із onlineUsers (delete/heartbeat не встигли). Тоді
        // наївний target.ws.send піде в нікуди, а FCM не спрацює — дзвінок
        // зникає безслідно. Тому доставляємо через WS лише якщо сокет ЖИВИЙ.
        const wsAlive = target && target.ws
          && target.ws.readyState === 1 /* WebSocket.OPEN */
          && target.ws.isAlive !== false;
        if (wsAlive) {
          target.ws.send(JSON.stringify({ type: 'call_offer', from: userNick, offer: msg.offer, hasVideo: msg.hasVideo || false }));
        } else {
          if (target) { onlineUsers.delete(msg.to); console.log(`call_offer: ${msg.to} stale socket → FCM`); }
          const hasToken = fcmTokens.has(msg.to);
          if (hasToken) {
            await sendCallPush(msg.to, userNick, msg.hasVideo || false, msg.offer);
          } else {
            ws.send(JSON.stringify({ type: 'call_error', error: `${msg.to} не в мережі` }));
            await supabase.from('call_logs').insert({ from_nick: userNick, to_nick: msg.to, has_video: msg.hasVideo || false, started_at: Date.now(), status: 'missed' });
          }
        }
      }
      if (msg.type === 'call_answer') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_answer', from: userNick, answer: msg.answer })); }
      if (msg.type === 'call_ice') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_ice', from: userNick, candidate: msg.candidate })); }
      // Перемикання аудіо↔відео посеред дзвінка (renegotiation)
      if (msg.type === 'call_renegotiate') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_renegotiate', from: userNick, offer: msg.offer })); }
      if (msg.type === 'call_renegotiate_answer') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_renegotiate_answer', from: userNick, answer: msg.answer })); }
      if (msg.type === 'call_video_state') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_video_state', from: userNick, on: !!msg.on })); }
      if (msg.type === 'call_reject') {
        const target = onlineUsers.get(msg.to);
        if (target) { target.ws.send(JSON.stringify({ type: 'call_reject', from: userNick })); }
        else { await sendFcmPush(msg.to, { type: 'call_end', from_nick: userNick }); }
      }
      if (msg.type === 'call_end') {
        const target = onlineUsers.get(msg.to);
        if (target) { target.ws.send(JSON.stringify({ type: 'call_end', from: userNick })); }
        else { await sendFcmPush(msg.to, { type: 'call_end', from_nick: userNick }); }
      }
    } catch (e) { console.error('Помилка:', e); }
  });
  ws.on('close', (code, reason) => {
    console.log(`[ws] close nick=${userNick || '?'} code=${code} reason=${reason ? reason.toString() : ''}`);
    if (userNick) onlineUsers.delete(userNick);
  });
  ws.on('error', (e) => { console.log(`[ws] error nick=${userNick || '?'}: ${e && e.message}`); });
});

setInterval(() => { const now = Date.now(); for (const [nick, user] of onlineUsers) if (now - user.lastSeen > 60000) onlineUsers.delete(nick); }, 60000);

// Серверний WS-heartbeat: кожні 30с пінгуємо всі сокети; хто не відповів pong
// з минулого циклу — транспорт мертвий (code=1006) → термінуємо й чистимо presence.
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      try { ws.terminate(); } catch (_) {}
      return;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch (_) {}
  });
}, 30000);

// ── Прибирання транзитного сховища (БЕЗПЕЧНО) ──────────────────────────────
// Принцип «сервер = транзит, не архів»: доставлені повідомлення прибираються за TTL,
// і ПАРНО з рядком видаляються байти у Storage (фікс «осиротілих» файлів).
// ЗАПОБІЖНИК: за замовчуванням DRY-RUN — лише ЛОГУЄ, що видалив би, нічого не чіпає.
// Перевіривши логи на реальних даних — постав env CLEANUP_DRY_RUN=false, щоб увімкнути реальне видалення.
const CLEANUP_DRY_RUN = (process.env.CLEANUP_DRY_RUN || 'true') !== 'false';
const DIRECT_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // direct: 7 днів після доставки
const GROUP_TTL_MS = 30 * 24 * 60 * 60 * 1000;   // групи: 30 днів І лише якщо доставлено ВСІМ поточним учасникам

// Видалення файлу каналу (пост/коментар) зі Storage при видаленні запису.
// Безпечний: пропускає base64/порожнє, ковтає помилки, не блокує відповідь.
async function removeChannelFile(...urls) {
  for (const u of urls) {
    const path = storagePathFromUrl(u);
    if (!path) continue; // base64 або не-Storage URL — нічого видаляти
    try { await supabase.storage.from('files').remove([path]); console.log('[channel-cleanup] removed:', path); }
    catch (e) { console.log('[channel-cleanup] remove error:', path, e.message); }
  }
}

function storagePathFromUrl(url) {
  if (!url || typeof url !== 'string') return null;
  const marker = '/object/public/files/';
  const i = url.indexOf(marker);
  if (i === -1) return null;
  const tail = url.slice(i + marker.length);
  try { return decodeURIComponent(tail); } catch (_) { return tail; }
}

// Чи посилається на цей файл ще якийсь рядок (окрім тих, що ЗАРАЗ видаляємо)?
// Це захищає переслані копії: файл прибираємо лише коли на нього більше нема посилань.
async function fileStillReferenced(fileData, delDirectIds, delGroupIds) {
  const { data: m } = await supabase.from('messages').select('id').eq('file_data', fileData);
  if ((m || []).some(r => !delDirectIds.has(r.id))) return true;
  const { data: g } = await supabase.from('group_messages').select('id').eq('file_data', fileData);
  if ((g || []).some(r => !delGroupIds.has(r.id))) return true;
  return false;
}

async function removeOrphanFile(fileData, delDirectIds, delGroupIds) {
  const path = storagePathFromUrl(fileData);
  if (!path) return;
  if (await fileStillReferenced(fileData, delDirectIds, delGroupIds)) return; // ще використовується — не чіпаємо
  if (await fileObjectActive(path)) return; // 2C: ще не всі забрали і TTL не вийшов — лишаємо 2C
  if (CLEANUP_DRY_RUN) { console.log('[cleanup][dry] would remove storage:', path); return; }
  try { await supabase.storage.from('files').remove([path]); console.log('[cleanup] removed storage:', path); }
  catch (e) { console.log('[cleanup] storage remove error:', path, e.message); }
}

async function cleanupDirect() {
  const cutoff = Date.now() - DIRECT_TTL_MS;
  const { data: old } = await supabase.from('messages').select('id, file_data').eq('delivered', true).lt('timestamp', cutoff);
  const rows = old || [];
  if (!rows.length) return;
  const delIds = new Set(rows.map(r => r.id));
  const seen = new Set();
  for (const r of rows) {
    if (!r.file_data || seen.has(r.file_data)) continue;
    seen.add(r.file_data);
    await removeOrphanFile(r.file_data, delIds, new Set());
  }
  if (CLEANUP_DRY_RUN) { console.log(`[cleanup][dry] direct: would delete ${rows.length} rows (${seen.size} unique files)`); return; }
  await supabase.from('messages').delete().eq('delivered', true).lt('timestamp', cutoff);
  console.log(`[cleanup] direct: deleted ${rows.length} rows`);
}

async function cleanupGroups() {
  const cutoff = Date.now() - GROUP_TTL_MS;
  const { data: old } = await supabase.from('group_messages').select('id, group_id, file_data, delivered_to').lt('timestamp', cutoff);
  const rows = old || [];
  if (!rows.length) return;
  const byGroup = new Map();
  for (const r of rows) { if (!byGroup.has(r.group_id)) byGroup.set(r.group_id, []); byGroup.get(r.group_id).push(r); }
  const delRows = [];
  for (const [gid, grows] of byGroup) {
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', gid);
    const memberNicks = (members || []).map(m => m.nick);
    if (!memberNicks.length) continue; // підстрахування: групу без учасників не чіпаємо
    for (const r of grows) {
      const dt = new Set(r.delivered_to || []);
      if (memberNicks.every(n => dt.has(n))) delRows.push(r); // доставлено ВСІМ поточним учасникам
    }
  }
  if (!delRows.length) return;
  const delIds = new Set(delRows.map(r => r.id));
  const seen = new Set();
  for (const r of delRows) {
    if (!r.file_data || seen.has(r.file_data)) continue;
    seen.add(r.file_data);
    await removeOrphanFile(r.file_data, new Set(), delIds);
  }
  if (CLEANUP_DRY_RUN) { console.log(`[cleanup][dry] groups: would delete ${delRows.length} delivered-to-all rows (${seen.size} unique files)`); return; }
  const ids = [...delIds];
  for (let i = 0; i < ids.length; i += 100) {
    await supabase.from('group_messages').delete().in('id', ids.slice(i, i + 100));
  }
  console.log(`[cleanup] groups: deleted ${delRows.length} rows`);
}

// ── 2C: облік завантажень файлів (видаляємо зі Storage лише коли ВСІ забрали АБО вийшов TTL) ──
const FILE_OBJECT_TTL_MS = 30 * 24 * 60 * 60 * 1000; // жорсткий TTL: 30 днів

// Заводимо облік для надісланого файлу: хто має забрати (recipients).
async function trackFileObject(fileData, recipients) {
  const path = storagePathFromUrl(fileData);
  if (!path || !recipients || !recipients.length) return;
  const now = Date.now();
  try {
    await supabase.from('file_objects').upsert({
      storage_path: path, recipients, downloaded_by: [],
      created_at: now, expires_at: now + FILE_OBJECT_TTL_MS,
    }, { onConflict: 'storage_path' });
  } catch (e) { console.log('[2C] trackFileObject error:', e.message); }
}

// true, якщо для шляху є активний облік (ще не всі забрали І TTL не вийшов) → 2A не чіпає.
async function fileObjectActive(path) {
  try {
    const { data } = await supabase.from('file_objects').select('recipients, downloaded_by, expires_at').eq('storage_path', path).limit(1);
    if (!data || !data.length) return false;
    const r = data[0];
    const recips = r.recipients || [];
    const dl = new Set(r.downloaded_by || []);
    const allDownloaded = recips.length > 0 && recips.every(x => dl.has(x));
    const expired = Date.now() > (r.expires_at || 0);
    return !(allDownloaded || expired);
  } catch (_) { return false; }
}

async function cleanupFileObjects() {
  const now = Date.now();
  const { data: rows } = await supabase.from('file_objects').select('storage_path, recipients, downloaded_by, expires_at');
  const list = rows || [];
  if (!list.length) return;
  let removed = 0;
  for (const r of list) {
    const recips = r.recipients || [];
    const dl = new Set(r.downloaded_by || []);
    const allDownloaded = recips.length > 0 && recips.every(x => dl.has(x));
    const expired = now > (r.expires_at || 0);
    if (!allDownloaded && !expired) continue;
    if (CLEANUP_DRY_RUN) {
      console.log(`[cleanup][dry] 2C would remove ${r.storage_path} (allDownloaded=${allDownloaded}, expired=${expired})`);
      continue;
    }
    try { await supabase.storage.from('files').remove([r.storage_path]); } catch (e) { console.log('[2C] remove err:', e.message); }
    await supabase.from('file_objects').delete().eq('storage_path', r.storage_path);
    removed++;
  }
  if (!CLEANUP_DRY_RUN && removed) console.log(`[cleanup] 2C removed ${removed} files`);
}

setInterval(async () => {
  try { await cleanupDirect(); } catch (e) { console.log('[cleanup] direct error:', e.message); }
  try { await cleanupGroups(); } catch (e) { console.log('[cleanup] groups error:', e.message); }
  try { await cleanupFileObjects(); } catch (e) { console.log('[cleanup] fileObjects error:', e.message); }
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`EION сервер запущено на порті ${PORT}`));
