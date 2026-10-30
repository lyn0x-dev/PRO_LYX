'use strict';
// PRO-LYX — Zero-dependency Shadowsocks server (AEAD, aes-256-gcm, TCP) for Node.js 16+
// Optimized for Katabump / Pterodactyl panels: auto-detects port and public IP.
// By Lynox & KHALED
//
// Env vars (all optional):
//   PORT / SERVER_PORT / SS_PORT  - listen port (auto from panel)
//   SS_BIND                       - bind address (default 0.0.0.0)
//   SS_HOST                       - public host override (default: auto-detect)
//   SS_PASSWORD                   - password override (default: config or generated)
//   SS_MAX_CONN                   - max simultaneous connections (default 1024)
//   ALLOW_PRIVATE=1               - allow connections to private IPs (default: off)
//
// config.json (all fields optional):
//   { "password": "...", "host": "", "port": 8388 }

const net = require('net');
const dns = require('dns');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');

// ---- Load config.json ----
let file = {};
try { file = require('./config.json'); } catch (_) {}

// ---- Port detection: panel env vars take priority ----
const PORT_ENV = process.env.SS_PORT
  || process.env.SERVER_PORT
  || process.env.ALLOCATION_PORT
  || process.env.PORT;
const PORT = +(PORT_ENV || file.port || 8388);
const PORT_FROM = PORT_ENV ? 'env (panel)' : (file.port ? 'config.json' : 'default fallback');

// ---- Bind address (always 0.0.0.0 on panels) ----
const BIND = process.env.SS_BIND || '0.0.0.0';

// ---- Public host override (optional) ----
const PUBLIC_HOST = (process.env.SS_HOST || file.host || '').trim();

// ---- Security / limits ----
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';
const MAX_CONN = Math.max(1, +(process.env.SS_MAX_CONN || 1024));
const IDLE_MS = 5 * 60 * 1000;      // idle timeout for client and target sockets
const DRAIN_MS = 60 * 1000;         // how long to silently hold a failed-auth connection
const QUEUE_MAX = 256 * 1024;       // max bytes buffered while the target is connecting
const SALT_TTL = 60 * 60 * 1000;    // replay-protection memory (1 hour)
const SALT_MAX = 200000;            // replay-protection cache size cap

// ---- Protocol constants ----
const METHOD = 'aes-256-gcm';
const KEYLEN = 32, SALTLEN = 32, TAG = 16, MAXCHUNK = 0x3fff;

// ---- Password ----
function getPassword() {
  const given = process.env.SS_PASSWORD || file.password;
  if (given) return given;
  const f = path.join(__dirname, '.ss-password');
  try { return fs.readFileSync(f, 'utf8').trim(); } catch (_) {}
  const gen = crypto.randomBytes(18).toString('base64url');
  try { fs.writeFileSync(f, gen, { mode: 0o600 }); } catch (_) {
    console.warn('⚠ Could not save .ss-password; password will change on restart');
  }
  return gen;
}
const PASSWORD = getPassword();
if (PASSWORD.length < 8) {
  console.error('✗ Password must be at least 8 characters');
  process.exit(1);
}

// ---- Key derivation (EVP_BytesToKey MD5) ----
function deriveKey(pw, len) {
  let out = Buffer.alloc(0), prev = Buffer.alloc(0);
  while (out.length < len) {
    prev = crypto.createHash('md5').update(Buffer.concat([prev, Buffer.from(pw)])).digest();
    out = Buffer.concat([out, prev]);
  }
  return out.subarray(0, len);
}
const MASTER = deriveKey(PASSWORD, KEYLEN);
const subkey = (salt) => Buffer.from(crypto.hkdfSync('sha1', MASTER, salt, 'ss-subkey', KEYLEN));
function incNonce(n) { for (let i = 0; i < n.length; i++) { n[i] = (n[i] + 1) & 255; if (n[i] !== 0) break; } }

// ---- Crypto ----
class Decryptor {
  constructor() {
    this.buf = Buffer.alloc(0); this.key = null; this.salt = null;
    this.nonce = Buffer.alloc(12); this.len = -1; this.authed = false;
  }
  open(data) {
    const d = crypto.createDecipheriv(METHOD, this.key, this.nonce, { authTagLength: TAG });
    d.setAuthTag(data.subarray(data.length - TAG));
    const out = Buffer.concat([d.update(data.subarray(0, data.length - TAG)), d.final()]);
    incNonce(this.nonce);
    this.authed = true; // at least one chunk authenticated with the right key
    return out;
  }
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    const out = [];
    if (!this.key) {
      if (this.buf.length < SALTLEN) return out;
      this.salt = Buffer.from(this.buf.subarray(0, SALTLEN));
      this.key = subkey(this.salt);
      this.buf = this.buf.subarray(SALTLEN);
    }
    for (;;) {
      if (this.len < 0) {
        if (this.buf.length < 2 + TAG) break;
        this.len = this.open(this.buf.subarray(0, 2 + TAG)).readUInt16BE(0) & MAXCHUNK;
        this.buf = this.buf.subarray(2 + TAG);
      }
      if (this.buf.length < this.len + TAG) break;
      out.push(this.open(this.buf.subarray(0, this.len + TAG)));
      this.buf = this.buf.subarray(this.len + TAG);
      this.len = -1;
    }
    return out;
  }
}

class Encryptor {
  constructor() { this.salt = crypto.randomBytes(SALTLEN); this.key = subkey(this.salt); this.nonce = Buffer.alloc(12); this.sent = false; }
  seal(p) {
    const c = crypto.createCipheriv(METHOD, this.key, this.nonce, { authTagLength: TAG });
    const out = Buffer.concat([c.update(p), c.final(), c.getAuthTag()]);
    incNonce(this.nonce);
    return out;
  }
  encode(data) {
    const parts = [];
    if (!this.sent) { parts.push(this.salt); this.sent = true; }
    for (let i = 0; i < data.length; i += MAXCHUNK) {
      const p = data.subarray(i, i + MAXCHUNK);
      const l = Buffer.alloc(2); l.writeUInt16BE(p.length);
      parts.push(this.seal(l), this.seal(p));
    }
    return Buffer.concat(parts);
  }
}

// ---- Replay protection (remember salts of authenticated connections) ----
const seenSalts = new Map(); // insertion order == time order
function seenSalt(salt) {
  const k = salt.toString('base64');
  if (seenSalts.has(k)) return true;
  if (seenSalts.size >= SALT_MAX) seenSalts.delete(seenSalts.keys().next().value);
  seenSalts.set(k, Date.now());
  return false;
}
setInterval(() => {
  const cut = Date.now() - SALT_TTL;
  for (const [k, t] of seenSalts) { if (t > cut) break; seenSalts.delete(k); }
}, 60 * 1000).unref();

// ---- Private / reserved IP check ----
function isPrivateV4(o) {
  const [a, b, c] = o;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113);
}

// Expand any valid IPv6 text form into 8 numeric groups (null if invalid)
function expandV6(ip) {
  let s = ip.toLowerCase();
  const z = s.indexOf('%');
  if (z >= 0) s = s.slice(0, z);
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    if (!net.isIPv4(m[2])) return null;
    const o = m[2].split('.').map(Number);
    s = m[1] + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...tail];
  } else groups = head;
  if (groups.length !== 8) return null;
  const out = groups.map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return out.some(Number.isNaN) ? null : out;
}

function isPrivate(ip) {
  if (net.isIPv4(ip)) return isPrivateV4(ip.split('.').map(Number));
  const g = net.isIPv6(ip.split('%')[0]) ? expandV6(ip) : null;
  if (!g) return true; // unparseable → treat as blocked
  const v4 = (hi, lo) => isPrivateV4([hi >> 8, hi & 255, lo >> 8, lo & 255]);
  const zeros = (from, to) => g.slice(from, to).every((x) => x === 0);
  if (zeros(0, 6)) return v4(g[6], g[7]);                                   // ::, ::1, ::a.b.c.d
  if (zeros(0, 5) && g[5] === 0xffff) return v4(g[6], g[7]);                // ::ffff:a.b.c.d (mapped)
  if (g[0] === 0x64 && g[1] === 0xff9b && zeros(2, 6)) return v4(g[6], g[7]); // NAT64
  if (g[0] === 0x2002) return v4(g[1], g[2]);                               // 6to4
  if (g[0] === 0x2001 && (g[1] === 0 || g[1] === 0xdb8)) return true;       // Teredo / documentation
  return (g[0] & 0xfe00) === 0xfc00      // fc00::/7  unique local
    || (g[0] & 0xffc0) === 0xfe80        // fe80::/10 link-local
    || (g[0] & 0xffc0) === 0xfec0        // fec0::/10 site-local
    || (g[0] & 0xff00) === 0xff00;       // ff00::/8  multicast
}

// ---- Shadowsocks target header ----
function parseTarget(p) {
  const atyp = p[0];
  let host, off;
  if (atyp === 1 && p.length >= 7) { host = [...p.subarray(1, 5)].join('.'); off = 5; }
  else if (atyp === 3 && p.length >= 2 && p.length >= 4 + p[1]) { host = p.toString('utf8', 2, 2 + p[1]); off = 2 + p[1]; }
  else if (atyp === 4 && p.length >= 19) {
    const g = []; for (let i = 0; i < 16; i += 2) g.push(p.readUInt16BE(1 + i).toString(16));
    host = g.join(':'); off = 17;
  } else return null;
  return { host, port: p.readUInt16BE(off), rest: p.subarray(off + 2) };
}

// ---- Multi-service public IP detection ----
function detectPublicIP(cb) {
  const services = [
    'https://api.ipify.org',
    'https://icanhazip.com',
    'https://ifconfig.me/ip',
    'https://checkip.amazonaws.com',
    'https://ipinfo.io/ip'
  ];
  let i = 0, done = false;
  const finish = (ip) => { if (!done) { done = true; cb(ip); } };
  const tryNext = () => {
    if (done) return;
    if (i >= services.length) return finish('');
    const url = services[i++];
    let moved = false; // makes sure each service advances the list exactly once
    const next = () => { if (moved) return; moved = true; tryNext(); };
    let req;
    try {
      req = https.get(url, { timeout: 5000 }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return next(); }
        let d = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { d += c; if (d.length > 256) req.destroy(); });
        res.on('end', () => {
          const ip = d.trim();
          if (net.isIP(ip) && !isPrivate(ip)) { moved = true; finish(ip); }
          else next();
        });
        res.on('error', next);
        res.on('close', next);
      });
      req.on('error', next);
      req.on('timeout', () => { req.destroy(); next(); });
    } catch (_) { next(); }
  };
  tryNext();
}

// ---- Server ----
const server = net.createServer((sock) => {
  const dec = new Decryptor(), enc = new Encryptor();
  const queue = [];
  let queued = 0;
  let remote = null, ready = false, gotHeader = false;
  let closed = false, dead = false, saltChecked = false;

  const kill = () => {
    if (closed) return;
    closed = true;
    queue.length = 0; queued = 0;
    sock.destroy();
    if (remote) remote.destroy();
  };
  // Failed authentication / replay: don't close right away (that would fingerprint
  // the server to probes). Silently swallow data until the short timeout fires.
  const quarantine = () => {
    if (dead) return;
    dead = true;
    dec.buf = Buffer.alloc(0);
    queue.length = 0; queued = 0;
    sock.setTimeout(DRAIN_MS);
  };

  sock.setNoDelay(true);
  sock.setTimeout(IDLE_MS, kill);
  sock.on('error', kill);
  sock.on('close', kill);
  sock.on('drain', () => { if (remote && !closed) remote.resume(); });

  // client → target (with backpressure)
  const forward = (buf) => {
    if (!buf.length || closed) return;
    if (ready) {
      if (!remote.write(buf)) sock.pause();
    } else {
      queue.push(buf);
      queued += buf.length;
      if (queued > QUEUE_MAX) sock.pause();
    }
  };

  const connectRemote = (host, port) => {
    if (!host || host.length > 255) return kill();
    try {
      dns.lookup(host, (err, addr) => {
        if (closed) return; // client left while we were resolving
        if (err || !addr || (!ALLOW_PRIVATE && isPrivate(addr))) return kill();
        try { remote = net.connect({ host: addr, port }); } catch (_) { return kill(); }
        remote.setNoDelay(true);
        remote.setTimeout(IDLE_MS, kill);
        remote.on('error', kill);
        remote.on('close', kill);
        remote.on('drain', () => { if (!closed) sock.resume(); });
        remote.on('connect', () => {
          if (closed) return;
          ready = true;
          let ok = true;
          for (const b of queue) ok = remote.write(b) && ok;
          queue.length = 0; queued = 0;
          if (ok) sock.resume();
        });
        remote.on('data', (d) => {
          if (closed) return;
          if (!sock.write(enc.encode(d))) remote.pause();
        });
      });
    } catch (_) { kill(); }
  };

  sock.on('data', (chunk) => {
    if (closed || dead) return;
    let plains;
    try { plains = dec.push(chunk); } catch (_) { return quarantine(); }

    // replay check: only salts of successfully authenticated connections are remembered
    if (dec.authed && !saltChecked) {
      saltChecked = true;
      if (seenSalt(dec.salt)) return quarantine();
    }

    for (const p of plains) {
      if (gotHeader) { forward(p); continue; }
      const t = parseTarget(p);
      if (!t || !t.port) return kill(); // authenticated but malformed / invalid port
      gotHeader = true;
      forward(t.rest);
      connectRemote(t.host, t.port);
    }
  });
});

server.maxConnections = MAX_CONN;

server.on('error', (e) => {
  if (e.code === 'EADDRNOTAVAIL' && BIND !== '0.0.0.0') {
    console.warn(`⚠ Address ${BIND} is not local, falling back to 0.0.0.0`);
    server.listen(PORT, '0.0.0.0');
  } else {
    console.error('✗ Server error:', e.message);
    process.exit(1);
  }
});

// Last-resort safety net: log instead of dying on an unexpected error
process.on('uncaughtException', (e) => console.error('⚠ Unexpected error:', e && e.message));
process.on('unhandledRejection', (e) => console.error('⚠ Unhandled rejection:', e && e.message));

// ---- Startup banner ----
const SEP = '─'.repeat(62);

server.on('listening', () => {
  const a = server.address();
  const actualPort = a.port;

  console.log('');
  console.log('╔' + '═'.repeat(60) + '╗');
  console.log('║' + '  PRO-LYX — Shadowsocks Proxy by Lynox & KHALED'.padEnd(60) + '║');
  console.log('╚' + '═'.repeat(60) + '╝');
  console.log('  Method    : ' + METHOD);
  console.log('  Password  : ' + PASSWORD);
  console.log('  Local     : ' + a.address + ':' + actualPort);
  console.log('  Port src  : ' + PORT_FROM);
  console.log('  Max conn  : ' + MAX_CONN);
  console.log(SEP);
  console.log('  Detecting public IP...');

  detectPublicIP((detectedIP) => {
    const host = PUBLIC_HOST || detectedIP;
    const src = PUBLIC_HOST ? 'config/env' : 'auto-detected';

    if (PUBLIC_HOST && detectedIP && PUBLIC_HOST !== detectedIP) {
      console.log('  ⚠ Config host (' + PUBLIC_HOST + ') differs from detected IP (' + detectedIP + ')');
      console.log('    Using config value. Clear "host" in config.json to auto-use detected IP.');
    }

    console.log('');

    if (host) {
      const userinfo = Buffer.from(METHOD + ':' + PASSWORD).toString('base64url');
      const link = 'ss://' + userinfo + '@' + host + ':' + actualPort + '#PRO-LYX';

      console.log('  Public    : ' + host + '  (' + src + ')');
      console.log(SEP);
      console.log('  ✅ Import this link in your Shadowsocks app:');
      console.log('');
      console.log('  ' + link);
      console.log('');
    } else {
      console.log('  Public    : ❌ could not detect');
      console.log(SEP);
      console.log('  Enter manually in your app:');
      console.log('    Server   : <your Katabump node IP>');
      console.log('    Port     : ' + actualPort);
      console.log('    Method   : ' + METHOD);
      console.log('    Password : ' + PASSWORD);
      console.log('');
    }

    console.log(SEP);
    console.log('  ⚠ Reminders:');
    console.log('   • Renew your Katabump server every 4 days.');
    console.log('   • Make sure your allocation is TCP (not HTTP-only).');
    console.log('   • This is Shadowsocks, not MTProto — use a Shadowsocks app.');
    console.log('═'.repeat(62));
    console.log('');
  });
});

// ---- Warn if port looks like fallback ----
if (!PORT_ENV && !file.port) {
  console.log('⚠ No PORT env var or config port found. Falling back to ' + PORT + '.');
  console.log('  Set PORT env or config.json port to match your panel allocation.');
}

server.listen(PORT, BIND);
