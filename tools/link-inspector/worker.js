"use strict";

/* Separate low-privilege worker. Deploy only behind authenticated TLS and enforced
 * egress isolation (no internal/VPC/metadata access). Never run in the main API. */
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const dns = require("node:dns").promises;
const crypto = require("node:crypto");

const MAX_REDIRECTS = 4;
const MAX_HTML = 32768;
const TOTAL_MS = 6500;

function publicIpv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a,b,c] = ip.split(".").map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 192 && b === 88 && c === 99) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) || ip === "168.63.129.16");
}

function safeUrl(raw, base) {
  if (typeof raw !== "string" || raw.length > 2048) throw new Error("invalid URL");
  const u = new URL(raw, base);
  if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || u.port ||
      net.isIP(u.hostname) || !u.hostname.includes(".") || !/^[a-z0-9.-]+$/i.test(u.hostname) ||
      u.hostname.endsWith(".") ||
      /(?:^|\.)(localhost|local|internal|test|example|invalid|onion|home\.arpa)$/i.test(u.hostname))
    throw new Error("restricted URL");
  const queryOmitted = !!u.search || !!u.hash;
  u.search = ""; u.hash = "";
  return { url: u, queryOmitted };
}

async function bounded(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("deadline")), ms);
  })]); } finally { clearTimeout(timer); }
}

async function resolvePublic(host, resolve4 = dns.resolve4.bind(dns), timeout = 1000) {
  const ips = await bounded(resolve4(host), timeout);
  if (!Array.isArray(ips) || ips.length === 0 || ips.length > 32 || !ips.every(publicIpv4))
    throw new Error("non-public DNS answer");
  return ips[0];
}

/** A connection is pinned to the validated IP; no second DNS lookup or proxy. */
function requestPinned(u, ip, ms) {
  return new Promise((resolve, reject) => {
    const transport = u.protocol === "https:" ? https : http;
    let settled = false, timer;
    function done(err, result) {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (err) reject(err); else resolve(result);
    }
    const req = transport.request(u, {
      method: "GET", agent: false, family: 4, autoSelectFamily: false,
      maxHeaderSize: 8192, rejectUnauthorized: true,
      lookup: (_host, options, cb) => options.all ? cb(null, [{ address: ip, family: 4 }]) : cb(null, ip, 4),
      headers: { "User-Agent": "Bacha-LinkInspector/1.0", Accept: "text/html", "Accept-Encoding": "identity" },
    }, (res) => {
      const status = res.statusCode || 0;
      const location = typeof res.headers.location === "string" ? res.headers.location : null;
      if ([301,302,303,307,308].includes(status)) {
        done(null, { status, location, html: "", truncated: false }); res.destroy(); return;
      }
      if (status < 200 || status >= 300) { done(new Error("HTTP failure")); res.destroy(); return; }
      if (!/^text\/html(?:;|$)/i.test(res.headers["content-type"] || "") ||
          (res.headers["content-encoding"] && res.headers["content-encoding"] !== "identity")) {
        done(null, { status, html: "", truncated: true }); res.destroy(); return;
      }
      let count = 0; const chunks = [];
      res.on("data", (chunk) => {
        const remaining = MAX_HTML - count;
        if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
        count += chunk.length;
        if (count >= MAX_HTML) {
          done(null, { status, html: Buffer.concat(chunks).toString("utf8"), truncated: true }); res.destroy();
        }
      });
      res.on("end", () => done(null, { status, html: Buffer.concat(chunks).toString("utf8"), truncated: false }));
      res.on("error", (e) => done(e));
    });
    req.on("error", (e) => done(e));
    timer = setTimeout(() => { done(new Error("deadline")); req.destroy(); }, ms);
    req.end();
  });
}

/** Static bounded HTML inspection; never execute scripts, CSS, load images or submit forms. */
function formFeatures(html, url) {
  const text = String(html || "").slice(0, MAX_HTML);
  const passwordForm = /<input\b[^>]{0,512}\btype\s*=\s*["']?password\b/i.test(text);
  const cardForm = /<input\b[^>]{0,512}\b(?:autocomplete\s*=\s*["']?cc-number\b|name\s*=\s*["']?(?:cardnumber|card_number|cvv|cvc)\b)/i.test(text);
  let externalForm = false;
  for (const m of text.matchAll(/<form\b[^>]{0,512}\baction\s*=\s*["']([^"']{1,512})["']/gi)) {
    try { const destination = new URL(m[1], url);
      if (["http:","https:"].includes(destination.protocol) && destination.origin !== url.origin) externalForm = true;
    } catch { /* unknown action */ }
  }
  return { passwordForm, cardForm, externalForm };
}
async function inspect(raw, { resolve4, request = requestPinned, now = Date.now } = {}) {
  try {
    const deadline = now() + TOTAL_MS;
    let { url, queryOmitted } = safeUrl(raw);
    const initial = url.hostname;
    const visited = new Set();
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (visited.has(url.href) || deadline <= now()) throw new Error("limit");
      visited.add(url.href);
      const ip = await resolvePublic(url.hostname, resolve4, Math.min(1000, Math.max(1, deadline - now())));
      const left = deadline - now();
      if (left <= 0) throw new Error("deadline");
      const res = await request(url, ip, left);
      if ([301,302,303,307,308].includes(res.status)) {
        if (hop === MAX_REDIRECTS || !res.location) throw new Error("redirect limit");
        const next = safeUrl(res.location, url);
        queryOmitted ||= next.queryOmitted; url = next.url; continue;
      }
      return { checked: true, redirects: hop, changedHost: url.hostname !== initial,
        queryOmitted, truncated: res.truncated === true, ...formFeatures(res.html, url) };
    }
  } catch { /* Do not log submitted URLs, DNS records or HTML. */ }
  return { checked: false };
}

function serve({ token, port = 8080 }) {
  if (!token || token.length < 32) throw new Error("LINK_INSPECTOR_TOKEN required");
  const expected = Buffer.from("Bearer " + token);
  let active = 0;
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 10000, headersTimeout: 3000 }, async (req, res) => {
    const auth = Buffer.from(req.headers.authorization || "");
    if (auth.length !== expected.length || !crypto.timingSafeEqual(auth, expected) || req.method !== "POST" || req.url !== "/inspect") {
      res.writeHead(403); res.end(); return;
    }
    if (active >= 2) { res.writeHead(429); res.end(); return; }
    active++;
    try {
      let size = 0; const chunks = [];
      for await (const chunk of req) {
        size += chunk.length; if (size > 4096) throw new Error("size");
        chunks.push(chunk);
      }
      const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const result = await inspect(data.url);
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(JSON.stringify(result));
    } catch { res.writeHead(400); res.end(); } finally { active--; }
  });
  server.maxConnections = 16;
  server.listen(port, "0.0.0.0");
  return server;
}
if (require.main === module) serve({ token: process.env.LINK_INSPECTOR_TOKEN, port: Number(process.env.PORT || 8080) });
module.exports = { publicIpv4, safeUrl, resolvePublic, formFeatures, inspect, serve };
