import fs from "node:fs";
import path from "node:path";

const secretNames = new Set([
  "RECAPTCHA_SECRET_KEY", "RESEND_API_KEY", "FIREBASE_ADMIN_PRIVATE_KEY",
  "GEMINI_API_KEY", "THREAT_INTEL_HMAC_SECRET", "WEB_RISK_API_KEY",
  "PHISHTANK_API_KEY", "URLHAUS_API_KEY", "PLAY_SERVICE_ACCOUNT_PRIVATE_KEY",
  "CRON_SECRET",
]);
const candidates = [".env", ".env.local", ".env.production", ".env.production.local"];
const secrets = [];

for (const filename of candidates) {
  if (!fs.existsSync(filename)) continue;
  const contents = fs.readFileSync(filename, "utf8");
  for (const line of contents.split(/\r?\n/)) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (!match || !secretNames.has(match[1])) continue;
    const value = match[2].replace(/^['"]|['"]$/g, "").replace(/\\n/g, "\n");
    if (value && !value.includes("REPLACE_WITH_VERCEL_SECRET")) secrets.push([match[1], value]);
  }
}

const staticDir = path.join(".next", "static");
if (!fs.existsSync(staticDir)) throw new Error("Missing .next/static; run the production build first.");
const files = [];
function visit(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) visit(target);
    else files.push(target);
  }
}
visit(staticDir);

const leaked = new Set();
for (const file of files) {
  const contents = fs.readFileSync(file);
  for (const [name, value] of secrets) {
    if (Buffer.byteLength(value) >= 8 && contents.includes(Buffer.from(value))) leaked.add(name);
  }
}
if (leaked.size) throw new Error(`Server secrets found in client assets: ${[...leaked].join(", ")}`);
console.log(`Client bundle secret scan passed (${files.length} assets checked).`);
