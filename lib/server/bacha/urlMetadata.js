"use strict";

const { getDomain } = require("tldts");
const { isIP } = require("node:net");

const REGISTRIES = Object.freeze({
  cz: "https://rdap.nic.cz/domain/",
  com: "https://rdap.verisign.com/com/v1/domain/",
  net: "https://rdap.verisign.com/net/v1/domain/",
});
const MAX_RESPONSE = 256 * 1024;
const LOOKUP_TIMEOUT = 3000;

function normalizedPublicDomain(host) {
  if (typeof host !== "string" || host.length > 253 || isIP(host) || !/^[a-z0-9.-]+$/i.test(host)) return null;
  const domain = getDomain(host, { allowPrivateDomains: false });
  return domain && REGISTRIES[domain.split(".").at(-1)] ? domain.toLowerCase() : null;
}
async function readBoundedJson(res, max = MAX_RESPONSE) {
  const reader = res.body?.getReader();
  if (!reader) throw new Error("Missing body");
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > max) throw new Error("Response too large");
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } finally {
    await reader.cancel().catch(() => {});
  }
}
function registrationAge(data, domain, now = Date.now()) {
  if (data?.objectClassName !== "domain" || String(data.ldhName || "").toLowerCase() !== domain) return null;
  const dates = (Array.isArray(data.events) ? data.events : []).filter((e) => e?.eventAction === "registration")
    .map((e) => Date.parse(e.eventDate)).filter((d) => Number.isFinite(d) && d <= now);
  if (!dates.length) return null;
  // Multiple conflicting registration dates are not reliable enough.
  if (Math.max(...dates) - Math.min(...dates) > 86400000) return null;
  return Math.floor((now - dates[0]) / 86400000);
}
async function lookupDomainAge(host, { fetchImpl = fetch, now = Date.now(), enabled = false } = {}) {
  if (!enabled) return { checked: false };
  const domain = normalizedPublicDomain(host);
  if (!domain) return { checked: false };
  try {
    const res = await fetchImpl(REGISTRIES[domain.split(".").at(-1)] + encodeURIComponent(domain), {
      method: "GET", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(LOOKUP_TIMEOUT),
      headers: { Accept: "application/rdap+json" },
    });
    if (!res.ok) return { checked: false };
    const ageDays = registrationAge(await readBoundedJson(res), domain, now);
    return ageDays === null ? { checked: false } : { checked: true, ageDays };
  } catch { return { checked: false }; }
}

/** Never fetch the submitted URL from the main API process. Only call an operator-configured isolated worker. */
async function inspectThroughWorker(raw, { fetchImpl = fetch, endpoint, token } = {}) {
  if (!endpoint || !token || token.length < 32) return { checked: false };
  try {
    const target = new URL(raw);
    const worker = new URL(endpoint);
    if (!["http:", "https:"].includes(target.protocol) || target.username || target.password ||
        worker.protocol !== "https:" || worker.username || worker.password || worker.search || worker.hash) return { checked: false };
    // Queries and fragments may contain personal tokens, and are not inspected.
    const stripped = !!target.search || !!target.hash;
    target.search = ""; target.hash = "";
    const res = await fetchImpl(worker, {
      method: "POST", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(8000),
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify({ url: target.href }),
    });
    if (!res.ok) return { checked: false };
    const body = await readBoundedJson(res, 4096);
    if (body?.checked !== true || !Number.isInteger(body.redirects) || body.redirects < 0 || body.redirects > 4) return { checked: false };
    return { checked: true, queryOmitted: stripped || body.queryOmitted === true,
      redirects: body.redirects, changedHost: body.changedHost === true,
      passwordForm: body.passwordForm === true, externalForm: body.externalForm === true,
      cardForm: body.cardForm === true, truncated: body.truncated === true };
  } catch { return { checked: false }; }
}
function metadataSignals(age, inspection) {
  const signals = [];
  function add(id, title, description, severity, evidenceGroup) {
    signals.push({ id, title, description, severity, isPositive: false, source: "URL_METADATA", evidenceGroup });
  }
  if (age.checked && age.ageDays <= 30) add("metadata_new_domain", "Nově registrovaná doména",
    "Registr uvádí stáří nejvýše 30 dní. Samo o sobě to neznamená podvod.", "LOW", "DOMAIN_AGE");
  if (inspection.checked && inspection.changedHost) add("metadata_redirect_host", "Přesměrování na jiný host",
    "Omezená kontrola zaznamenala přesměrování na jiný host. Ověřte cílovou adresu.", "LOW", "REDIRECT");
  if (inspection.checked && inspection.externalForm && (inspection.passwordForm || inspection.cardForm))
    add("metadata_external_sensitive_form", "Citlivý formulář na jiné adrese",
      "V omezeném vzorku HTML byl nalezen citlivý formulář a externí cíl formuláře. Ověřte příjemce.", "CAUTION", "FORM");
  return signals;
}

module.exports = { lookupDomainAge, inspectThroughWorker, normalizedPublicDomain, registrationAge, metadataSignals };
