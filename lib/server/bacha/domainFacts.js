"use strict";

/**
 * Factual, non-accusatory domain context for deep analysis (Phase 5, BUG-08).
 *
 * - Reserved names (RFC 2606 / RFC 6761 / RFC 8375): .invalid, .test, .example,
 *   .localhost, .local, .home.arpa, example.com/net/org. They can never be a live
 *   public website, so "phishing page" claims about them are not substantiated.
 * - DNS existence check: resolves only NS/A records of the registrable domain with a
 *   short timeout. It never opens an HTTP connection, never follows redirects and
 *   never fetches content, so it cannot be used for SSRF; a private/loopback answer
 *   is reported (DNS-rebinding indicator) but never contacted.
 * - Each fact says whether it was VERIFIED, FAILED or NOT_CHECKED. A failed lookup is
 *   never presented as "the domain does not exist".
 *
 * None of these facts is counted as negative risk evidence on its own.
 */
const threatIntel = require("./threatIntel");

const RESERVED_TLDS = ["invalid", "test", "example", "localhost", "local", "internal"];
const RESERVED_SUFFIXES = ["home.arpa"];
const RESERVED_DOMAINS = ["example.com", "example.net", "example.org"];
const DNS_TIMEOUT_MS = 2000;
const MAX_DOMAINS = 3;

function reservedReason(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  const tld = h.split(".").pop();
  if (RESERVED_TLDS.includes(tld)) return `.${tld}`;
  if (RESERVED_SUFFIXES.some((s) => h === s || h.endsWith(`.${s}`))) return ".home.arpa";
  const reg = RESERVED_DOMAINS.find((d) => h === d || h.endsWith(`.${d}`));
  return reg || null;
}

function isNonPublicAddress(ip) {
  const v = String(ip);
  if (/^(10\.|127\.|0\.|169\.254\.|192\.168\.)/.test(v)) return true;
  const m = /^172\.(\d+)\./.exec(v);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(v)) return true; // CGNAT
  const low = v.toLowerCase();
  return low === "::1" || low.startsWith("fc") || low.startsWith("fd") || low.startsWith("fe80");
}

/** Default resolver: node:dns with one try and a hard timeout. */
async function defaultResolve(domain) {
  const { Resolver } = require("node:dns").promises;
  const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  const withTimeout = (p) => Promise.race([
    p, new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("dns timeout"), { code: "ETIMEOUT" })), DNS_TIMEOUT_MS + 200)),
  ]);
  try {
    const addrs = await withTimeout(resolver.resolve4(domain));
    return { status: "EXISTS", addresses: addrs.slice(0, 8) };
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) {
      try {
        await withTimeout(resolver.resolveNs(domain));
        return { status: "EXISTS", addresses: [] }; // delegated, no A record
      } catch (e2) {
        if (e2 && (e2.code === "ENOTFOUND" || e2.code === "ENODATA")) return { status: "NXDOMAIN" };
        return { status: "FAILED" };
      }
    }
    return { status: "FAILED" };
  }
}

/**
 * @returns {{ signals: object[], limitations: string[], promptFacts: string[], facts: object[] }}
 */
async function assessUrlDomains(text, { resolve, enabled = false } = {}) {
  const candidates = threatIntel.extractCandidateIndicators(text || "")
    .filter((c) => c.type === threatIntel.INDICATOR_TYPES.URL || c.type === threatIntel.INDICATOR_TYPES.DOMAIN);
  const domains = [...new Set(candidates.map((c) => c.domainOnly || c.canonicalValue).filter(Boolean))].slice(0, MAX_DOMAINS);
  const signals = [];
  const limitations = [];
  const promptFacts = [];
  const facts = [];

  for (const host of domains) {
    const reserved = reservedReason(host);
    if (reserved) {
      facts.push({ host, reserved, dns: "NOT_CHECKED" });
      signals.push({
        id: "url_reserved_domain",
        title: "Rezervovaná doména, nemůže být veřejný web",
        description: `Adresa používá rezervované jméno (${reserved}), které ve veřejném internetu nemůže existovat. Odkaz proto nevede na skutečnou stránku; sama zpráva tím ale bezpečná není.`,
        severity: "LOW",
        isPositive: false,
        source: "URL_FACT",
        evidenceGroup: "URL_STRUCTURE",
      });
      promptFacts.push(`Doména ${host} používá rezervované jméno ${reserved} (RFC 2606/6761): ve veřejném DNS nemůže existovat. Netvrď, že jde o aktivní phishingovou stránku; posuď jen text zprávy.`);
      continue;
    }
    if (!enabled) {
      facts.push({ host, dns: "NOT_CHECKED" });
      continue;
    }
    let r;
    try { r = await resolve(host); } catch { r = { status: "FAILED" }; }
    facts.push({ host, dns: r.status });
    if (r.status === "NXDOMAIN") {
      signals.push({
        id: "url_domain_not_found",
        title: "Doména se v DNS nenašla",
        description: "Doména z odkazu momentálně v DNS neexistuje, odkaz tedy nyní nikam nevede. Může jít o zrušenou nebo dosud neaktivní doménu.",
        severity: "LOW",
        isPositive: false,
        source: "URL_FACT",
        evidenceGroup: "URL_STRUCTURE",
      });
      promptFacts.push(`DNS dotaz na ${host} vrátil NXDOMAIN (doména teď neexistuje).`);
    } else if (r.status === "EXISTS" && (r.addresses || []).some(isNonPublicAddress)) {
      signals.push({
        id: "url_domain_private_address",
        title: "Doména ukazuje na neveřejnou adresu",
        description: "Veřejná doména se překládá na interní nebo místní IP adresu, což běžné weby nedělají.",
        severity: "CAUTION",
        isPositive: false,
        source: "URL_METADATA",
        evidenceGroup: "URL_STRUCTURE",
      });
      promptFacts.push(`Doména ${host} se v DNS překládá na neveřejnou IP adresu.`);
    } else if (r.status === "FAILED") {
      limitations.push("Existenci domény se nepodařilo ověřit (DNS dotaz selhal).");
    }
  }
  return { signals, limitations: limitations.slice(0, 1), promptFacts, facts };
}

module.exports = { assessUrlDomains, defaultResolve, reservedReason, isNonPublicAddress, RESERVED_TLDS };
