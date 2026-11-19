import { NextRequest, NextResponse } from "next/server";
import { firestore } from "@/lib/server/bacha/firebaseAdmin";
import { sendInterestConfirmation } from "@/lib/server/interestEmail";
import {
  normalizeTesterEmail, createToken,
  enforceInterestLimits, createPendingVerification,
} from "@/lib/server/interestVerification";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function reply(status: number, ok: boolean, message: string) {
  return NextResponse.json({ ok, message }, {
    status,
    headers: { "Cache-Control": "no-store, max-age=0" },
  });
}

function allowedOrigins() {
  const configured = [
    process.env.APP_ORIGIN || "https://bacha.petrvurm.cz",
    ...(process.env.ALLOWED_ORIGINS || "").split(","),
  ].map((origin) => origin.trim().replace(/\/$/, "")).filter(Boolean);
  if (process.env.NODE_ENV !== "production")
    configured.push("http://localhost:3000", "http://127.0.0.1:3000");
  return new Set(configured);
}

function clientAddress(request: NextRequest) {
  const direct = request.headers.get("x-real-ip")?.trim();
  if (direct) return direct;
  const forwarded = request.headers.get("x-forwarded-for")
    ?.split(",").map((part) => part.trim()).filter(Boolean);
  return forwarded?.at(-1) || "unknown";
}

async function parseSubmission(request: NextRequest) {
  const type = request.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    const data = (await request.json()) as Record<string, unknown>;
    return {
      mail: typeof data.mail === "string" ? data.mail : "",
      captchaToken: typeof data.captchaToken === "string" ? data.captchaToken : "",
      website: typeof data.website === "string" ? data.website : "",
    };
  }
  const data = await request.formData();
  return {
    mail: typeof data.get("mail") === "string" ? String(data.get("mail")) : "",
    captchaToken: String(data.get("captchaToken") || data.get("g-recaptcha-response") || ""),
    website: String(data.get("website") || ""),
  };
}

async function verifyCaptcha(token: string) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret) throw new Error("Missing reCAPTCHA server secret");
  const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    body: new URLSearchParams({ secret, response: token }),
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(10_000),
    cache: "no-store",
  });
  if (!response.ok) return false;
  const result = (await response.json()) as { success?: boolean; hostname?: string };
  const expected = (process.env.RECAPTCHA_EXPECTED_HOSTNAME || "bacha.petrvurm.cz").trim();
  return result.success === true && result.hostname === expected;
}

export async function POST(request: NextRequest) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 16_384) return reply(413, false, "Požadavek je příliš velký.");

  const origin = request.headers.get("origin");
  if (!origin || !allowedOrigins().has(origin.replace(/\/$/, ""))) {
    return reply(403, false, "Požadavek pochází z nepovoleného webu.");
  }

  let submission: Awaited<ReturnType<typeof parseSubmission>>;
  try {
    submission = await parseSubmission(request);
  } catch {
    return reply(400, false, "Požadavek se nepodařilo přečíst.");
  }
  if (submission.website.trim()) {
    // Honeypot: do not send any email or reveal that the bot was detected.
    return reply(200, true, "Pokud byla žádost přijata, zašleme ověřovací odkaz.");
  }
  const checked = normalizeTesterEmail(submission.mail, process.env.INTEREST_BLOCKED_EMAIL_DOMAINS || "");
  if (checked.error === "invalid" || !checked.email) return reply(422, false, "Zadejte platnou e-mailovou adresu.");
  if (checked.error === "disposable") {
    return reply(422, false, "Dočasné e-mailové schránky nejsou pro uzavřené testování povolené. Použijte stálou adresu.");
  }
  if (submission.captchaToken.length > 8192 || !submission.captchaToken)
    return reply(422, false, "Potvrďte prosím reCAPTCHA.");

  try {
    if (!(await verifyCaptcha(submission.captchaToken))) {
      return reply(422, false, "reCAPTCHA se nepodařilo ověřit. Zkuste to prosím znovu.");
    }
    // Firebase credentials are already configured for the Android backend.
    // Transactional Firestore counters work across Vercel serverless instances.
    const db = firestore();
    const accepted = await enforceInterestLimits(
      db, process.env.RECAPTCHA_SECRET_KEY,
      clientAddress(request), checked.email,
    );
    if (!accepted) return reply(429, false, "Příliš mnoho pokusů. Zkuste to prosím později.");

    const token = createToken();
    const id = await createPendingVerification(db, checked.email, token);
    const site = new URL(process.env.APP_ORIGIN || "https://bacha.petrvurm.cz");
    if (site.protocol !== "https:" && process.env.NODE_ENV === "production")
      throw new Error("APP_ORIGIN must use HTTPS");
    const link = new URL("/api/interest/confirm", site);
    link.searchParams.set("token", token);
    await sendInterestConfirmation(checked.email, link.toString(), id);
    return reply(200, true, "Odeslali jsme ověřovací odkaz. Zkontrolujte e-mail a potvrďte adresu do 24 hodin.");
  } catch (error) {
    console.error("Bacha interest request failed", error instanceof Error ? error.name : "unknown");
    return reply(500, false, "Zájem se teď nepodařilo zpracovat. Zkuste to prosím později.");
  }
}

export function GET() {
  return reply(405, false, "Tato akce přijímá pouze POST požadavky.");
}
