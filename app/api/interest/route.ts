import { createHmac } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const WINDOW_MS = 15 * 60 * 1000;
const LIMIT = 5;
const requestsByIpHash = new Map<string, number[]>();
const MAX_ENTRIES = 10_000;

function reply(status: number, ok: boolean, message: string) {
  return NextResponse.json(
    { ok, message },
    { status, headers: { "Cache-Control": "no-store, max-age=0" } },
  );
}

function allowedOrigins() {
  const configured = [
    process.env.APP_ORIGIN || "https://bacha.petrvurm.cz",
    ...(process.env.ALLOWED_ORIGINS || "").split(","),
  ]
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean);
  if (process.env.NODE_ENV !== "production")
    configured.push("http://localhost:3000", "http://127.0.0.1:3000");
  return new Set(configured);
}

function clientAddress(request: NextRequest) {
  const direct = request.headers.get("x-real-ip")?.trim();
  if (direct) return direct;
  const forwarded = request.headers
    .get("x-forwarded-for")
    ?.split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return forwarded?.at(-1) || "unknown";
}

function enforceRateLimit(address: string) {
  const secret =
    process.env.RECAPTCHA_SECRET_KEY ||
    process.env.APP_ORIGIN ||
    "bacha-local-rate-limit";
  const key = createHmac("sha256", secret).update(address).digest("hex");
  const now = Date.now();
  const active = (requestsByIpHash.get(key) || []).filter(
    (timestamp) => timestamp > now - WINDOW_MS,
  );
  if (active.length >= LIMIT) return false;
  if (requestsByIpHash.size >= MAX_ENTRIES && !requestsByIpHash.has(key)) {
    for (const [storedKey, timestamps] of requestsByIpHash) {
      if (timestamps.every((timestamp) => timestamp <= now - WINDOW_MS))
        requestsByIpHash.delete(storedKey);
      if (requestsByIpHash.size < MAX_ENTRIES) break;
    }
    if (requestsByIpHash.size >= MAX_ENTRIES) return false;
  }
  active.push(now);
  requestsByIpHash.set(key, active);
  return true;
}

async function parseSubmission(request: NextRequest) {
  const type = request.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    const data = (await request.json()) as Record<string, unknown>;
    return {
      mail: typeof data.mail === "string" ? data.mail : "",
      captchaToken:
        typeof data.captchaToken === "string" ? data.captchaToken : "",
      website: typeof data.website === "string" ? data.website : "",
    };
  }
  const data = await request.formData();
  return {
    mail: typeof data.get("mail") === "string" ? String(data.get("mail")) : "",
    captchaToken: String(
      data.get("captchaToken") || data.get("g-recaptcha-response") || "",
    ),
    website: String(data.get("website") || ""),
  };
}

async function verifyCaptcha(token: string) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret) throw new Error("Missing reCAPTCHA server secret");
  const body = new URLSearchParams({ secret, response: token });
  const response = await fetch(
    "https://www.google.com/recaptcha/api/siteverify",
    {
      method: "POST",
      body,
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
      cache: "no-store",
    },
  );
  if (!response.ok) return false;
  const result = (await response.json()) as {
    success?: boolean;
    hostname?: string;
  };
  const expectedHostname = (
    process.env.RECAPTCHA_EXPECTED_HOSTNAME || "bacha.petrvurm.cz"
  ).trim();
  return result.success === true && result.hostname === expectedHostname;
}

export async function POST(request: NextRequest) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 16_384)
    return reply(413, false, "Požadavek je příliš velký.");

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

  const address = clientAddress(request);
  if (!enforceRateLimit(address))
    return reply(429, false, "Příliš mnoho pokusů. Zkuste to prosím později.");
  if (submission.website.trim())
    return reply(200, true, "Díky. Zájem o testování byl odeslán.");
  if (
    Buffer.byteLength(submission.mail, "utf8") > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(submission.mail.trim())
  ) {
    return reply(422, false, "Zadejte platnou e-mailovou adresu.");
  }
  if (submission.captchaToken.length > 8192)
    return reply(
      422,
      false,
      "reCAPTCHA se nepodařilo ověřit. Zkuste to prosím znovu.",
    );
  if (!submission.captchaToken)
    return reply(422, false, "Potvrďte prosím reCAPTCHA.");

  try {
    if (!(await verifyCaptcha(submission.captchaToken)))
      return reply(
        422,
        false,
        "reCAPTCHA se nepodařilo ověřit. Zkuste to prosím znovu.",
      );
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) throw new Error("Missing Resend API key");
    const mail = submission.mail.trim();
    const submittedAt = new Intl.DateTimeFormat("cs-CZ", {
      timeZone: "Europe/Prague",
      day: "numeric",
      month: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date());
    const text = [
      "Nový zájem o uzavřené testování Bacha!",
      "",
      "Na webu Bacha! byl vyplněn formulář se zájmem o uzavřené testování.",
      "",
      "Google účet / e-mail:",
      mail,
      "",
      "Odesláno:",
      submittedAt,
    ].join("\n");
    const sent = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        from: "Bacha! <bacha@petrvurm.cz>",
        to: ["kontakt@petrvurm.cz"],
        reply_to: mail,
        subject: "Bacha! – zájem o uzavřené testování",
        text,
        tags: [{ name: "source", value: "bacha_test_interest" }],
      }),
      signal: AbortSignal.timeout(10_000),
      cache: "no-store",
    });
    if (!sent.ok) {
      console.error("Bacha Resend request failed with HTTP", sent.status);
      throw new Error("Resend rejected request");
    }
    return reply(200, true, "Díky. Zájem o uzavřené testování byl odeslán.");
  } catch (error) {
    console.error(
      "Bacha interest submission failed:",
      error instanceof Error ? error.message : "unknown error",
    );
    return reply(
      500,
      false,
      "Zájem se teď nepodařilo odeslat. Zkuste to prosím později.",
    );
  }
}

export function GET() {
  return reply(405, false, "Tato akce přijímá pouze POST požadavky.");
}
