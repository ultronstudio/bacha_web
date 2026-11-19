import { NextRequest, NextResponse } from "next/server";
import { firestore } from "@/lib/server/bacha/firebaseAdmin";
import { sendVerifiedInterestNotification } from "@/lib/server/interestEmail";
import {
  tokenId, getVerificationState, claimVerification, finishVerification,
} from "@/lib/server/interestVerification";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const HEADERS = {
  "Cache-Control": "no-store, max-age=0",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};

function page(title: string, body: string, token?: string, status = 200) {
  const form = token ? [
    '<form method="post" action="/api/interest/confirm">',
    '<input type="hidden" name="token" value="' + token + '">',
    '<button type="submit">Potvrdit e-mail</button>',
    '</form>',
  ].join("") : "";
  const html = [
    '<!doctype html><html lang="cs"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>' + title + ' – Bacha!</title>',
    '<style>',
    'body{margin:0;background:#0b1421;color:#eef6ff;font:16px system-ui,Arial,sans-serif;min-height:100vh;display:grid;place-items:center}',
    'main{max-width:580px;padding:32px;border-radius:16px;background:#162336;margin:20px}',
    'h1{font-size:1.7rem}p{line-height:1.6}',
    'button{background:#00b7ef;color:#00121a;border:0;padding:14px 22px;border-radius:9px;font-weight:700;cursor:pointer}',
    'a{color:#73d6ff}',
    '</style></head><body><main><h1>' + title + '</h1><p>' + body + '</p>',
    form, '<p><a href="/">Zpět na Bacha!</a></p></main></body></html>',
  ].join("");
  return new NextResponse(html, { status, headers: { ...HEADERS, "Content-Type": "text/html; charset=utf-8" } });
}

function statePage(state: string, token?: string) {
  switch (state) {
    case "ready":
      return page("Potvrzení e-mailu", "Kliknutím potvrzujete, že jste zadali tuto e-mailovou adresu pro účast v uzavřeném testování Bacha!. Tím ještě nezískáváte přístup do Google Play testování.", token);
    case "notified":
      return page("Adresa je potvrzená", "Váš zájem už byl potvrzen a předán provozovateli Bacha!.");
    case "sending":
      return page("Probíhá zpracování", "Potvrzení právě zpracováváme. Pokud se nedokončí, zkuste stránku znovu za pár minut.");
    case "expired":
      return page("Odkaz vypršel", "Platnost ověřovacího odkazu skončila. Odešlete novou žádost z webu Bacha!.", undefined, 410);
    default:
      return page("Neplatný odkaz", "Ověřovací odkaz je neplatný nebo již není dostupný.", undefined, 400);
  }
}

/** GET never consumes tokens: mail scanners and link previews are harmless. */
export async function GET(request: NextRequest) {
  const token = request.nextUrl.searchParams.get("token");
  if (!tokenId(token)) return statePage("invalid");
  try {
    const state = await getVerificationState(firestore(), token);
    return statePage(state, state === "ready" ? token : undefined);
  } catch {
    return page("Služba není dostupná", "Zkuste ověření později.", undefined, 503);
  }
}

export async function POST(request: NextRequest) {
  if (Number(request.headers.get("content-length") || 0) > 2048) return statePage("invalid");
  const origin = request.headers.get("origin");
  // Browser confirmation happens only from this website, never cross-origin.
  if (!origin || origin !== new URL(request.url).origin) return statePage("invalid");
  if (!(request.headers.get("content-type") || "").includes("application/x-www-form-urlencoded")) return statePage("invalid");

  let token: string;
  try {
    const data = await request.formData();
    token = String(data.get("token") || "");
  } catch {
    return statePage("invalid");
  }
  if (!tokenId(token)) return statePage("invalid");

  try {
    const db = firestore();
    const claim = await claimVerification(db, token);
    if (claim.state !== "send") return statePage(claim.state);
    try {
      await sendVerifiedInterestNotification(claim.email, claim.id);
    } catch {
      await finishVerification(db, claim.id, claim.claim, false);
      return page("Dočasná chyba", "Adresa byla potvrzena, ale oznámení se nepodařilo odeslat. Zkuste potvrzení zopakovat.", undefined, 503);
    }
    // Resend idempotency key prevents repeated notification on quick retries.
    await finishVerification(db, claim.id, claim.claim, true);
    return statePage("notified");
  } catch {
    return page("Služba není dostupná", "Zkuste potvrzení později.", undefined, 503);
  }
}
