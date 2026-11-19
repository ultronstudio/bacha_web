import "server-only";

const SENDER = "Bacha! <bacha@petrvurm.cz>";
const ADMIN = "kontakt@petrvurm.cz";

async function sendEmail(body: Record<string, unknown>, idempotencyKey: string) {
  const key = process.env.RESEND_API_KEY;
  if (!key) throw new Error("Missing RESEND_API_KEY");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + key,
      "Content-Type": "application/json",
      Accept: "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({ from: SENDER, ...body }),
    signal: AbortSignal.timeout(10_000),
    cache: "no-store",
  });
  if (!response.ok) {
    console.error("Bacha interest email delivery failed", response.status);
    throw new Error("Resend rejected request");
  }
}

export async function sendInterestConfirmation(email: string, confirmUrl: string, id: string) {
  await sendEmail({
    to: [email],
    subject: "Potvrďte e-mail pro testování Bacha!",
    text: [
      "Dobrý den,",
      "",
      "z webu Bacha! přišla žádost o účast v uzavřeném testování.",
      "Adresu potvrďte otevřením odkazu a následným kliknutím na tlačítko Potvrdit:",
      "",
      confirmUrl,
      "",
      "Odkaz platí 24 hodin. Pokud jste žádost neposílali, tento e-mail ignorujte.",
      "Potvrzení e-mailu samo o sobě nezaručuje přístup do testování ani neověřuje existenci Google účtu.",
      "",
      "Bacha! – bacha.petrvurm.cz",
    ].join("\n"),
    tags: [{ name: "source", value: "bacha_interest_confirm" }],
  }, "bacha-interest-confirm-" + id);
}

export async function sendVerifiedInterestNotification(email: string, id: string) {
  const submittedAt = new Intl.DateTimeFormat("cs-CZ", {
    timeZone: "Europe/Prague",
    day: "numeric", month: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  }).format(new Date());

  await sendEmail({
    to: [ADMIN],
    reply_to: email,
    subject: "Bacha! – ověřený zájem o uzavřené testování",
    text: [
      "Nový potvrzený zájem o uzavřené testování Bacha!",
      "",
      "Zájemce potvrdil vlastnictví e-mailové schránky kliknutím na ověřovací odkaz.",
      "E-mail (existence Google účtu nebyla automaticky ověřena):",
      email,
      "",
      "Potvrzeno:",
      submittedAt,
    ].join("\n"),
    tags: [{ name: "source", value: "bacha_test_interest" }],
  }, "bacha-interest-notify-" + id);
}
