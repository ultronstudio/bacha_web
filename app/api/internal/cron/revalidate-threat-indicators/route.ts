import { handleCron } from "@/lib/server/bacha/httpApi";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = handleCron;
export const POST = handleCron;
