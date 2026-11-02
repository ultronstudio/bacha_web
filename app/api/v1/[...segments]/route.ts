import { handleRtdn, handleV1 } from "@/lib/server/bacha/httpApi";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 120;

type RouteContext = { params: Promise<{ segments: string[] }> };

async function dispatch(request: Request, context: RouteContext) {
  const { segments } = await context.params;
  if (segments.join("/") === "billing/rtdn" && request.method === "POST") return handleRtdn(request);
  return handleV1(request, segments);
}

export const GET = dispatch;
export const POST = dispatch;
export const PUT = dispatch;
export const PATCH = dispatch;
export const DELETE = dispatch;
