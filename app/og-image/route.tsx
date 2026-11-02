import { NextRequest } from "next/server";
import {
  loadBachaLogo,
  renderOpenGraphImage,
} from "@/components/BrandMetadataImage";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const requestedTheme = request.nextUrl.searchParams.get("theme");
  const theme = requestedTheme === "dark" ? "dark" : "light";

  return renderOpenGraphImage(await loadBachaLogo(), theme);
}
