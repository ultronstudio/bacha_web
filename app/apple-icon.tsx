import { loadBachaLogo, renderAppleIcon } from "@/components/BrandMetadataImage";

export const runtime = "nodejs";
export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default async function AppleIcon() {
  return renderAppleIcon(await loadBachaLogo());
}
