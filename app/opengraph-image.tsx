import {
  loadBachaLogo,
  renderOpenGraphImage,
} from "@/components/BrandMetadataImage";

export const runtime = "nodejs";
export const alt = "Bacha! – Než klikneš, zkontroluj.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function OpenGraphImage() {
  return renderOpenGraphImage(await loadBachaLogo());
}
