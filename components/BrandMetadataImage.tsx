import { ImageResponse } from "next/og";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createElement } from "react";

function Logo({ src, width, height }: { src: string; width: number; height: number }) {
  return createElement("img", {
    src,
    alt: "Bacha!",
    width,
    height,
    style: { objectFit: "contain" },
  });
}

export async function loadBachaLogo() {
  const svg = await readFile(
    join(process.cwd(), "public", "assets", "images", "bacha-logo.svg"),
  );
  return `data:image/svg+xml;base64,${svg.toString("base64")}`;
}

export function renderAppleIcon(logo: string) {
  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: "#FAFAF7",
      }}
    >
      <Logo src={logo} width={124} height={133} />
    </div>,
    { width: 180, height: 180 },
  );
}

export function renderOpenGraphImage(logo: string) {
  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "72px 96px",
        backgroundColor: "#FAFAF7",
        color: "#1E1C16",
        fontFamily: "Nunito, Arial, sans-serif",
      }}
    >
      <div
        style={{
          width: 200,
          height: 220,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <Logo src={logo} width={180} height={193} />
      </div>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          marginLeft: 72,
          fontSize: 76,
          fontWeight: 800,
          lineHeight: 1.05,
          letterSpacing: -2,
        }}
      >
        <div>Než klikneš,</div>
        <div>zkontroluj.</div>
      </div>
    </div>,
    { width: 1200, height: 630 },
  );
}
