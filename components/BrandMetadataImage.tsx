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

async function loadNunitoFont(weight: 600 | 800) {
  const paths = [
    `nunito-latin-${weight}-normal.woff`,
    `nunito-latin-ext-${weight}-normal.woff`,
  ];

  return Promise.all(
    paths.map(async (path) => {
      const font = await readFile(join(process.cwd(), "public", "assets", "fonts", path));
      return font.buffer.slice(
        font.byteOffset,
        font.byteOffset + font.byteLength,
      ) as ArrayBuffer;
    }),
  );
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

export async function renderOpenGraphImage(
  logo: string,
  theme: "light" | "dark" = "light",
) {
  const [nunito600, nunito600Ext] = await loadNunitoFont(600);
  const [nunito800, nunito800Ext] = await loadNunitoFont(800);
  const colors =
    theme === "dark"
      ? { background: "#131311", title: "#FAFAF7", slogan: "#C3C0B7" }
      : { background: "#FAFAF7", title: "#1E1C16", slogan: "#6B675E" };

  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "72px 96px",
        backgroundColor: colors.background,
        color: colors.title,
        fontFamily: "Nunito, Nunito Ext",
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
          marginLeft: 64,
          gap: 14,
        }}
      >
        <div
          style={{
            fontSize: 94,
            fontWeight: 800,
            lineHeight: 1,
            letterSpacing: -3,
          }}
        >
          Bacha!
        </div>
        <div
          style={{
            color: colors.slogan,
            fontSize: 42,
            fontWeight: 600,
            lineHeight: 1.15,
          }}
        >
          Než klikneš, zkontroluj
        </div>
      </div>
    </div>,
    {
      width: 1200,
      height: 630,
      fonts: [
        { name: "Nunito", data: nunito600, weight: 600, style: "normal" },
        { name: "Nunito Ext", data: nunito600Ext, weight: 600, style: "normal" },
        { name: "Nunito", data: nunito800, weight: 800, style: "normal" },
        { name: "Nunito Ext", data: nunito800Ext, weight: 800, style: "normal" },
      ],
    },
  );
}
