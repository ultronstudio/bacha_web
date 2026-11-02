/* eslint-disable @next/next/no-page-custom-font -- Nunito is loaded once in the shared App Router layout. */
import type { Metadata } from "next";
import "bootstrap/dist/css/bootstrap.min.css";
import "./globals.css";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import NoticeBanner from "@/components/NoticeBanner";
import BootstrapClient from "@/components/BootstrapClient";
import ThemeInit from "@/components/ThemeInit";

export const metadata: Metadata = {
  applicationName: "Bacha!",
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    locale: "cs_CZ",
    siteName: "Bacha!",
    url: "/",
    title: "Bacha! – Než klikneš, zkontroluj.",
    description:
      "Bacha! – osobní asistent proti podvodům. Prověřte zprávy, odkazy, QR kódy a screenshoty.",
  },
  twitter: {
    card: "summary_large_image",
    title: "Bacha! – Než klikneš, zkontroluj.",
    description:
      "Bacha! – osobní asistent proti podvodům. Prověřte zprávy, odkazy, QR kódy a screenshoty.",
    images: ["/opengraph-image"],
  },
  title: "Bacha! – Než klikneš, zkontroluj.",
  description:
    "Bacha! – osobní asistent proti podvodům. Prověřte zprávy, odkazy, QR kódy a screenshoty.",
  metadataBase: new URL(process.env.APP_ORIGIN || "https://bacha.petrvurm.cz"),
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="cs" data-bs-theme="light" suppressHydrationWarning>
      <head>
        <ThemeInit />
        <meta name="theme-color" content="#FAFAF7" id="theme-color" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <Header />
        <NoticeBanner />
        <main id="top">{children}</main>
        <Footer />
        <BootstrapClient />
      </body>
    </html>
  );
}
