import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const siteUrl = (process.env.APP_ORIGIN || "https://bacha.petrvurm.cz").replace(
    /\/$/,
    "",
  );
  const pages = [
    { path: "/", priority: 1 },
    { path: "/ochrana-soukromi", priority: 0.5 },
    { path: "/smazat-ucet", priority: 0.4 },
    { path: "/podpora", priority: 0.5 },
  ];

  return pages.map(({ path, priority }) => ({
    url: `${siteUrl}${path}`,
    lastModified: new Date(),
    changeFrequency: "monthly",
    priority,
  }));
}
