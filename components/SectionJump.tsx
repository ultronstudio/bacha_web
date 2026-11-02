"use client";

import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useEffect, useState } from "react";

export default function SectionJump({
  target,
  className,
  children,
}: {
  target: string;
  className: string;
  children: ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [pendingTarget, setPendingTarget] = useState<string | null>(null);

  useEffect(() => {
    if (pathname !== "/" || !pendingTarget) return;
    const frame = window.requestAnimationFrame(() => {
      document.getElementById(pendingTarget)?.scrollIntoView({ behavior: "smooth" });
      setPendingTarget(null);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [pathname, pendingTarget]);

  function jump() {
    if (pathname === "/") {
      document.getElementById(target)?.scrollIntoView({ behavior: "smooth" });
      return;
    }
    setPendingTarget(target);
    router.push("/");
  }

  return (
    <button className={className} type="button" onClick={jump}>
      {children}
    </button>
  );
}
