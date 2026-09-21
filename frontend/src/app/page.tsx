"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { loadSession } from "@/lib/session";

/** Send each visitor to their own portal, or to sign-in. */
export default function Root() {
  const router = useRouter();
  useEffect(() => {
    const s = loadSession();
    router.replace(s?.kind === "soc" ? "/soc" : s?.kind === "employee" ? "/employee" : "/login");
  }, [router]);
  return null;
}
