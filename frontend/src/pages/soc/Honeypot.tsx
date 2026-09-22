import { HoneypotPanel } from "@/components/HoneypotPanel";
import { useLive } from "@/hooks/useLive";
import { loadSession } from "@/lib/session";

export function Honeypot() {
  const { version } = useLive();
  return <HoneypotPanel refreshKey={version} analyst={loadSession()?.profile.username ?? "soc"} />;
}
