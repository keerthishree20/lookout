import { AuditPanel } from "@/components/AuditPanel";
import { useLive } from "@/hooks/useLive";

export function AuditLogs() {
  const { version, reset } = useLive();
  return <AuditPanel refreshKey={version} onReset={reset} />;
}
