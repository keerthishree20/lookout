import { IdentitiesPanel } from "@/components/IdentitiesPanel";
import { useLive } from "@/hooks/useLive";

export function Users() {
  const { version } = useLive();
  return <IdentitiesPanel refreshKey={version} />;
}
