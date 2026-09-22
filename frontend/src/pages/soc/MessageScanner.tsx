import { DecisionDetail } from "@/components/DecisionDetail";
import { GatewayPanel } from "@/components/GatewayPanel";
import { useLive } from "@/hooks/useLive";

/** Send a simulated SMS/email/push through the AI security gateway. */
export function MessageScanner() {
  const { version, selected, select, merge, refresh } = useLive();
  const isMessage = selected?.event.action === "send_message";
  return (
    <div className="space-y-4">
      <GatewayPanel
        refreshKey={version}
        onDecision={(d) => {
          select(d);
          merge([d]);
          refresh();
        }}
      />
      {isMessage && (
        <div className="lg:max-w-2xl">
          <DecisionDetail decision={selected} />
        </div>
      )}
    </div>
  );
}
