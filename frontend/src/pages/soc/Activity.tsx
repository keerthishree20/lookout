import { useState } from "react";

import { DecisionDetail } from "@/components/DecisionDetail";
import { LiveFeed } from "@/components/LiveFeed";
import { useLive } from "@/hooks/useLive";

/** Every scored event as it happens: the session-monitoring view. */
export function Activity() {
  const { feed, selected, select, connected } = useLive();
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  return (
    <div className="grid gap-4 xl:grid-cols-12">
      <div className="min-w-0 xl:col-span-7">
        <LiveFeed
          decisions={feed}
          selectedId={selected?.event.event_id ?? null}
          onSelect={select}
          flaggedOnly={flaggedOnly}
          onToggleFlagged={() => setFlaggedOnly((f) => !f)}
          connected={connected}
        />
      </div>
      <div className="xl:col-span-5">
        <div className="xl:sticky xl:top-20">
          <DecisionDetail decision={selected} />
        </div>
      </div>
    </div>
  );
}
