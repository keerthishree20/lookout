import { useEffect, useState } from "react";

import { DecisionDetail } from "@/components/DecisionDetail";
import { LiveFeed } from "@/components/LiveFeed";
import { ScenarioPanel } from "@/components/ScenarioPanel";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import type { Decision, Scenario } from "@/lib/types";

/** Demo mode: inject a scripted incident and watch Lookout respond. */
export function Simulation() {
  const { feed, merge, selected, select, connected, refresh, bump } = useLive();
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [peaks, setPeaks] = useState<Record<string, Decision>>({});
  const [flaggedOnly, setFlaggedOnly] = useState(false);

  useEffect(() => {
    api.scenarios().then(setScenarios).catch(() => {});
  }, []);

  async function run(key: string) {
    const r = await api.runScenario(key);
    merge(r.decisions);
    select(r.peak);
    setPeaks((p) => ({ ...p, [key]: r.peak }));
    refresh();
    bump();
  }

  return (
    <div className="grid gap-4 xl:grid-cols-12">
      <div className="xl:col-span-3">
        <ScenarioPanel scenarios={scenarios} onRun={run} lastPeaks={peaks} />
      </div>
      <div className="min-w-0 xl:col-span-5">
        <LiveFeed
          decisions={feed}
          selectedId={selected?.event.event_id ?? null}
          onSelect={select}
          flaggedOnly={flaggedOnly}
          onToggleFlagged={() => setFlaggedOnly((f) => !f)}
          connected={connected}
        />
      </div>
      <div className="xl:col-span-4">
        <div className="xl:sticky xl:top-20">
          <DecisionDetail decision={selected} />
        </div>
      </div>
    </div>
  );
}
