"use client";

import { Loader2, Play, Siren } from "lucide-react";
import { useState } from "react";

import type { Decision, Scenario } from "@/lib/types";

import { ActionChip, Card } from "./ui";

export function ScenarioPanel({
  scenarios,
  onRun,
  lastPeaks,
}: {
  scenarios: Scenario[];
  onRun: (key: string) => Promise<void>;
  lastPeaks: Record<string, Decision>;
}) {
  const [running, setRunning] = useState<string | null>(null);

  return (
    <Card title="Inject an incident" icon={<Siren className="h-4 w-4 text-red-400" />}>
      <p className="mb-3 text-xs leading-relaxed text-zinc-500">
        Each scenario replays labelled events through the same pipeline as live traffic. Nothing in the
        scoring knows a scenario is running.
      </p>
      <ul className="space-y-2">
        {scenarios.map((s) => {
          const peak = lastPeaks[s.key];
          const busy = running === s.key;
          return (
            <li key={s.key} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-zinc-200">{s.title}</div>
                  <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">{s.summary}</p>
                </div>
                <button
                  disabled={running !== null}
                  onClick={async () => {
                    setRunning(s.key);
                    try {
                      await onRun(s.key);
                    } finally {
                      setRunning(null);
                    }
                  }}
                  className="inline-flex shrink-0 items-center gap-1 rounded-md bg-red-600/90 px-2.5 py-1 text-xs font-medium text-white transition hover:bg-red-500 disabled:opacity-40"
                  aria-label={`Run ${s.title}`}
                >
                  {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                  Run
                </button>
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {s.covers.map((c) => (
                  <span key={c} className="rounded bg-zinc-800/80 px-1.5 py-0.5 text-[10px] text-zinc-400">
                    {c}
                  </span>
                ))}
              </div>
              {peak && (
                <div className="mt-2 flex items-center gap-2 border-t border-zinc-800 pt-2 text-xs text-zinc-400">
                  Peak <span className="font-mono text-zinc-200">{peak.risk.total.toFixed(0)}</span>
                  <ActionChip action={peak.action_taken} />
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
