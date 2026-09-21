"use client";

import { Activity, Filter } from "lucide-react";

import { humanise, time } from "@/lib/format";
import type { Decision } from "@/lib/types";

import { ActionChip, Card, ClassChip, Empty, ScoreBar } from "./ui";

export function LiveFeed({
  decisions,
  selectedId,
  onSelect,
  flaggedOnly,
  onToggleFlagged,
  connected,
}: {
  decisions: Decision[];
  selectedId: string | null;
  onSelect: (d: Decision) => void;
  flaggedOnly: boolean;
  onToggleFlagged: () => void;
  connected: boolean;
}) {
  const rows = flaggedOnly ? decisions.filter((d) => d.action_taken !== "allow") : decisions;

  return (
    <Card
      title={
        <>
          Live decisions
          <span
            className={`ml-2 inline-flex items-center gap-1 text-[11px] font-normal ${
              connected ? "text-emerald-400" : "text-zinc-500"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? "animate-pulse bg-emerald-400" : "bg-zinc-600"}`} />
            {connected ? "streaming" : "reconnecting"}
          </span>
        </>
      }
      icon={<Activity className="h-4 w-4 text-emerald-400" />}
      right={
        <button
          onClick={onToggleFlagged}
          className={`inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs ring-1 ring-inset transition ${
            flaggedOnly ? "bg-sky-500/10 text-sky-300 ring-sky-500/40" : "text-zinc-400 ring-zinc-700 hover:bg-zinc-800"
          }`}
        >
          <Filter className="h-3 w-3" />
          {flaggedOnly ? "Flagged only" : "All activity"}
        </button>
      }
      className="min-w-0"
    >
      {rows.length === 0 ? (
        <Empty>
          {flaggedOnly
            ? "Nothing flagged yet. Run a scenario to inject an incident into the stream."
            : "Waiting for activity…"}
        </Empty>
      ) : (
        <div className="-mx-4 -mb-4 max-h-[560px] overflow-auto">
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 z-10 bg-zinc-900 text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-2 py-2 font-medium">Identity</th>
                <th className="px-2 py-2 font-medium">Action</th>
                <th className="px-2 py-2 font-medium">Risk</th>
                <th className="px-2 py-2 font-medium">Response</th>
                <th className="hidden px-4 py-2 font-medium xl:table-cell">Class</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => {
                const selected = d.event.event_id === selectedId;
                const flagged = d.action_taken !== "allow";
                return (
                  <tr
                    key={d.event.event_id}
                    onClick={() => onSelect(d)}
                    className={`cursor-pointer border-t border-zinc-800/70 transition ${
                      selected ? "bg-sky-500/10" : flagged ? "bg-red-500/[0.04] hover:bg-zinc-800/60" : "hover:bg-zinc-800/40"
                    }`}
                  >
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-zinc-500">{time(d.event.ts)}</td>
                    <td className="px-2 py-2">
                      <div className="text-zinc-200">{d.event.actor}</div>
                      <div className="text-[11px] text-zinc-500">
                        {humanise(d.event.actor_role)} · {d.event.geo.city}
                      </div>
                    </td>
                    <td className="px-2 py-2 text-zinc-300">
                      {humanise(d.event.action)}
                      {d.event.message && (
                        <span className="ml-1 text-[11px] text-zinc-500">
                          ×{d.event.message.recipient_count.toLocaleString()}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-2"><ScoreBar score={d.risk.total} band={d.risk.band} /></td>
                    <td className="px-2 py-2"><ActionChip action={d.action_taken} /></td>
                    <td className="hidden px-4 py-2 xl:table-cell">
                      {d.threat_class !== "benign" && <ClassChip cls={d.threat_class} />}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
