import { Users } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { humanise } from "@/lib/format";
import type { Identity } from "@/lib/types";

import { Card, Empty, SearchBox } from "./ui";

const LEVEL: Record<string, number> = {
  teller: 1,
  officer: 2,
  analyst: 2,
  manager: 3,
  dba: 4,
  sysadmin: 5,
  domain_admin: 6,
};

export function IdentitiesPanel({ refreshKey }: { refreshKey: number }) {
  const [users, setUsers] = useState<Identity[]>([]);
  const [search, setSearch] = useState("");
  const { risk } = useLive();

  useEffect(() => {
    api.users().then(setUsers).catch(() => setUsers([]));
  }, [refreshKey]);

  const needle = search.trim().toLowerCase();
  const sorted = [...users].filter((u) => !needle || `${u.actor} ${u.role}`.toLowerCase().includes(needle)).sort((a, b) => LEVEL[b.role] - LEVEL[a.role] || b.peak_risk - a.peak_risk);

  return (
    <Card
      title="Behavioural baselines"
      icon={<Users className="h-4 w-4 text-sky-400" />}
      right={<SearchBox value={search} onChange={setSearch} placeholder="User or role" />}
    >
      <p className="mb-3 text-xs leading-relaxed text-zinc-500">
        What Lookout has learned is normal for each identity. Every threshold is measured against these,
        never against a bank-wide constant — a 2 a.m. login is routine for the on-call sysadmin and
        alarming for a teller.
      </p>
      {sorted.length === 0 ? (
        <Empty>Loading identities…</Empty>
      ) : (
        <div className="-mx-4 -mb-4 overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">Identity</th>
                <th className="px-2 py-2 font-medium">Privilege</th>
                <th className="px-2 py-2 font-medium">Usual hours</th>
                <th className="px-2 py-2 font-medium">Rows / query</th>
                <th className="px-2 py-2 font-medium">Reach / message</th>
                <th className="px-2 py-2 font-medium">Seen from</th>
                <th className="px-2 py-2 text-right font-medium">Now</th>
                <th className="px-4 py-2 text-right font-medium">Peak risk</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((u) => (
                <tr key={u.actor} className="border-t border-zinc-800/70">
                  <td className="px-4 py-2">
                    <Link to={`/users/${encodeURIComponent(u.actor)}`} className="text-zinc-200 hover:text-sky-300">
                      {u.actor}
                    </Link>
                    <div className="text-[11px] text-zinc-500">{humanise(u.role)} · {u.events.toLocaleString()} events</div>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex gap-0.5" title={`level ${LEVEL[u.role]} of 6`}>
                      {Array.from({ length: 6 }, (_, i) => (
                        <span
                          key={i}
                          className={`h-3 w-1.5 rounded-sm ${i < LEVEL[u.role] ? (LEVEL[u.role] >= 4 ? "bg-orange-400" : "bg-sky-400") : "bg-zinc-800"}`}
                        />
                      ))}
                    </div>
                  </td>
                  <td className="px-2 py-2 font-mono text-xs text-zinc-400">
                    {u.usual_hours.length ? `${String(Math.min(...u.usual_hours)).padStart(2, "0")}–${String(Math.max(...u.usual_hours) + 1).padStart(2, "0")}h` : "—"}
                  </td>
                  <td className="px-2 py-2 font-mono text-xs text-zinc-400">
                    {u.records_per_query.n ? `${Math.round(u.records_per_query.mean).toLocaleString()} ± ${Math.round(u.records_per_query.std).toLocaleString()}` : "—"}
                  </td>
                  <td className="px-2 py-2 font-mono text-xs text-zinc-400">
                    {u.recipients_per_message.n ? `${Math.round(u.recipients_per_message.mean).toLocaleString()}` : "—"}
                  </td>
                  <td className="px-2 py-2 text-xs text-zinc-400">
                    {u.countries.join(", ")} · {u.devices.length} device{u.devices.length === 1 ? "" : "s"}
                  </td>
                  <td className="px-2 py-2 text-right font-mono text-xs tabular-nums" title="Latest score, live over WebSocket">
                    <span className={riskTone(risk[u.actor]?.score ?? -1)}>{risk[u.actor] ? risk[u.actor].score.toFixed(0) : "—"}</span>
                  </td>
                  <td className="px-4 py-2 text-right">
                    <span className={`font-mono text-sm tabular-nums ${riskTone(u.peak_risk)}`}>
                      {u.decisions ? u.peak_risk.toFixed(0) : "—"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** The spec's risk colours: medium yellow, high orange, critical red. */
function riskTone(score: number): string {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-300";
  if (score >= 30) return "text-amber-300";
  return "text-zinc-500";
}
