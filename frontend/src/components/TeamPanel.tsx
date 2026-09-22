import { UsersRound } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { AccessRequest, TeamOverview } from "@/lib/types";

/** A manager's view: their branch team's risk and the requests awaiting them.
 *  Deliberately silent about the honeypot -- a manager who knew could tip off
 *  the person being watched. */
export function TeamPanel({ onExpired }: { onExpired: () => void }) {
  const [team, setTeam] = useState<TeamOverview | null>(null);
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    const fail = (e: unknown) => (e instanceof ApiError && e.status === 401 ? onExpired() : setError(String(e)));
    api.team().then(setTeam).catch(fail);
    api.teamRequests().then(setRequests).catch(fail);
  }, [onExpired]);
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  async function decide(id: string, approve: boolean) {
    try {
      await api.teamDecide(id, approve);
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    }
  }

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1fr)_420px]">
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-1 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <UsersRound className="h-4 w-4 text-emerald-400" /> My team {team && <span className="font-normal text-slate-500">· {team.branch}</span>}
        </h2>
        <p className="mb-3 text-xs text-slate-500">Risk summary for the people who report to you.</p>
        {error && <p className="mb-2 text-xs text-red-400">{error}</p>}
        <div className="overflow-x-auto">
        <table className="w-full min-w-[480px] text-left text-sm">
          <thead className="text-[11px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="py-1.5 font-medium">Employee</th>
              <th className="py-1.5 font-medium">Activity</th>
              <th className="py-1.5 font-medium">Flagged</th>
              <th className="py-1.5 font-medium">Peak risk</th>
              <th className="py-1.5 font-medium">Trend</th>
            </tr>
          </thead>
          <tbody>
            {team?.members.map((m) => (
              <tr key={m.user} className="border-t border-slate-800/70">
                <td className="py-2">
                  <div className="text-slate-100">{m.user}</div>
                  <div className="text-[11px] text-slate-500">{humanise(m.role)} · {m.last_activity ? dateTime(m.last_activity) : "no activity yet"}</div>
                </td>
                <td className="py-2 font-mono text-xs text-slate-300">{m.activities}</td>
                <td className={`py-2 font-mono text-xs ${m.flagged ? "text-amber-300" : "text-slate-400"}`}>{m.flagged}</td>
                <td className={`py-2 font-mono text-xs ${m.peak_risk >= 60 ? "text-red-300" : m.peak_risk >= 30 ? "text-amber-300" : "text-slate-400"}`}>
                  {m.peak_risk.toFixed(0)}
                </td>
                <td className="py-2"><Sparkline values={m.risk_trend} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Access requests to decide</h2>
        {requests.length === 0 ? (
          <p className="text-sm text-slate-500">Nothing waiting.</p>
        ) : (
          <ul className="space-y-2">
            {requests.map((r) => (
              <li key={r.id} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-sm">
                <div className="text-slate-100">{r.user} <span className="text-xs text-slate-500">wants</span> {r.resource_name}</div>
                <div className="mt-0.5 text-xs italic text-slate-400">“{r.reason}”</div>
                {r.status === "PENDING" ? (
                  <div className="mt-2 flex gap-2">
                    <button onClick={() => decide(r.id, true)} className="rounded-md bg-emerald-600 px-2.5 py-1 text-xs text-white hover:bg-emerald-500">Approve</button>
                    <button onClick={() => decide(r.id, false)} className="rounded-md px-2.5 py-1 text-xs text-slate-300 ring-1 ring-inset ring-slate-700 hover:bg-slate-800">Deny</button>
                  </div>
                ) : (
                  <div className={`mt-1 text-xs ${r.status === "APPROVED" ? "text-emerald-300" : "text-red-300"}`}>{r.status}</div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

/** Tiny single-series trend: no legend needed, the column header names it. */
function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <span className="text-xs text-slate-600">—</span>;
  const w = 90;
  const h = 22;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * w},${h - (Math.min(v, 100) / 100) * h}`).join(" ");
  return (
    <svg width={w} height={h} role="img" aria-label={`risk trend, last ${values.length} events, latest ${values[values.length - 1]}`}>
      <polyline points={pts} fill="none" stroke="#3987e5" strokeWidth={1.5} strokeLinejoin="round" />
    </svg>
  );
}
