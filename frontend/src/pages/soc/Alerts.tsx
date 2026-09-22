import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { Card, Empty, Pagination, SearchBox, usePaged } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime } from "@/lib/format";
import type { Alert, AlertStatus } from "@/lib/types";

const STATUSES: AlertStatus[] = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];

export function Alerts() {
  const { version, alerts: live } = useLive();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<AlertStatus | "">("");
  const [open, setOpen] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    api.alerts(filter || undefined).then(setAlerts).catch(() => {});
  }, [filter, version, live.length]);

  async function setStatus(id: string, status: AlertStatus) {
    const a = await api.alertStatus(id, status);
    setAlerts((xs) => xs.map((x) => (x.id === id ? a : x)));
  }

  const needle = search.trim().toLowerCase();
  const shown = alerts.filter((a) => !needle || `${a.user} ${a.alert_type} ${a.id} ${a.severity}`.toLowerCase().includes(needle));
  const paged = usePaged(shown, 15);

  return (
    <Card
      title={`Security alerts (${shown.length})`}
      right={
        <div className="flex flex-wrap items-center gap-2">
        <SearchBox value={search} onChange={setSearch} placeholder="User, type, id" />
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as AlertStatus | "")}
          className="rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-200"
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
        </select>
        </div>
      }
    >
      {shown.length === 0 ? (
        <Empty>No alerts{filter ? ` with status ${filter}` : ""}. Run a scenario from Simulation.</Empty>
      ) : (
        <div className="-mx-4 -mb-4">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">Alert</th>
                <th className="px-2 py-2 font-medium">Severity</th>
                <th className="px-2 py-2 font-medium">Type</th>
                <th className="px-2 py-2 font-medium">User</th>
                <th className="px-2 py-2 font-medium">Risk</th>
                <th className="px-2 py-2 font-medium">When</th>
                <th className="px-2 py-2 font-medium">Incident</th>
                <th className="px-4 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {paged.items.map((a) => (
                <Fragment key={a.id}>
                  <tr
                    onClick={() => setOpen(open === a.id ? null : a.id)}
                    className="cursor-pointer border-t border-zinc-800/70 hover:bg-zinc-800/40"
                  >
                    <td className="px-4 py-2 font-mono text-xs text-zinc-400">{a.id}</td>
                    <td className="px-2 py-2">
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${a.severity === "CRITICAL" ? "bg-red-600/25 text-red-100" : "bg-orange-500/15 text-orange-200"}`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="px-2 py-2 text-zinc-200">{a.alert_type}</td>
                    <td className="px-2 py-2 text-zinc-300">
                      <Link to={`/users/${encodeURIComponent(a.user)}`} onClick={(e) => e.stopPropagation()} className="hover:text-sky-300">
                        {a.user}
                      </Link>
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-300">{a.risk_score.toFixed(0)}</td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-500">{dateTime(a.ts)}</td>
                    <td className="px-2 py-2">
                      {a.incident_id && (
                        <Link to={`/incidents/${a.incident_id}`} onClick={(e) => e.stopPropagation()} className="font-mono text-xs text-sky-400">
                          {a.incident_id}
                        </Link>
                      )}
                    </td>
                    <td className="px-4 py-2" onClick={(e) => e.stopPropagation()}>
                      <select
                        value={a.status}
                        onChange={(e) => setStatus(a.id, e.target.value as AlertStatus)}
                        className="rounded border border-zinc-700 bg-zinc-950 px-1.5 py-0.5 text-[11px] text-zinc-200"
                        aria-label={`Status of ${a.id}`}
                      >
                        {STATUSES.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                      </select>
                    </td>
                  </tr>
                  {open === a.id && (
                    <tr className="bg-zinc-950/50">
                      <td colSpan={8} className="px-4 py-3 text-xs">
                        <p className="text-zinc-300">{a.description}</p>
                        <ul className="mt-2 list-disc space-y-0.5 pl-4 text-zinc-500">
                          {a.reasons.map((r) => <li key={r}>{r}</li>)}
                        </ul>
                        <p className="mt-2 text-amber-200/90"><strong>Recommended:</strong> {a.recommended_action}</p>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        <Pagination {...paged} />
        </div>
      )}
    </Card>
  );
}
