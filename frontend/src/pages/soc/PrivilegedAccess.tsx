import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { ActionChip, BandChip, Card, Empty } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { AccountRow, Decision } from "@/lib/types";

const PRIVILEGED_ACTIONS = new Set(["priv_escalate", "config_change", "vault_read"]);

/** Privileged access management: who holds power, and what they did with it. */
export function PrivilegedAccess() {
  const { feed, version, select } = useLive();
  const [accounts, setAccounts] = useState<AccountRow[]>([]);
  const [history, setHistory] = useState<Decision[]>([]);

  useEffect(() => {
    api.accounts().then(setAccounts).catch(() => {});
    api.decisions(500).then(setHistory).catch(() => {});
  }, [version]);

  const seen = new Set<string>();
  const actions = [...feed, ...history].filter((d) => {
    if (!PRIVILEGED_ACTIONS.has(d.event.action) || seen.has(d.event.event_id)) return false;
    seen.add(d.event.event_id);
    return true;
  });
  const privileged = accounts.filter((a) => (a.privilege_level ?? 0) >= 4);
  const escalations = actions.filter((d) => d.event.action === "priv_escalate");

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={`Privileged accounts (${privileged.length})`} icon={<ShieldCheck className="h-4 w-4 text-orange-400" />}>
          <p className="mb-2 text-xs text-zinc-500">
            Level 4 and above. Every action they take is scored with a higher privilege multiplier, and a transfer
            or escalation from them is judged more harshly.
          </p>
          <ul className="space-y-1.5 text-sm">
            {privileged.map((a) => (
              <li key={a.username} className="flex items-center justify-between rounded-md bg-zinc-950/40 px-2.5 py-1.5">
                <Link to={`/users/${encodeURIComponent(a.username)}`} className="text-zinc-200 hover:text-sky-300">{a.username}</Link>
                <span className="text-xs text-zinc-500">{humanise(a.role)} · level {a.privilege_level}</span>
                <span className={`text-xs ${a.disabled ? "text-red-300" : "text-emerald-300"}`}>
                  {a.disabled ? "disabled" : `${a.active_sessions} session${a.active_sessions === 1 ? "" : "s"}`}
                </span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title={`Escalation attempts (${escalations.length})`}>
          {escalations.length === 0 ? (
            <Empty>None yet. Run the privilege-escalation or attack-story scenario.</Empty>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {escalations.slice(0, 12).map((d) => (
                <li
                  key={d.event.event_id}
                  onClick={() => select(d)}
                  className="flex cursor-pointer flex-wrap items-center gap-2 rounded-md bg-zinc-950/40 px-2.5 py-1.5 hover:bg-zinc-800/50"
                >
                  <span className="text-zinc-200">{d.event.actor}</span>
                  <span className="text-xs text-zinc-500">
                    {humanise(d.event.actor_role)} → {humanise(String(d.event.meta.target_role ?? "?"))}
                  </span>
                  <span className={`text-xs ${d.event.success ? "text-red-300" : "text-zinc-500"}`}>
                    {d.event.success ? "granted" : "rejected"}
                  </span>
                  <span className="ml-auto"><ActionChip action={d.action_taken} /></span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      <Card title={`Privileged actions (${actions.length})`}>
        {actions.length === 0 ? (
          <Empty>No configuration changes, vault reads or escalations scored yet.</Empty>
        ) : (
          <div className="-mx-4 -mb-4 overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="px-4 py-2 font-medium">When</th>
                  <th className="px-2 py-2 font-medium">Who</th>
                  <th className="px-2 py-2 font-medium">Action</th>
                  <th className="px-2 py-2 font-medium">Resource</th>
                  <th className="px-2 py-2 font-medium">Risk</th>
                  <th className="px-4 py-2 font-medium">Response</th>
                </tr>
              </thead>
              <tbody>
                {actions.slice(0, 60).map((d) => (
                  <tr key={d.event.event_id} onClick={() => select(d)} className="cursor-pointer border-t border-zinc-800/70 hover:bg-zinc-800/40">
                    <td className="px-4 py-2 font-mono text-xs text-zinc-500">{dateTime(d.event.ts)}</td>
                    <td className="px-2 py-2 text-zinc-200">{d.event.actor} <span className="text-xs text-zinc-500">{humanise(d.event.actor_role)}</span></td>
                    <td className="px-2 py-2 text-zinc-300">{humanise(d.event.action)}</td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-400">{d.event.resource}</td>
                    <td className="px-2 py-2"><BandChip band={d.risk.band} /></td>
                    <td className="px-4 py-2"><ActionChip action={d.action_taken} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
