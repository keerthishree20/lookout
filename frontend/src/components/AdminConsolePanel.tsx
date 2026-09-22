import { ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api";
import { humanise } from "@/lib/format";
import type { AdminUserRow, Policy } from "@/lib/types";

const ROLES = ["teller", "officer", "analyst", "manager", "dba", "sysadmin", "domain_admin"];
const LEVEL: Record<string, number> = { teller: 1, officer: 2, analyst: 2, manager: 3, dba: 4, sysadmin: 5, domain_admin: 6 };

type Comms = Pick<Policy, "customer_comms_roles" | "bulk_comms_roles" | "bulk_threshold" | "privileged_comms_step_up">;

/** The privileged administrator's tools: manage accounts and roles below their
 *  own level, and the communication policy. Every action is a monitored,
 *  scored admin operation. */
export function AdminConsolePanel({ myLevel, onExpired }: { myLevel: number; onExpired: () => void }) {
  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [comms, setComms] = useState<Comms | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const fail = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 401) return onExpired();
      setNote(e instanceof ApiError ? e.detail : "Action failed.");
    },
    [onExpired],
  );
  const load = useCallback(() => {
    api.adminUsers().then(setUsers).catch(fail);
    api.adminCommsPolicy().then(setComms).catch(fail);
  }, [fail]);
  useEffect(load, [load]);

  async function run(label: string, fn: () => Promise<unknown>) {
    setNote(null);
    try {
      await fn();
      setNote(`${label}. Logged and monitored.`);
      load();
    } catch (e) {
      fail(e);
    }
  }

  function toggle(key: "customer_comms_roles" | "bulk_comms_roles", role: string) {
    if (!comms) return;
    const set = new Set(comms[key]);
    if (set.has(role)) set.delete(role);
    else set.add(role);
    setComms({ ...comms, [key]: [...set].sort() });
  }

  return (
    <div className="space-y-5">
      <p className="flex items-center gap-2 rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
        <ShieldCheck className="h-4 w-4" /> Privileged administration. Every change here is recorded and receives
        enhanced monitoring.
      </p>
      {note && <p className="rounded-md bg-slate-800 px-3 py-2 text-xs text-slate-200">{note}</p>}

      <section className="rounded-xl border border-slate-800 bg-slate-900/60">
        <h2 className="border-b border-slate-800 px-4 py-3 text-sm font-semibold text-slate-200">Users and roles</h2>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-2 font-medium">User</th>
                <th className="px-2 py-2 font-medium">Branch</th>
                <th className="px-2 py-2 font-medium">Role</th>
                <th className="px-2 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const manageable = u.privilege_level < myLevel;
                return (
                  <tr key={u.username} className="border-t border-slate-800/70">
                    <td className="px-4 py-2 font-mono text-slate-200">{u.username}</td>
                    <td className="px-2 py-2 text-xs text-slate-400">{u.city}</td>
                    <td className="px-2 py-2">
                      {manageable ? (
                        <select
                          aria-label={`Role for ${u.username}`}
                          value={u.role}
                          onChange={(e) => run(`${u.username} is now ${humanise(e.target.value)}`, () => api.adminRole(u.username, e.target.value))}
                          className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-200"
                        >
                          {ROLES.filter((r) => LEVEL[r] < myLevel).map((r) => (
                            <option key={r} value={r}>
                              {humanise(r)}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <span className="text-xs text-slate-400">{humanise(u.role)}</span>
                      )}
                    </td>
                    <td className={`px-2 py-2 text-xs ${u.status === "disabled" ? "text-red-300" : "text-slate-400"}`}>{u.status}</td>
                    <td className="px-4 py-2 text-right">
                      {manageable &&
                        (u.status === "disabled" ? (
                          <button
                            onClick={() => run(`${u.username} re-enabled`, () => api.adminEnable(u.username))}
                            className="rounded-md px-2 py-0.5 text-xs text-emerald-300 ring-1 ring-inset ring-emerald-500/40"
                          >
                            Enable
                          </button>
                        ) : (
                          <button
                            onClick={() => run(`${u.username} disabled`, () => api.adminDisable(u.username, "disabled by administrator"))}
                            className="rounded-md px-2 py-0.5 text-xs text-red-300 ring-1 ring-inset ring-red-500/40"
                          >
                            Disable
                          </button>
                        ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {comms && (
        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="mb-1 text-sm font-semibold text-slate-200">Communication policy</h2>
          <p className="mb-3 text-xs text-slate-500">
            Who may send customer-facing messages, and who may send them in bulk.
            {comms.privileged_comms_step_up && " Privileged administrators always need a second factor to message customers."}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[420px] text-left text-xs">
              <thead className="text-slate-500">
                <tr>
                  <th className="py-1 font-medium">Role</th>
                  <th className="py-1 font-medium">Customer messages</th>
                  <th className="py-1 font-medium">Bulk campaigns</th>
                </tr>
              </thead>
              <tbody>
                {ROLES.map((r) => (
                  <tr key={r} className="border-t border-slate-800/60">
                    <td className="py-1 text-slate-300">{humanise(r)}</td>
                    <td className="py-1">
                      <input type="checkbox" aria-label={`${r} may message customers`} checked={comms.customer_comms_roles.includes(r)} onChange={() => toggle("customer_comms_roles", r)} />
                    </td>
                    <td className="py-1">
                      <input type="checkbox" aria-label={`${r} may send bulk`} checked={comms.bulk_comms_roles.includes(r)} onChange={() => toggle("bulk_comms_roles", r)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <label className="mt-3 flex items-center gap-2 text-xs text-slate-400">
            Bulk threshold (recipients)
            <input
              type="number"
              min={2}
              value={comms.bulk_threshold}
              onChange={(e) => setComms({ ...comms, bulk_threshold: Number(e.target.value) })}
              className="w-24 rounded-md border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-200"
            />
          </label>
          <button
            onClick={() =>
              run("Communication policy saved", () =>
                api.adminPutCommsPolicy({
                  customer_comms_roles: comms.customer_comms_roles,
                  bulk_comms_roles: comms.bulk_comms_roles,
                  bulk_threshold: comms.bulk_threshold,
                }),
              )
            }
            className="mt-3 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500"
          >
            Save communication policy
          </button>
        </section>
      )}
    </div>
  );
}
