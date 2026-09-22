import { CheckCircle2, Loader2, Lock, SlidersHorizontal } from "lucide-react";
import { useEffect, useState } from "react";

import { Button, Card } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { ApiError, api } from "@/lib/api";
import { humanise } from "@/lib/format";
import { loadSession } from "@/lib/session";
import type { AccessRequest, Policy } from "@/lib/types";

/** Thresholds and limits the whole engine reads live. Super Admin edits;
 *  everyone else on the console can read. Every change is audited. */
const ROLE_LEVEL: Record<string, number> = { teller: 1, officer: 2, analyst: 2, manager: 3, dba: 4, sysadmin: 5, domain_admin: 6 };

export function SecurityPolicies() {
  const { version } = useLive();
  const isAdmin = loadSession()?.kind === "superadmin";
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [draft, setDraft] = useState<Policy | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api.policy().then((p) => {
      setPolicy(p);
      setDraft(p);
    });
  }, [version]);

  async function save() {
    if (!draft) return;
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.updatePolicies(draft);
      setPolicy(r.policy);
      setDraft(r.policy);
      const n = Object.keys(r.changed).length;
      setMsg({ ok: true, text: n ? `Saved ${n} change${n === 1 ? "" : "s"}; applies to the next decision and is in the audit log.` : "No changes." });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.detail : String(e) });
    } finally {
      setBusy(false);
    }
  }

  if (!draft || !policy) return <p className="text-sm text-zinc-500">Loading…</p>;
  const num = "w-28 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 font-mono text-sm text-zinc-100 disabled:opacity-60";
  const set = <K extends keyof Policy>(k: K, v: Policy[K]) => setDraft({ ...draft, [k]: v });

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card
        title="Risk bands and honeypot"
        icon={<SlidersHorizontal className="h-4 w-4 text-sky-400" />}
        right={!isAdmin && <span className="inline-flex items-center gap-1 text-[11px] text-zinc-500"><Lock className="h-3 w-3" /> Super Admin only</span>}
      >
        <p className="mb-4 text-xs leading-relaxed text-zinc-500">
          The response is chosen by band: <strong>low</strong> allow, <strong>medium</strong> step-up authentication,{" "}
          <strong>high</strong> block or quarantine, <strong>critical</strong> block, revoke the session and page the SOC.
        </p>
        <div className="space-y-3">
          {(
            [
              ["medium", "Medium from", "step-up authentication"],
              ["high", "High from", "block / quarantine"],
              ["critical", "Critical from", "block + revoke + alert"],
            ] as const
          ).map(([k, label, what]) => (
            <label key={k} className="flex items-center justify-between gap-3 text-sm text-zinc-300">
              <span>
                {label} <span className="text-xs text-zinc-500">({what})</span>
              </span>
              <input type="number" min={1} max={100} className={num} disabled={!isAdmin} value={draft[k]} onChange={(e) => set(k, Number(e.target.value))} />
            </label>
          ))}
          <label className="flex items-center justify-between gap-3 border-t border-zinc-800 pt-3 text-sm text-zinc-300">
            <span>
              Honeypot export threshold <span className="text-xs text-zinc-500">(records that always get a decoy PDF)</span>
            </span>
            <input
              type="number" min={1} max={500} className={num} disabled={!isAdmin}
              value={draft.honeypot_export_threshold}
              onChange={(e) => set("honeypot_export_threshold", Number(e.target.value))}
            />
          </label>
        </div>
      </Card>

      <Card title="Transfer limits per role" right={!isAdmin && <span className="text-[11px] text-zinc-500">read-only</span>}>
        <p className="mb-4 text-xs leading-relaxed text-zinc-500">
          The largest single customer transfer each role may process. A role that is not listed has no mandate to move
          money at all, and any transfer from it is blocked by policy (and lands the person in the honeypot).
        </p>
        <div className="space-y-3">
          {Object.entries(draft.transfer_limits).map(([role, v]) => (
            <label key={role} className="flex items-center justify-between gap-3 text-sm text-zinc-300">
              <span>{humanise(role)} <span className="text-xs text-zinc-500">₹</span></span>
              <input
                type="number" min={1} className={`${num} w-36`} disabled={!isAdmin} value={v}
                onChange={(e) => set("transfer_limits", { ...draft.transfer_limits, [role]: Number(e.target.value) })}
              />
            </label>
          ))}
        </div>
      </Card>

      <Card title="Communication policy" right={!isAdmin && <span className="text-[11px] text-zinc-500">read-only</span>} className="xl:col-span-2">
        <p className="mb-4 text-xs leading-relaxed text-zinc-500">
          Who may send customer-facing messages at all, and who may run bulk campaigns. A send from a role without the
          mandate is scored as unauthorised communication; privileged administrators can be required to pass a second
          factor for every customer message. Privileged administrators can also edit these roles from their portal.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[420px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="py-1.5 font-medium">Role</th>
                <th className="py-1.5 font-medium">Customer messages</th>
                <th className="py-1.5 font-medium">Bulk campaigns</th>
              </tr>
            </thead>
            <tbody>
              {Object.keys(ROLE_LEVEL).map((role) => (
                <tr key={role} className="border-t border-zinc-800/70">
                  <td className="py-1.5 text-zinc-300">{humanise(role)}</td>
                  {(["customer_comms_roles", "bulk_comms_roles"] as const).map((k) => (
                    <td key={k} className="py-1.5">
                      <input
                        type="checkbox"
                        aria-label={`${role} ${k}`}
                        disabled={!isAdmin}
                        checked={draft[k].includes(role)}
                        onChange={() =>
                          set(k, draft[k].includes(role) ? draft[k].filter((r) => r !== role) : [...draft[k], role].sort())
                        }
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-6 text-sm text-zinc-300">
          <label className="flex items-center gap-2">
            Bulk threshold
            <input type="number" min={2} className={num} disabled={!isAdmin} value={draft.bulk_threshold} onChange={(e) => set("bulk_threshold", Number(e.target.value))} />
            <span className="text-xs text-zinc-500">recipients</span>
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              disabled={!isAdmin}
              checked={draft.privileged_comms_step_up}
              onChange={(e) => set("privileged_comms_step_up", e.target.checked)}
            />
            Privileged administrators need MFA to message customers
          </label>
        </div>
      </Card>

      {isAdmin && (
        <div className="flex flex-wrap items-center gap-3 xl:col-span-2">
          <Button variant="primary" onClick={save} disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />} Save policy
          </Button>
          <Button variant="ghost" onClick={() => setDraft(policy)} disabled={busy}>Discard changes</Button>
          {msg && (
            <span className={`inline-flex items-center gap-1 text-sm ${msg.ok ? "text-emerald-300" : "text-red-400"}`}>
              {msg.ok && <CheckCircle2 className="h-4 w-4" />} {msg.text}
            </span>
          )}
        </div>
      )}

      {isAdmin && <AdminRequests />}
    </div>
  );
}

/** Access requests from staff without a branch manager land with the Super Admin. */
function AdminRequests() {
  const [rows, setRows] = useState<AccessRequest[]>([]);
  const load = () => api.adminRequests().then(setRows).catch(() => {});
  useEffect(() => {
    load();
  }, []);
  return (
    <Card title={`Access requests (${rows.length})`} className="xl:col-span-2">
      {rows.length === 0 ? (
        <p className="text-sm text-zinc-500">None. Employees request access from the portal; managers decide for their own team.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {rows.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center gap-2 rounded-md bg-zinc-950/40 px-3 py-2">
              <span className="font-mono text-xs text-zinc-500">{r.id}</span>
              <span className="text-zinc-200">{r.user}</span>
              <span className="text-xs text-zinc-500">wants {r.resource_name}</span>
              <span className="text-xs italic text-zinc-500">“{r.reason}”</span>
              <span className="ml-auto text-xs text-zinc-400">approver: {r.approver}</span>
              {r.status === "PENDING" ? (
                <>
                  <Button className="text-xs" onClick={() => api.adminDecide(r.id, true).then(load)}>Approve</Button>
                  <Button variant="ghost" className="text-xs" onClick={() => api.adminDecide(r.id, false).then(load)}>Deny</Button>
                </>
              ) : (
                <span className={`text-xs ${r.status === "APPROVED" ? "text-emerald-300" : "text-red-300"}`}>{r.status} by {r.decided_by}</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
