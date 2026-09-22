import { KeyRound, Loader2 } from "lucide-react";
import { useState } from "react";

import { Button, Card } from "@/components/ui";
import { ApiError, api } from "@/lib/api";
import { humanise } from "@/lib/format";
import type { AccessCheckResult } from "@/lib/types";

const USERS = [
  "r.krishnan", "s.iyer", "a.fernandes", "p.nair", "m.d'souza", "k.venkatesh",
  "d.sharma", "l.mathew", "v.rao", "t.banerjee", "h.qureshi", "n.pillai",
];
const RESOURCES = [
  "customer_database", "transaction_database", "payroll_system",
  "financial_records", "authentication_server", "admin_console",
];
const STYLE: Record<AccessCheckResult["decision"], string> = {
  ALLOWED: "bg-emerald-500/10 text-emerald-200 ring-emerald-500/30",
  MFA_REQUIRED: "bg-amber-500/10 text-amber-200 ring-amber-500/30",
  RESTRICTED: "bg-orange-500/10 text-orange-200 ring-orange-500/40",
  DENIED: "bg-zinc-800 text-zinc-200 ring-zinc-600",
  BLOCK_AND_REVOKE: "bg-red-600/20 text-red-100 ring-red-500/60",
};

/** Role + behaviour + risk, not RBAC alone. */
export function AccessControl() {
  const [user, setUser] = useState("p.nair");
  const [resource, setResource] = useState("customer_database");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<AccessCheckResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function check() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.accessCheck(user, resource);
      setHistory((h) => [r, ...h].slice(0, 12));
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  const select = "rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200";
  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <Card title="Risk-based access check" icon={<KeyRound className="h-4 w-4 text-sky-400" />} className="lg:col-span-2">
        <p className="mb-3 text-xs leading-relaxed text-zinc-500">
          Role decides whether a resource is in scope at all (or an approved access request). The person's current
          risk then decides whether in-scope access is normal, needs MFA, is restricted, or is refused with the
          session revoked. Privileged accounts always get enhanced monitoring.
        </p>
        <div className="space-y-2">
          <label className="block text-xs text-zinc-400">
            Employee
            <select className={`${select} mt-1 w-full`} value={user} onChange={(e) => setUser(e.target.value)}>
              {USERS.map((u) => <option key={u}>{u}</option>)}
            </select>
          </label>
          <label className="block text-xs text-zinc-400">
            Resource
            <select className={`${select} mt-1 w-full`} value={resource} onChange={(e) => setResource(e.target.value)}>
              {RESOURCES.map((r) => <option key={r} value={r}>{humanise(r)}</option>)}
            </select>
          </label>
          <Button variant="primary" onClick={check} disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />} Check access
          </Button>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <table className="mt-4 w-full text-left text-[11px] text-zinc-400">
          <thead className="text-zinc-500">
            <tr><th className="py-1 font-medium">Role + risk</th><th className="py-1 font-medium">Outcome</th></tr>
          </thead>
          <tbody>
            <tr className="border-t border-zinc-800"><td className="py-1">In scope, low risk</td><td>Allowed</td></tr>
            <tr className="border-t border-zinc-800"><td className="py-1">Medium risk, or privileged + critical system</td><td>MFA required</td></tr>
            <tr className="border-t border-zinc-800"><td className="py-1">High risk</td><td>Restricted</td></tr>
            <tr className="border-t border-zinc-800"><td className="py-1">Privileged + high, or anyone critical</td><td>Block + revoke</td></tr>
            <tr className="border-t border-zinc-800"><td className="py-1">Out of scope, no approval</td><td>Denied</td></tr>
          </tbody>
        </table>
      </Card>
      <Card title="Results" className="lg:col-span-3">
        {history.length === 0 ? (
          <p className="text-sm text-zinc-500">
            Run a check. Try a teller on the customer database, a sysadmin on the admin console, then run the
            exfiltration scenario and check k.venkatesh again.
          </p>
        ) : (
          <ul className="space-y-2">
            {history.map((r, i) => (
              <li key={i} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-zinc-200">{r.user}</span>
                  <span className="text-xs text-zinc-500">{humanise(r.role)}</span>
                  <span className="text-xs text-zinc-500">→ {humanise(r.resource)}</span>
                  <span className={`ml-auto rounded px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${STYLE[r.decision]}`}>
                    {r.decision.replaceAll("_", " ")}
                  </span>
                </div>
                <div className="mt-1 text-xs text-zinc-400">
                  {r.reason} · current risk {r.current_risk.toFixed(0)} ({r.risk_band}) · monitoring {r.monitoring}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
