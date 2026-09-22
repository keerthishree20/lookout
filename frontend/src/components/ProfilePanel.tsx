import { KeyRound, Loader2, UserRound } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api";
import { humanise } from "@/lib/format";
import type { MyProfile } from "@/lib/types";

const OUTCOME_STYLE: Record<string, string> = {
  ALLOWED: "text-emerald-300",
  RESTRICTED: "text-amber-300",
  MFA_REQUIRED: "text-amber-300",
  DENIED: "text-red-300",
  BLOCK_AND_REVOKE: "text-red-300",
};

/** The employee's own profile, their own recent activity, and the protected
 *  systems their role can open. Like the rest of the portal it shows no risk
 *  scores: those would teach an insider where the thresholds are. */
export function ProfilePanel({ onExpired }: { onExpired: () => void }) {
  const [me, setMe] = useState<MyProfile | null>(null);
  const [activity, setActivity] = useState<{ ts: string; activity: string; resource: string }[]>([]);
  const [resources, setResources] = useState<{ resource: string; min_level: number; in_role: boolean }[]>([]);
  const [outcome, setOutcome] = useState<Record<string, string>>({});
  const [otp, setOtp] = useState<{ resource: string; code: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    const fail = (e: unknown) => e instanceof ApiError && e.status === 401 && onExpired();
    api.myProfile().then(setMe).catch(fail);
    api.myActivity().then(setActivity).catch(fail);
    api.myResources().then(setResources).catch(fail);
  }, [onExpired]);
  useEffect(load, [load]);

  async function open(resource: string, code?: string) {
    setBusy(resource);
    try {
      const r = await api.openResource(resource, code);
      if (r.decision === "MFA_REQUIRED" && r.demo_otp) {
        setOtp({ resource, code: r.demo_otp });
        setOutcome((o) => ({ ...o, [resource]: "MFA_REQUIRED" }));
      } else {
        setOtp(null);
        setOutcome((o) => ({ ...o, [resource]: r.decision }));
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return onExpired();
      setOutcome((o) => ({ ...o, [resource]: e instanceof ApiError && e.status === 403 ? "DENIED" : "error" }));
    } finally {
      setBusy(null);
      load();
    }
  }

  if (!me) return <p className="text-sm text-slate-500">Loading…</p>;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[360px_minmax(0,1fr)]">
      <div className="space-y-5">
        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
            <UserRound className="h-4 w-4 text-emerald-400" /> My profile
          </h2>
          <dl className="grid grid-cols-[130px_minmax(0,1fr)] gap-y-1 text-xs">
            <dt className="text-slate-500">Username</dt>
            <dd className="font-mono text-slate-200">{me.username}</dd>
            <dt className="text-slate-500">Email</dt>
            <dd className="break-all text-slate-300">{me.email}</dd>
            <dt className="text-slate-500">Role</dt>
            <dd className="text-slate-200">
              {humanise(me.role)}
              {me.privileged_administrator && <span className="ml-1 text-amber-300">(privileged administrator)</span>}
            </dd>
            <dt className="text-slate-500">Branch</dt>
            <dd className="text-slate-300">{me.city}</dd>
            <dt className="text-slate-500">Registered device</dt>
            <dd className="font-mono text-slate-300">{me.device}</dd>
            <dt className="text-slate-500">Working hours</dt>
            <dd className="text-slate-300">{me.working_hours}</dd>
            <dt className="text-slate-500">Customer messaging</dt>
            <dd className="text-slate-300">{me.may_message_customers ? "Permitted" : "Not permitted"}</dd>
          </dl>
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="mb-1 flex items-center gap-2 text-sm font-semibold text-slate-200">
            <KeyRound className="h-4 w-4 text-emerald-400" /> Protected systems
          </h2>
          <p className="mb-3 text-xs text-slate-500">Every request is checked against your role and logged.</p>
          <ul className="space-y-1.5">
            {resources.map((r) => (
              <li key={r.resource} className="flex flex-wrap items-center gap-2 text-xs">
                <span className={r.in_role ? "text-slate-200" : "text-slate-500"}>{humanise(r.resource)}</span>
                {outcome[r.resource] && (
                  <span className={OUTCOME_STYLE[outcome[r.resource]] ?? "text-slate-400"}>
                    {humanise(outcome[r.resource].toLowerCase())}
                  </span>
                )}
                <button
                  onClick={() => open(r.resource)}
                  disabled={busy !== null}
                  className="ml-auto rounded-md px-2 py-0.5 text-emerald-300 ring-1 ring-inset ring-emerald-500/40 hover:bg-emerald-500/10 disabled:opacity-40"
                >
                  {busy === r.resource ? <Loader2 className="h-3 w-3 animate-spin" /> : "Open"}
                </button>
              </li>
            ))}
          </ul>
          {otp && (
            <div className="mt-3 rounded-md bg-amber-500/10 p-2 text-xs text-amber-100">
              {humanise(otp.resource)} needs a second factor. Simulated code:{" "}
              <span className="font-mono">{otp.code}</span>{" "}
              <button onClick={() => open(otp.resource, otp.code)} className="ml-1 underline">
                Verify and open
              </button>
            </div>
          )}
        </section>
      </div>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">My recent activity</h2>
        {activity.length === 0 ? (
          <p className="text-sm text-slate-500">Nothing yet.</p>
        ) : (
          <ul className="divide-y divide-slate-800/70 text-xs">
            {activity.map((a, i) => (
              <li key={i} className="flex flex-wrap gap-2 py-1.5">
                <span className="font-mono text-slate-500">{new Date(a.ts).toLocaleString("en-GB")}</span>
                <span className="text-slate-200">{a.activity}</span>
                <span className="ml-auto font-mono text-slate-500">{a.resource}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
