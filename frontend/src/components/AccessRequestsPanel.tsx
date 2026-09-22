import { KeyRound, Loader2, Send } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api";
import type { AccessRequest } from "@/lib/types";

const STATUS_STYLE: Record<AccessRequest["status"], string> = {
  PENDING: "bg-amber-500/10 text-amber-200",
  APPROVED: "bg-emerald-500/10 text-emerald-200",
  DENIED: "bg-red-500/10 text-red-200",
};

/** Employees ask for access they do not have; their branch manager (or the
 *  Super Admin, where there is no manager) decides. */
export function AccessRequestsPanel({ onExpired }: { onExpired: () => void }) {
  const [requestable, setRequestable] = useState<Record<string, string>>({});
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [resource, setResource] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .myAccessRequests()
      .then((r) => {
        setRequestable(r.requestable);
        setRequests(r.requests);
        setResource((cur) => cur || Object.keys(r.requestable)[0] || "");
      })
      .catch((e) => (e instanceof ApiError && e.status === 401 ? onExpired() : setError(String(e))));
  }, [onExpired]);
  useEffect(load, [load]);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.requestAccess(resource, reason);
      setReason("");
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[380px_minmax(0,1fr)]">
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <KeyRound className="h-4 w-4 text-emerald-400" /> Request access
        </h2>
        <label className="block text-xs text-slate-400">
          Resource
          <select
            value={resource}
            onChange={(e) => setResource(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-sm text-slate-100"
          >
            {Object.entries(requestable).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
        </label>
        <label className="mt-3 block text-xs text-slate-400">
          Business reason
          <textarea
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="e.g. month-end reconciliation for the Chennai branch"
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-sm text-slate-100"
          />
        </label>
        <button
          disabled={busy || reason.trim().length < 5 || !resource}
          onClick={submit}
          className="mt-3 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />} Submit request
        </button>
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Your requests</h2>
        {requests.length === 0 ? (
          <p className="text-sm text-slate-500">You have not requested anything yet.</p>
        ) : (
          <ul className="space-y-2">
            {requests.map((r) => (
              <li key={r.id} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-slate-500">{r.id}</span>
                  <span className="text-slate-100">{r.resource_name}</span>
                  <span className={`ml-auto rounded px-2 py-0.5 text-xs ${STATUS_STYLE[r.status]}`}>{r.status}</span>
                </div>
                <div className="mt-1 text-xs text-slate-400">“{r.reason}” · approver {r.approver}</div>
                {r.decided_by && (
                  <div className="mt-0.5 text-xs text-slate-500">
                    Decided by {r.decided_by}{r.note ? `: ${r.note}` : ""}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
