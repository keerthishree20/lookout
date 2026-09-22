import { ArrowRightLeft, FileWarning, Fingerprint, Loader2, Search, ShieldOff, UserX } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { ExportRecord, HoneypotListing, TraceResult, TransferDecoy } from "@/lib/types";

import { ActionChip, Button, Card, Empty } from "./ui";

const inr = (n: number) => `₹${n.toLocaleString("en-IN", { maximumFractionDigits: 0 })}`;

export function HoneypotPanel({ refreshKey, analyst }: { refreshKey: number; analyst: string }) {
  const [data, setData] = useState<HoneypotListing | null>(null);
  const [q, setQ] = useState("");
  const [trace, setTrace] = useState<TraceResult | null>(null);
  const [tracing, setTracing] = useState(false);

  const load = useCallback(() => {
    api.honeypots().then(setData).catch(() => {});
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load, refreshKey]);

  async function runTrace(needle = q) {
    if (needle.trim().length < 4) return;
    setTracing(true);
    try {
      setTrace(await api.trace(needle));
    } finally {
      setTracing(false);
    }
  }

  const served = data?.served ?? [];
  const transfers = data?.transfer_decoys ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-xl border border-fuchsia-500/30 bg-fuchsia-500/5 p-3 text-xs leading-relaxed text-fuchsia-100/90">
        <FileWarning className="mt-0.5 h-4 w-4 shrink-0" />
        <p>
          When an employee does something <strong>high-risk</strong> (exports {data?.threshold ?? 100}+ customers,
          makes a suspicious transfer, or trips any detector hard enough), they are silently moved into the{" "}
          <strong>honeypot</strong>. Their portal keeps looking exactly the same, but from then on it runs on fake
          data. Exports are decoy PDFs whose hidden fields are fabricated. Transfers show success, a reference and a
          debited balance, but <strong>no money moves</strong>. Every fake account number and transaction reference
          is traceable, and everything they do is recorded here.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card
          title={`Decoys served (${served.length + transfers.length})`}
          icon={<FileWarning className="h-4 w-4 text-fuchsia-400" />}
          className="lg:col-span-2"
        >
          {served.length + transfers.length === 0 ? (
            <Empty>
              No decoys yet. Sign in as an employee in another tab and export {data?.threshold ?? 100}+ customers, or
              transfer ₹4.8 lakh to an outside account.
            </Empty>
          ) : (
            <ul className="space-y-2">
              {transfers.map((t) => (
                <li key={t.reference} className="rounded-lg border border-red-500/40 bg-zinc-950/40 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <ArrowRightLeft className="h-4 w-4 text-red-300" />
                      <span className="font-medium text-zinc-100">{t.actor}</span>
                      <span className="text-xs text-zinc-500">{humanise(t.role)}</span>
                      <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase text-red-200">
                        fake transfer
                      </span>
                    </div>
                    <span className="font-mono text-xs text-zinc-500">{dateTime(t.ts)}</span>
                  </div>
                  <div className="mt-1.5 text-sm text-zinc-300">
                    Tried to move <strong>{inr(t.amount)}</strong> from {t.from_name} (
                    <span className="font-mono">•••• {t.from_account.slice(-4)}</span>) to{" "}
                    {t.to_name || "—"} (<span className="font-mono">•••• {t.to_account.slice(-4)}</span>, {t.to_ifsc}
                    {t.external ? ", outside bank" : ""})
                  </div>
                  <div className="mt-1 text-xs text-zinc-400">
                    Shown: <span className="text-emerald-300">success</span>, balance {inr(t.shown_balance_after)} ·{" "}
                    Real money moved: <strong className="text-red-300">{t.real_funds_moved ? "YES" : "No"}</strong>
                  </div>
                  <div className="mt-1 text-xs text-zinc-500">Why: {t.reason}</div>
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                    <button
                      onClick={() => {
                        setQ(t.reference);
                        runTrace(t.reference);
                      }}
                      className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-red-200 hover:bg-zinc-700"
                    >
                      {t.reference}
                    </button>
                    <span className="text-zinc-500">risk engine: {t.risk_total.toFixed(0)}</span>
                    <ActionChip action={t.action_taken} />
                    <span className="font-mono text-zinc-600">audit #{t.audit_seq}</span>
                  </div>
                </li>
              ))}
              {served.map((r) => (
                <li key={r.doc_ref} className="rounded-lg border border-fuchsia-500/30 bg-zinc-950/40 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <UserX className="h-4 w-4 text-fuchsia-300" />
                      <span className="font-medium text-zinc-100">{r.actor}</span>
                      <span className="text-xs text-zinc-500">{humanise(r.role)}</span>
                    </div>
                    <span className="font-mono text-xs text-zinc-500">{dateTime(r.ts)}</span>
                  </div>
                  <div className="mt-1.5 text-sm text-zinc-300">
                    Asked for <strong>{r.requested.toLocaleString()}</strong> customer records → received a decoy
                    with <strong>{r.canary_count}</strong> canary accounts
                  </div>
                  <div className="mt-1 text-xs text-zinc-500">Why: {r.reason}</div>
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                    <button
                      onClick={() => {
                        setQ(r.doc_ref);
                        runTrace(r.doc_ref);
                      }}
                      className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-fuchsia-200 hover:bg-zinc-700"
                      title="Trace this document"
                    >
                      {r.doc_ref}
                    </button>
                    <span className="text-zinc-500">risk engine: {r.risk_total.toFixed(0)}</span>
                    <ActionChip action={r.action_taken} />
                    <span className="font-mono text-zinc-600">audit #{r.audit_seq}</span>
                  </div>
                  {r.canaries && r.canaries.length > 0 && (
                    <details className="mt-2 text-xs text-zinc-500">
                      <summary className="cursor-pointer select-none hover:text-zinc-300">
                        Canary account numbers
                      </summary>
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {r.canaries.slice(0, 24).map((a) => (
                          <button
                            key={a}
                            onClick={() => {
                              setQ(a);
                              runTrace(a);
                            }}
                            className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-[11px] text-zinc-400 ring-1 ring-zinc-800 hover:text-zinc-200"
                          >
                            {a}
                          </button>
                        ))}
                        {r.canaries.length > 24 && <span className="px-1">+{r.canaries.length - 24} more</span>}
                      </div>
                    </details>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <div className="space-y-4">
          <Card title="Trace a leaked file" icon={<Fingerprint className="h-4 w-4 text-sky-400" />}>
            <p className="mb-2 text-xs leading-relaxed text-zinc-500">
              Paste a PDF footer reference, a leaked account number, or a transaction reference / UTR.
            </p>
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                runTrace();
              }}
            >
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="MB-DOC-…, MBTXN…, or 5021 …"
                className="min-w-0 flex-1 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 font-mono text-xs text-zinc-200"
                aria-label="Document reference or account number"
              />
              <Button type="submit" variant="primary" disabled={tracing || q.trim().length < 4}>
                {tracing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              </Button>
            </form>
            {trace && (
              <div
                className={`mt-3 rounded-lg p-3 text-sm ring-1 ring-inset ${
                  !trace.found
                    ? "bg-zinc-900 text-zinc-400 ring-zinc-800"
                    : trace.kind === "transfer" || (trace.record as ExportRecord)?.decoy
                      ? "bg-fuchsia-500/10 text-fuchsia-100 ring-fuchsia-500/40"
                      : "bg-sky-500/10 text-sky-100 ring-sky-500/30"
                }`}
              >
                {!trace.found ? (
                  "No match. It is not one of ours, or it predates this ledger."
                ) : trace.kind === "transfer" ? (
                  <>
                    <div className="font-medium">Fake transfer by {(trace.record as TransferDecoy).actor}</div>
                    <div className="mt-1 text-xs opacity-80">
                      {inr((trace.record as TransferDecoy).amount)} · {dateTime(trace.record!.ts)} · no money moved
                    </div>
                  </>
                ) : (
                  <>
                    <div className="font-medium">
                      {(trace.record as ExportRecord).decoy ? "Decoy" : "Genuine export"} issued to {trace.record!.actor}
                    </div>
                    <div className="mt-1 text-xs opacity-80">
                      matched by {trace.matched_by === "doc_ref" ? "document reference" : "canary account number"} ·{" "}
                      {(trace.record as ExportRecord).requested} records · {dateTime(trace.record!.ts)} ·{" "}
                      {(trace.record as ExportRecord).filename}
                    </div>
                  </>
                )}
              </div>
            )}
          </Card>

          <Card title="In the honeypot" icon={<ShieldOff className="h-4 w-4 text-amber-400" />}>
            <p className="mb-2 text-xs leading-relaxed text-zinc-500">
              These employees see only fake data, even after signing in again. Clear someone once the
              investigation is closed: their fake transfers disappear from their view and the clearance is
              written to the signed audit log.
            </p>
            {(data?.watch ?? []).length === 0 ? (
              <Empty>Nobody is in the honeypot.</Empty>
            ) : (
              <ul className="space-y-2">
                {data!.watch.map((w) => (
                  <li key={w.actor} className="rounded-md bg-zinc-950/40 p-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium text-zinc-200">{w.actor}</span>
                      <Button
                        variant="ghost"
                        className="text-xs"
                        onClick={async () => {
                          await api.clearWatchlist(w.actor, analyst);
                          load();
                        }}
                      >
                        Clear
                      </Button>
                    </div>
                    <div className="mt-0.5 text-[11px] text-zinc-500">
                      since {dateTime(w.since)} · {w.reason}
                    </div>
                    {w.activity.length > 0 && (
                      <details className="mt-1.5 text-xs" open>
                        <summary className="cursor-pointer select-none text-zinc-400 hover:text-zinc-200">
                          Activity in the honeypot ({w.activity.length})
                        </summary>
                        <ol className="mt-1.5 space-y-1 border-l border-zinc-800 pl-3">
                          {w.activity.slice(0, 12).map((a, i) => (
                            <li key={i} className="text-zinc-400">
                              <span className="font-mono text-[10px] text-zinc-600">
                                {new Date(a.ts).toLocaleTimeString("en-GB")}
                              </span>{" "}
                              {a.what}
                              {typeof a.amount === "number" && <> · {inr(a.amount)}</>}
                              {typeof a.records === "number" && <> · {a.records} records</>}
                            </li>
                          ))}
                        </ol>
                      </details>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>

      <Card title="All customer exports" icon={<Search className="h-4 w-4 text-zinc-400" />}>
        {(data?.exports ?? []).length === 0 ? (
          <Empty>No exports yet.</Empty>
        ) : (
          <div className="-mx-4 -mb-4 overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="px-4 py-2 font-medium">When</th>
                  <th className="px-2 py-2 font-medium">Employee</th>
                  <th className="px-2 py-2 font-medium">Records</th>
                  <th className="px-2 py-2 font-medium">Served</th>
                  <th className="px-2 py-2 font-medium">Risk</th>
                  <th className="px-4 py-2 font-medium">Reference</th>
                </tr>
              </thead>
              <tbody>
                {data!.exports.map((r) => (
                  <tr key={r.doc_ref} className="border-t border-zinc-800/70">
                    <td className="px-4 py-2 font-mono text-xs text-zinc-500">{dateTime(r.ts)}</td>
                    <td className="px-2 py-2 text-zinc-200">{r.actor}</td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-300">{r.requested}</td>
                    <td className="px-2 py-2">
                      {r.decoy ? (
                        <span className="rounded-md bg-fuchsia-500/10 px-2 py-0.5 text-xs text-fuchsia-200 ring-1 ring-fuchsia-500/40">
                          Decoy
                        </span>
                      ) : (
                        <span className="rounded-md bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300 ring-1 ring-zinc-700">
                          Genuine
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-400">{r.risk_total.toFixed(0)}</td>
                    <td className="px-4 py-2 font-mono text-xs text-zinc-500">{r.doc_ref}</td>
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
