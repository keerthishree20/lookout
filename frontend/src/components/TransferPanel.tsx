// The fund-transfer page. One component for real and honeypot transfers alike:
// the server decides which ledger the numbers land in, and nothing on this
// page can tell. A second "decoy" page would be the tell.

import { ArrowRightLeft, CheckCircle2, Landmark, Loader2, Search, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api";
import type { AccountView, Receipt } from "@/lib/types";

const inr = (n: number) =>
  `₹${n.toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

const PAYEES = [
  { label: "Another Meridian customer", to: "C100010", name: "", ifsc: "MERB0000001" },
  { label: "Outside account (HDFC)", to: "918877665544", name: "Rakesh Traders", ifsc: "HDFC0001234" },
  { label: "Outside account (ICICI)", to: "776655443322", name: "S K Enterprises", ifsc: "ICIC0004321" },
];

export function TransferPanel({ onExpired }: { onExpired: () => void }) {
  const [from, setFrom] = useState("C100065");
  const [account, setAccount] = useState<AccountView | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [to, setTo] = useState("");
  const [toName, setToName] = useState("");
  const [ifsc, setIfsc] = useState("MERB0000001");
  const [amount, setAmount] = useState<number>(10000);
  const [remarks, setRemarks] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<{ id: string; sentTo: string; demo: string } | null>(null);
  const [code, setCode] = useState("");
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [history, setHistory] = useState<Receipt[]>([]);

  const fail = useCallback(
    (e: unknown, set: (m: string) => void) => {
      if (e instanceof ApiError && e.status === 401) return onExpired();
      set(e instanceof ApiError ? e.detail : "Something went wrong. Please try again.");
    },
    [onExpired],
  );

  const lookup = useCallback(
    async (key = from) => {
      setLookupError(null);
      try {
        setAccount(await api.account(key.trim()));
      } catch (e) {
        setAccount(null);
        fail(e, setLookupError);
      }
    },
    [from, fail],
  );

  const loadHistory = useCallback(() => {
    api.transfers().then(setHistory).catch((e) => fail(e, setError));
  }, [fail]);

  useEffect(() => {
    lookup();
    loadHistory();
    // Only on first render: later lookups are explicit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function done(r: Receipt) {
    setReceipt(r);
    setChallenge(null);
    setCode("");
    lookup(account?.customer_id ?? from);
    loadHistory();
  }

  async function submit() {
    setBusy(true);
    setError(null);
    setReceipt(null);
    try {
      const r = await api.transfer({
        from_account: account?.customer_id ?? from,
        to_account: to,
        to_name: toName,
        to_ifsc: ifsc,
        amount,
        remarks,
      });
      if (r.status === "SUCCESS") done(r.receipt);
      else setChallenge({ id: r.challenge_id, sentTo: r.sent_to, demo: r.demo_code });
    } catch (e) {
      fail(e, setError);
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    if (!challenge) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.verifyTransfer(challenge.id, code);
      if (r.status === "SUCCESS") done(r.receipt);
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setChallenge(null);
      fail(e, setError);
    } finally {
      setBusy(false);
    }
  }

  const input = "mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-sm text-slate-100";

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1fr)_380px]">
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <ArrowRightLeft className="h-4 w-4 text-emerald-400" /> Customer fund transfer (NEFT / IMPS)
        </h2>

        {/* source */}
        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Debit account</div>
          <div className="mt-2 flex gap-2">
            <input
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && lookup()}
              placeholder="Customer ID (C100001) or account number"
              className="min-w-0 flex-1 rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-sm text-slate-100"
              aria-label="Debit account"
            />
            <button
              onClick={() => lookup()}
              className="inline-flex items-center gap-1 rounded-md px-3 text-sm text-slate-200 ring-1 ring-inset ring-slate-700 hover:bg-slate-800"
            >
              <Search className="h-4 w-4" /> Look up
            </button>
          </div>
          {lookupError && <p className="mt-2 text-xs text-red-400">{lookupError}</p>}
          {account && (
            <div className="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <div>
                <div className="text-[11px] text-slate-500">Customer</div>
                <div className="text-slate-100">{account.name}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-500">Account</div>
                <div className="font-mono text-slate-300">{account.masked}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-500">Product</div>
                <div className="text-slate-300">{account.product}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-500">Available balance</div>
                <div className="font-mono text-emerald-300">{inr(account.balance)}</div>
              </div>
            </div>
          )}
        </div>

        {/* beneficiary */}
        <div className="mt-4">
          <div className="mb-2 flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Beneficiary</span>
            {PAYEES.map((p) => (
              <button
                key={p.label}
                onClick={() => {
                  setTo(p.to);
                  setToName(p.name);
                  setIfsc(p.ifsc);
                }}
                className="rounded-md px-2 py-0.5 text-[11px] text-slate-400 ring-1 ring-inset ring-slate-700 hover:bg-slate-800 hover:text-slate-200"
              >
                {p.label}
              </button>
            ))}
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <label className="text-xs text-slate-400">
              Account number / customer ID
              <input value={to} onChange={(e) => setTo(e.target.value)} className={`${input} font-mono`} />
            </label>
            <label className="text-xs text-slate-400">
              Beneficiary name
              <input value={toName} onChange={(e) => setToName(e.target.value)} className={input} />
            </label>
            <label className="text-xs text-slate-400">
              IFSC
              <input value={ifsc} onChange={(e) => setIfsc(e.target.value.toUpperCase())} className={`${input} font-mono`} />
            </label>
          </div>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <label className="text-xs text-slate-400">
            Amount (₹)
            <input
              type="number"
              min={1}
              value={amount}
              onChange={(e) => setAmount(Math.max(0, Number(e.target.value) || 0))}
              className={`${input} font-mono`}
            />
          </label>
          <label className="text-xs text-slate-400 sm:col-span-2">
            Remarks
            <input value={remarks} onChange={(e) => setRemarks(e.target.value)} className={input} />
          </label>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {[10_000, 50_000, 150_000, 480_000].map((n) => (
            <button
              key={n}
              onClick={() => setAmount(n)}
              className="rounded-md px-2 py-0.5 font-mono text-[11px] text-slate-400 ring-1 ring-inset ring-slate-700 hover:bg-slate-800 hover:text-slate-200"
            >
              {inr(n).replace(".00", "")}
            </button>
          ))}
        </div>

        <button
          disabled={busy || !account || !to || amount <= 0}
          onClick={submit}
          className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-3 py-2.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          {busy && !challenge ? <Loader2 className="h-4 w-4 animate-spin" /> : <Landmark className="h-4 w-4" />}
          Transfer {amount > 0 ? inr(amount).replace(".00", "") : ""}
        </button>
        {error && <p className="mt-2 text-sm text-red-400">{error}</p>}

        {receipt && (
          <div className="mt-5 rounded-xl border border-emerald-500/40 bg-emerald-500/5 p-4">
            <div className="flex items-center gap-2 text-emerald-300">
              <CheckCircle2 className="h-5 w-5" />
              <span className="font-semibold">Transfer successful</span>
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
              <dt className="text-slate-500">Reference</dt>
              <dd className="font-mono text-slate-100">{receipt.reference}</dd>
              <dt className="text-slate-500">UTR</dt>
              <dd className="font-mono text-slate-300">{receipt.utr}</dd>
              <dt className="text-slate-500">Amount</dt>
              <dd className="font-mono text-slate-100">{inr(receipt.amount)}</dd>
              <dt className="text-slate-500">From</dt>
              <dd className="text-slate-300">
                {receipt.from_name} · <span className="font-mono">{receipt.from_account}</span>
              </dd>
              <dt className="text-slate-500">To</dt>
              <dd className="text-slate-300">
                {receipt.to_name || "—"} · <span className="font-mono">{receipt.to_account}</span> · {receipt.to_ifsc}
              </dd>
              <dt className="text-slate-500">Balance after</dt>
              <dd className="font-mono text-slate-300">{inr(receipt.balance_after)}</dd>
              <dt className="text-slate-500">Time</dt>
              <dd className="text-slate-300">{new Date(receipt.ts).toLocaleString("en-GB")}</dd>
            </dl>
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Transfers you processed</h2>
        {history.length === 0 ? (
          <p className="text-xs text-slate-500">None yet.</p>
        ) : (
          <ul className="space-y-2">
            {history.map((t) => (
              <li key={t.reference} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-slate-100">{inr(t.amount)}</span>
                  <span className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-300">{t.status}</span>
                </div>
                <div className="mt-1 text-slate-400">
                  {t.from_name} <span className="font-mono">{t.from_account}</span> →{" "}
                  {t.to_name || "—"} <span className="font-mono">{t.to_account}</span>
                </div>
                <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                  {t.reference} · {new Date(t.ts).toLocaleTimeString("en-GB")}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {challenge && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-sm rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl">
            <div className="flex items-start justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <ShieldCheck className="h-4 w-4 text-amber-400" /> Additional verification
              </h3>
              <button onClick={() => setChallenge(null)} aria-label="Cancel" className="text-slate-500 hover:text-slate-300">
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="mt-2 text-sm text-slate-400">
              Enter the one-time code sent to your {challenge.sentTo}.
            </p>
            <input
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              onKeyDown={(e) => e.key === "Enter" && verify()}
              inputMode="numeric"
              className="mt-3 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-center font-mono text-xl tracking-[0.4em] text-slate-100"
              aria-label="One-time code"
            />
            <p className="mt-2 text-[11px] text-slate-500">
              Demo: no SMS is sent. Your code is <span className="font-mono text-slate-300">{challenge.demo}</span>
            </p>
            {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
            <button
              disabled={busy || code.length !== 6}
              onClick={verify}
              className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null} Verify and transfer
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
