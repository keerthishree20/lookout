"use client";

// The employee's view of the bank. It deliberately knows nothing about Lookout:
// no risk scores, no alerts, and no way to tell a genuine export from a decoy.
// If this page could tell, so could the insider.

import {
  Building2,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Download,
  FileDown,
  Loader2,
  LogOut,
  Search,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api";
import { humanise } from "@/lib/format";
import { clearSession, loadSession, type Profile } from "@/lib/session";
import type { MaskedCustomer } from "@/lib/types";

const PAGE = 50;
const QUICK = [10, 25, 50, 100, 250];

interface Download {
  filename: string;
  records: number;
  at: string;
}

export default function EmployeePortal() {
  const router = useRouter();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [rows, setRows] = useState<MaskedCustomer[]>([]);
  const [total, setTotal] = useState(0);
  const [maxExport, setMaxExport] = useState(500);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [count, setCount] = useState(10);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloads, setDownloads] = useState<Download[]>([]);

  const expired = useCallback(() => {
    clearSession();
    router.replace("/login");
  }, [router]);

  useEffect(() => {
    const s = loadSession();
    if (!s || s.kind !== "employee") {
      router.replace("/login");
      return;
    }
    setProfile(s.profile);
  }, [router]);

  useEffect(() => {
    if (!profile) return;
    api
      .customers(query, offset, PAGE)
      .then((page) => {
        setRows(page.rows);
        setTotal(page.total);
        setMaxExport(page.max_export);
      })
      .catch((e) => (e instanceof ApiError && e.status === 401 ? expired() : setError(String(e))));
  }, [profile, query, offset, expired]);

  async function download(body: { count?: number; customer_ids?: string[] }, records: number) {
    setBusy(true);
    setError(null);
    try {
      const { blob, filename } = await api.exportPdf(body);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      setDownloads((d) => [{ filename, records, at: new Date().toLocaleTimeString("en-GB") }, ...d].slice(0, 8));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return expired();
      setError(e instanceof ApiError ? e.detail : "Export failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    await api.logout().catch(() => {});
    clearSession();
    router.replace("/login");
  }

  function toggle(id: string) {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  if (!profile) return null;

  const pageIds = rows.map((r) => r.customer_id);
  const allOnPage = pageIds.length > 0 && pageIds.every((id) => selected.has(id));

  return (
    <div className="min-h-screen bg-slate-950">
      <header className="border-b border-slate-800 bg-slate-900/80">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="grid h-9 w-9 place-items-center rounded-lg bg-emerald-600">
              <Building2 className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="text-base font-semibold text-slate-50">Meridian Bank · Core Portal</div>
              <div className="text-xs text-slate-400">Customer relationship workspace</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-sm font-medium text-slate-100">{profile.username}</div>
              <div className="text-xs text-slate-400">
                {humanise(profile.role)} · {profile.city}
              </div>
            </div>
            <button
              onClick={signOut}
              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm text-slate-300 ring-1 ring-inset ring-slate-700 hover:bg-slate-800"
            >
              <LogOut className="h-4 w-4" /> Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto grid max-w-[1400px] gap-5 px-4 py-6 sm:px-6 lg:grid-cols-[1fr_320px]">
        {/* directory */}
        <section className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/60">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-4 py-3">
            <h1 className="text-sm font-semibold text-slate-100">
              Customer directory <span className="font-normal text-slate-500">· {total.toLocaleString()} customers</span>
            </h1>
            <form
              className="flex items-center gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                setOffset(0);
                setQuery(q);
              }}
            >
              <div className="relative">
                <Search className="pointer-events-none absolute left-2 top-2 h-4 w-4 text-slate-500" />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Name, ID or city"
                  className="w-52 rounded-md border border-slate-700 bg-slate-950 py-1.5 pl-8 pr-2 text-sm text-slate-100"
                  aria-label="Search customers"
                />
              </div>
            </form>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-sm">
              <thead className="bg-slate-900 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="w-10 px-4 py-2">
                    <input
                      type="checkbox"
                      checked={allOnPage}
                      onChange={() =>
                        setSelected((s) => {
                          const next = new Set(s);
                          pageIds.forEach((id) => (allOnPage ? next.delete(id) : next.add(id)));
                          return next;
                        })
                      }
                      aria-label="Select all on this page"
                    />
                  </th>
                  <th className="px-2 py-2 font-medium">Customer</th>
                  <th className="px-2 py-2 font-medium">Account</th>
                  <th className="px-2 py-2 font-medium">Product</th>
                  <th className="px-2 py-2 font-medium">City</th>
                  <th className="px-2 py-2 font-medium">Phone</th>
                  <th className="px-2 py-2 font-medium">Email</th>
                  <th className="px-4 py-2 font-medium">KYC</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr
                    key={c.customer_id}
                    className={`border-t border-slate-800/70 ${selected.has(c.customer_id) ? "bg-emerald-500/5" : "hover:bg-slate-800/40"}`}
                  >
                    <td className="px-4 py-2">
                      <input
                        type="checkbox"
                        checked={selected.has(c.customer_id)}
                        onChange={() => toggle(c.customer_id)}
                        aria-label={`Select ${c.name}`}
                      />
                    </td>
                    <td className="px-2 py-2">
                      <div className="text-slate-100">{c.name}</div>
                      <div className="font-mono text-[11px] text-slate-500">{c.customer_id}</div>
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-300">{c.account_no}</td>
                    <td className="px-2 py-2 text-slate-300">{c.product}</td>
                    <td className="px-2 py-2 text-slate-400">{c.city}</td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-400">{c.phone}</td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-400">{c.email}</td>
                    <td className="px-4 py-2">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[11px] ${
                          c.kyc === "Verified" ? "bg-emerald-500/10 text-emerald-300" : "bg-amber-500/10 text-amber-300"
                        }`}
                      >
                        {c.kyc}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between border-t border-slate-800 px-4 py-2 text-xs text-slate-500">
            <span>
              {total ? offset + 1 : 0}–{Math.min(offset + PAGE, total)} of {total.toLocaleString()} · sensitive
              fields masked on screen
            </span>
            <div className="flex gap-1">
              <button
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE))}
                className="rounded p-1 hover:bg-slate-800 disabled:opacity-30"
                aria-label="Previous page"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                disabled={offset + PAGE >= total}
                onClick={() => setOffset(offset + PAGE)}
                className="rounded p-1 hover:bg-slate-800 disabled:opacity-30"
                aria-label="Next page"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </section>

        {/* export */}
        <aside className="space-y-5">
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <h2 className="mb-1 flex items-center gap-2 text-sm font-semibold text-slate-100">
              <FileDown className="h-4 w-4 text-emerald-400" /> Export customer data
            </h2>
            <p className="mb-4 text-xs leading-relaxed text-slate-400">
              Downloads a PDF with full, unmasked account details.
            </p>

            <button
              disabled={busy || selected.size === 0}
              onClick={() => download({ customer_ids: [...selected] }, selected.size)}
              className="mb-4 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-slate-800 px-3 py-2 text-sm text-slate-100 ring-1 ring-inset ring-slate-700 hover:bg-slate-700 disabled:opacity-40"
            >
              <Download className="h-4 w-4" />
              Export selected ({selected.size})
            </button>

            <div className="mb-2 text-xs text-slate-400">Or export the first N customers</div>
            <div className="mb-2 flex flex-wrap gap-1.5">
              {QUICK.map((n) => (
                <button
                  key={n}
                  onClick={() => setCount(n)}
                  className={`rounded-md px-2.5 py-1 text-xs ring-1 ring-inset ${
                    count === n ? "bg-emerald-600/20 text-emerald-200 ring-emerald-500/50" : "text-slate-300 ring-slate-700 hover:bg-slate-800"
                  }`}
                >
                  {n}
                </button>
              ))}
            </div>
            <input
              type="number"
              min={1}
              max={maxExport}
              value={count}
              onChange={(e) => setCount(Math.min(maxExport, Math.max(1, Number(e.target.value) || 1)))}
              className="mb-3 w-full rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-sm text-slate-100"
              aria-label="Number of customers to export"
            />
            <button
              disabled={busy}
              onClick={() => download({ count }, count)}
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
              Download PDF ({count} customers)
            </button>
            {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
          </section>

          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <h2 className="mb-3 text-sm font-semibold text-slate-100">Recent downloads</h2>
            {downloads.length === 0 ? (
              <p className="text-xs text-slate-500">Nothing downloaded this session.</p>
            ) : (
              <ul className="space-y-2">
                {downloads.map((d, i) => (
                  <li key={`${d.filename}-${i}`} className="flex items-start gap-2 text-xs">
                    <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                    <div className="min-w-0">
                      <div className="truncate font-mono text-slate-300">{d.filename}</div>
                      <div className="text-slate-500">
                        {d.records} customers · {d.at}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
      </main>
    </div>
  );
}
