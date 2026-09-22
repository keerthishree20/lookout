import { Binoculars, KeyRound, Loader2, LogIn, ShieldCheck, UserRound } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";

import { API_URL, ApiError, api, type SignInContext } from "@/lib/api";
import { humanise } from "@/lib/format";
import { saveSession, type StoredSession } from "@/lib/session";
import type { DemoAccount, MfaChallenge } from "@/lib/types";

/** Demo presets for where a sign-in claims to come from (the portal is on the
 *  intranet, so by default it is the employee's own desk). */
const CONTEXTS: { label: string; ctx: SignInContext }[] = [
  { label: "Usual desk (normal)", ctx: {} },
  { label: "New laptop at 02:30", ctx: { at_hour: 2, device_id: "LT-NEW-4410", ip: "203.0.113.9" } },
  {
    label: "02:30, new device, new country, unknown IP",
    ctx: { at_hour: 2, device_id: "LT-UNKNOWN-7731", city: "Singapore", ip: "203.0.113.77" },
  },
  { label: "Signing in from New York", ctx: { city: "New York", ip: "198.51.100.23" } },
];

export function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [accounts, setAccounts] = useState<DemoAccount[]>([]);
  const [preset, setPreset] = useState(0);
  const [mfa, setMfa] = useState<MfaChallenge | null>(null);
  const [otp, setOtp] = useState("");

  function enter(s: StoredSession) {
    saveSession(s);
    navigate(s.kind === "employee" ? "/employee" : "/dashboard", { replace: true });
  }

  useEffect(() => {
    api.demoAccounts().then(setAccounts).catch(() => setError(`Cannot reach the Lookout API at ${API_URL}.`));
  }, []);

  async function submit(u = username, p = password) {
    setBusy(true);
    setError(null);
    try {
      const r = await api.login(u.trim(), p, CONTEXTS[preset].ctx);
      if ("mfa_required" in r) {
        setMfa(r);
        setOtp("");
      } else {
        enter(r);
      }
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.status === 403
            ? "Sign-in blocked by security policy."
            : "Wrong username or password."
          : `Cannot reach the Lookout API at ${API_URL}.`,
      );
    } finally {
      setBusy(false);
    }
  }

  const soc = accounts.filter((a) => a.kind !== "employee");
  const staff = accounts.filter((a) => a.kind === "employee");

  return (
    <div className="mx-auto grid min-h-screen w-full max-w-6xl grid-cols-[minmax(0,1fr)] items-start gap-8 px-4 py-10 sm:px-6 lg:grid-cols-[380px_minmax(0,1fr)] lg:py-16">
      <div>
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-gradient-to-br from-sky-500 to-violet-600 shadow-lg shadow-sky-900/40">
            <Binoculars className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-zinc-50">Meridian Bank</h1>
            <p className="text-xs text-zinc-500">Staff sign-in · protected by Lookout</p>
          </div>
        </div>

        <form
          className="space-y-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-5"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <label className="block text-xs text-zinc-400">
            Username or work email
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            />
          </label>
          <label className="block text-xs text-zinc-400">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            />
          </label>
          <label className="block text-xs text-zinc-400">
            Sign-in context <span className="text-zinc-600">(simulation)</span>
            <select
              value={preset}
              onChange={(e) => setPreset(Number(e.target.value))}
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            >
              {CONTEXTS.map((c, i) => (
                <option key={c.label} value={i}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <button
            type="submit"
            disabled={busy || !username || !password}
            className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-sky-500 disabled:opacity-50"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <LogIn className="h-4 w-4" />}
            Sign in
          </button>
          <p className="text-xs leading-relaxed text-zinc-500">
            Every sign-in, including a wrong password, is scored by Lookout: time, device, IP, location, failed
            attempts, privilege and impossible travel. A medium-risk sign-in asks for a one-time code.
          </p>
        </form>

        {mfa && (
          <form
            className="mt-4 space-y-3 rounded-xl border border-amber-500/40 bg-amber-500/5 p-5"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError(null);
              try {
                enter(await api.verifyMfa(mfa.challenge_id, otp));
              } catch (err) {
                setError(err instanceof ApiError ? err.detail : "Verification failed.");
                if (err instanceof ApiError && /again/.test(err.detail)) setMfa(null);
              } finally {
                setBusy(false);
              }
            }}
          >
            <h2 className="flex items-center gap-2 text-sm font-semibold text-amber-200">
              <ShieldCheck className="h-4 w-4" /> Additional verification required
            </h2>
            <p className="text-xs text-zinc-400">
              This sign-in looks unusual ({mfa.risk.risk_level.toLowerCase()} risk), so a second factor is needed.
            </p>
            <ul className="list-disc space-y-0.5 pl-4 text-xs text-zinc-400">
              {mfa.risk.reason.slice(0, 3).map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
            <p className="rounded-md bg-zinc-950 px-3 py-2 text-xs text-zinc-400">
              Simulated {humanise(mfa.factor)}: your code is <span className="font-mono text-amber-200">{mfa.demo_otp}</span>
            </p>
            <input
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
              inputMode="numeric"
              aria-label="One-time code"
              placeholder="6-digit code"
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm tracking-widest text-zinc-100"
            />
            <button
              type="submit"
              disabled={busy || otp.length !== 6}
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-amber-600 px-3 py-2 text-sm font-medium text-white hover:bg-amber-500 disabled:opacity-50"
            >
              Verify and sign in
            </button>
          </form>
        )}
      </div>

      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
        <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-3">
          <KeyRound className="h-4 w-4 text-amber-400" />
          <h2 className="text-sm font-semibold text-zinc-200">Demo accounts</h2>
          <span className="ml-auto text-xs text-zinc-500">simulated bank · click a row to sign in</span>
        </div>
        <div className="p-4">
          <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-violet-300">
            <ShieldCheck className="h-3.5 w-3.5" /> Security operations &amp; administration
          </h3>
          <AccountTable rows={soc} onPick={(a) => submit(a.username, a.password)} fill={(a) => { setUsername(a.username); setPassword(a.password); }} />
          <h3 className="mb-2 mt-5 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-sky-300">
            <UserRound className="h-3.5 w-3.5" /> Employees ({staff.length})
          </h3>
          <AccountTable rows={staff} onPick={(a) => submit(a.username, a.password)} fill={(a) => { setUsername(a.username); setPassword(a.password); }} />
        </div>
      </div>
    </div>
  );
}

function AccountTable({
  rows,
  onPick,
  fill,
}: {
  rows: DemoAccount[];
  onPick: (a: DemoAccount) => void;
  fill: (a: DemoAccount) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[520px] text-left text-sm">
        <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
          <tr>
            <th className="py-1.5 pr-2 font-medium">#</th>
            <th className="py-1.5 pr-2 font-medium">Username</th>
            <th className="py-1.5 pr-2 font-medium">Password</th>
            <th className="py-1.5 pr-2 font-medium">Role</th>
            <th className="py-1.5 pr-2 font-medium">Branch</th>
            <th className="py-1.5" />
          </tr>
        </thead>
        <tbody>
          {rows.map((a, i) => (
            <tr key={a.username} className="border-t border-zinc-800/70">
              <td className="py-1.5 pr-2 font-mono text-xs text-zinc-600">{i + 1}</td>
              <td className="py-1.5 pr-2">
                <button onClick={() => fill(a)} className="font-mono text-zinc-200 hover:text-sky-300" title="Fill the form">
                  {a.username}
                </button>
              </td>
              <td className="py-1.5 pr-2 font-mono text-xs text-zinc-400">{a.password}</td>
              <td className="py-1.5 pr-2 text-xs text-zinc-400">{humanise(a.role)}</td>
              <td className="py-1.5 pr-2 text-xs text-zinc-500">{a.city}</td>
              <td className="py-1.5 text-right">
                <button
                  onClick={() => onPick(a)}
                  className="rounded-md px-2 py-0.5 text-xs text-sky-300 ring-1 ring-inset ring-sky-500/40 hover:bg-sky-500/10"
                  aria-label={`Sign in as ${a.username}`}
                >
                  Sign in
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
