import { Database, Lock, UserCog } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { Button, Card } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { ApiError, api } from "@/lib/api";
import { humanise } from "@/lib/format";
import { loadSession } from "@/lib/session";
import type { AccountRow, CryptoStatus, DbStatus } from "@/lib/types";

export function Settings() {
  const { version } = useLive();
  const me = loadSession()?.profile.username;
  const [accounts, setAccounts] = useState<AccountRow[]>([]);
  const [db, setDb] = useState<DbStatus | null>(null);
  const [crypto, setCrypto] = useState<CryptoStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.accounts().then(setAccounts).catch(() => {});
    api.dbStatus().then(setDb).catch(() => {});
    api.crypto().then(setCrypto).catch(() => {});
  }, []);
  useEffect(load, [load, version]);

  async function toggle(a: AccountRow) {
    setError(null);
    try {
      if (a.disabled) await api.enableAccount(a.username);
      else await api.disableAccount(a.username, "temporarily disabled from the console");
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    }
  }

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card title="Accounts" icon={<UserCog className="h-4 w-4 text-sky-400" />} className="xl:col-span-2">
        <p className="mb-2 text-xs text-zinc-500">
          Disabling signs the person out everywhere and refuses their next sign-in. Both actions are audited.
        </p>
        {error && <p className="mb-2 text-xs text-red-400">{error}</p>}
        <div className="-mx-4 -mb-4 overflow-x-auto">
          <table className="w-full min-w-[600px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">Account</th>
                <th className="px-2 py-2 font-medium">Role</th>
                <th className="px-2 py-2 font-medium">Level</th>
                <th className="px-2 py-2 font-medium">Sessions</th>
                <th className="px-2 py-2 font-medium">Status</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.username} className="border-t border-zinc-800/70">
                  <td className="px-4 py-2 text-zinc-200">{a.username}</td>
                  <td className="px-2 py-2 text-xs text-zinc-400">{humanise(a.role)}</td>
                  <td className="px-2 py-2 font-mono text-xs text-zinc-400">{a.privilege_level ?? "—"}</td>
                  <td className="px-2 py-2 font-mono text-xs text-zinc-400">{a.active_sessions}</td>
                  <td className="px-2 py-2 text-xs">
                    {a.disabled ? <span className="text-red-300" title={a.disabled_reason ?? ""}>disabled by {a.disabled_by}</span> : <span className="text-emerald-300">active</span>}
                  </td>
                  <td className="px-4 py-2 text-right">
                    {a.username !== me && (
                      <Button variant={a.disabled ? "default" : "ghost"} className="text-xs" onClick={() => toggle(a)}>
                        {a.disabled ? "Enable" : "Disable"}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="space-y-4">
        <Card title="Database" icon={<Database className="h-4 w-4 text-sky-400" />}>
          {!db ? (
            <p className="text-sm text-zinc-500">Loading…</p>
          ) : !db.enabled ? (
            <p className="text-sm text-zinc-400">
              Running in memory only. Set <code className="font-mono text-zinc-300">DATABASE_URL</code> to persist to
              PostgreSQL (Docker Compose does this for you).
            </p>
          ) : (
            <div className="space-y-2 text-xs">
              <div className="text-zinc-300">
                {db.dialect} · <span className="font-mono text-zinc-500">{db.url}</span>
              </div>
              <div className={db.audit_chain.ok ? "text-emerald-300" : "text-red-300"}>
                Stored audit chain {db.audit_chain.ok ? "verifies" : `broken at #${db.audit_chain.broken_at}`} ({db.audit_chain.rows} rows)
              </div>
              <table className="w-full">
                <tbody>
                  {Object.entries(db.rows).map(([t, n]) => (
                    <tr key={t} className="border-t border-zinc-800/60">
                      <td className="py-0.5 font-mono text-zinc-400">{t}</td>
                      <td className="py-0.5 text-right font-mono text-zinc-300">{n.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Cryptography" icon={<Lock className="h-4 w-4 text-violet-400" />}>
          {crypto && (
            <div className="space-y-1.5 text-xs text-zinc-400">
              <div>Audit signing: <span className="font-mono text-zinc-200">{crypto.signing.algorithm}</span> ({crypto.signing.standard})</div>
              <div>Credential sealing: <span className="font-mono text-zinc-200">{crypto.sealing.algorithm}</span> ({crypto.sealing.standard})</div>
              <div>Sessions and passwords: classical (PBKDF2-SHA256 hashes, HMAC-signed tokens). Post-quantum protection covers the long-lived artefacts only.</div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
