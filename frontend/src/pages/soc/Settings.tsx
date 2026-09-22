import { Cog, Database, Lock, ShieldCheck, UserCog } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { Button, Card } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { ApiError, api } from "@/lib/api";
import { humanise } from "@/lib/format";
import { loadSession } from "@/lib/session";
import type { AccountRow, CryptoStatus, DbStatus, RoleRow, RuntimeConfig } from "@/lib/types";

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
      {loadSession()?.kind === "superadmin" && (
        <>
          <RolesCard />
          <SystemConfigCard />
        </>
      )}
    </div>
  );
}

/** Super Admin: every role, what it reaches, and the privilege each protected
 *  system requires. */
function RolesCard() {
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [levels, setLevels] = useState<Record<string, number>>({});
  const [msg, setMsg] = useState<string | null>(null);
  const load = useCallback(() => {
    api.roles().then((r) => {
      setRoles(r.roles);
      setLevels(r.resource_min_level);
    }).catch(() => {});
  }, []);
  useEffect(load, [load]);
  return (
    <Card title="Roles and permissions" icon={<ShieldCheck className="h-4 w-4 text-sky-400" />} className="xl:col-span-3">
      <div className="-mx-4 overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-xs">
          <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
            <tr>
              <th className="px-4 py-2 font-medium">Role</th>
              <th className="px-2 py-2 font-medium">Level</th>
              <th className="px-2 py-2 font-medium">Members</th>
              <th className="px-2 py-2 font-medium">Protected systems</th>
              <th className="px-2 py-2 font-medium">Messaging</th>
              <th className="px-4 py-2 text-right font-medium">Transfer limit</th>
            </tr>
          </thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r.role} className="border-t border-zinc-800/70">
                <td className="px-4 py-1.5 text-zinc-200">
                  {humanise(r.role)}
                  {r.privileged_administrator && <span className="ml-1 text-[10px] text-amber-300">privileged</span>}
                </td>
                <td className="px-2 py-1.5 font-mono text-zinc-400">{r.privilege_level}</td>
                <td className="px-2 py-1.5 text-zinc-400">{r.members.join(", ") || "—"}</td>
                <td className="px-2 py-1.5 text-zinc-400">{r.resources.map(humanise).join(", ") || "—"}</td>
                <td className="px-2 py-1.5 text-zinc-400">{r.bulk_messaging ? "customers, bulk" : r.customer_messaging ? "customers" : "internal only"}</td>
                <td className="px-4 py-1.5 text-right font-mono text-zinc-400">{r.transfer_limit ? `₹${r.transfer_limit.toLocaleString("en-IN")}` : "none"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h3 className="mb-2 mt-4 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Minimum privilege level per protected system</h3>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        {Object.entries(levels).map(([res, lvl]) => (
          <label key={res} className="flex items-center justify-between gap-2 text-xs text-zinc-300">
            {humanise(res)}
            <input
              type="number"
              min={1}
              max={6}
              value={lvl}
              onChange={(e) => setLevels({ ...levels, [res]: Number(e.target.value) })}
              className="w-16 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-zinc-100"
            />
          </label>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-3">
        <Button
          variant="primary"
          onClick={() =>
            api
              .updateRoles(levels)
              .then((r) => {
                setMsg(`${Object.keys(r.changed).length} permission change(s) saved and audited.`);
                load();
              })
              .catch((e) => setMsg(e instanceof ApiError ? e.detail : String(e)))
          }
        >
          Save permissions
        </Button>
        {msg && <span className="text-xs text-zinc-400">{msg}</span>}
      </div>
    </Card>
  );
}

/** Super Admin: operational settings, changed without a restart. */
function SystemConfigCard() {
  const [cfg, setCfg] = useState<RuntimeConfig | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    api.config().then(setCfg).catch(() => {});
  }, []);
  if (!cfg) return null;
  const flags: [keyof RuntimeConfig, string][] = [
    ["live_traffic", "Background demo traffic"],
    ["login_mfa", "Ask for a one-time code on medium-risk sign-ins"],
    ["show_demo_accounts", "List demo accounts on the sign-in page"],
    ["allow_tamper_demo", "Allow the forgery / tamper demo buttons"],
  ];
  return (
    <Card title="System configuration" icon={<Cog className="h-4 w-4 text-sky-400" />} className="xl:col-span-3">
      <div className="grid gap-2 sm:grid-cols-2">
        {flags.map(([k, label]) => (
          <label key={k} className="flex items-center gap-2 text-sm text-zinc-300">
            <input type="checkbox" checked={Boolean(cfg[k])} onChange={(e) => setCfg({ ...cfg, [k]: e.target.checked })} />
            {label}
          </label>
        ))}
        <label className="flex items-center gap-2 text-sm text-zinc-300">
          Traffic interval
          <input
            type="number"
            step={0.5}
            min={0.3}
            value={cfg.traffic_interval}
            onChange={(e) => setCfg({ ...cfg, traffic_interval: Number(e.target.value) })}
            className="w-20 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-zinc-100"
          />
          seconds
        </label>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <Button
          variant="primary"
          onClick={() =>
            api
              .updateConfig(cfg)
              .then((r) => {
                setCfg(r.config);
                setMsg(`${Object.keys(r.changed).length} setting(s) changed and audited.`);
              })
              .catch((e) => setMsg(e instanceof ApiError ? e.detail : String(e)))
          }
        >
          Save configuration
        </Button>
        {msg && <span className="text-xs text-zinc-400">{msg}</span>}
      </div>
    </Card>
  );
}
