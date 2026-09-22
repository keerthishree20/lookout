import { AlertTriangle, CheckCircle2, KeyRound, Loader2, Skull } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { ApiError, api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { Alert, Artefact, CryptoLayer } from "@/lib/types";

import { Button, Card, Empty } from "./ui";

const FAMILY_STYLE: Record<string, string> = {
  "post-quantum": "text-violet-300",
  classical: "text-zinc-400",
  "classical hash": "text-zinc-400",
};

/** Spec section 29: what is sealed post-quantum, and how that is kept apart
 *  from the classical cryptography that signs people in. */
export function ProtectedStorePanel({ refreshKey }: { refreshKey: number }) {
  const [artefacts, setArtefacts] = useState<Artefact[]>([]);
  const [layers, setLayers] = useState<CryptoLayer[]>([]);
  const [result, setResult] = useState<{ ok: boolean; results: { name: string; ok: boolean; reason: string }[]; alert?: Alert } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [a, c] = await Promise.all([api.artefacts(), api.crypto()]);
    setArtefacts(a.artefacts);
    setLayers(c.layers ?? []);
  }, []);

  useEffect(() => {
    load().catch(() => {});
  }, [load, refreshKey]);

  async function run(key: string, fn: () => Promise<void>) {
    setBusy(key);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(null);
    }
  }

  const target = artefacts.find((a) => a.category === "credential")?.name;

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card
        title="Post-quantum protected store"
        icon={<KeyRound className="h-4 w-4 text-violet-400" />}
        right={<span className="font-mono text-xs text-zinc-500">{artefacts.length} sealed</span>}
      >
        <p className="mb-3 text-xs leading-relaxed text-zinc-500">
          Credentials, sensitive configuration, key material and security artefacts, each sealed with ML-KEM-768 +
          AES-256-GCM under its own name. The audit signing seed is itself wrapped here. Plaintexts never leave the server.
        </p>
        <div className="mb-3 flex flex-wrap gap-2">
          <Button
            variant="primary"
            disabled={busy !== null}
            onClick={() => run("verify", async () => { setResult(await api.verifyArtefacts()); await load(); })}
          >
            {busy === "verify" ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
            Verify every artefact
          </Button>
          <Button
            variant="danger"
            disabled={busy !== null || !target}
            title="Flip one ciphertext byte, as an attacker editing the store would"
            onClick={() => run("tamper", async () => { await api.tamperArtefact(target!); setResult(null); await load(); })}
          >
            <Skull className="h-4 w-4" /> Corrupt {target ?? "an artefact"}
          </Button>
        </div>
        {error && <p className="mb-2 text-xs text-red-400">{error}</p>}
        {result && (
          <div
            className={`mb-3 rounded-lg px-3 py-2 text-sm ring-1 ring-inset ${
              result.ok ? "bg-emerald-500/10 text-emerald-200 ring-emerald-500/30" : "bg-red-500/10 text-red-200 ring-red-500/40"
            }`}
          >
            <div className="flex items-center gap-2 font-medium">
              {result.ok ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
              {result.ok ? "Every artefact opens and matches its digest" : `${result.results.filter((r) => !r.ok).length} artefact(s) failed`}
            </div>
            {result.results.filter((r) => !r.ok).map((r) => (
              <p key={r.name} className="mt-1 text-xs opacity-80">
                {r.name}: {r.reason}
              </p>
            ))}
            {result.alert && (
              <p className="mt-1 text-xs">
                Raised {result.alert.id}: {result.alert.alert_type}
                {result.alert.incident_id && (
                  <>
                    {" "}·{" "}
                    <Link className="underline" to={`/incidents/${result.alert.incident_id}`}>
                      {result.alert.incident_id}
                    </Link>
                  </>
                )}
              </p>
            )}
          </div>
        )}
        {artefacts.length === 0 ? (
          <Empty>Nothing sealed yet.</Empty>
        ) : (
          <div className="-mx-4 -mb-4 overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-xs">
              <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="px-4 py-2 font-medium">Artefact</th>
                  <th className="px-2 py-2 font-medium">Category</th>
                  <th className="px-2 py-2 text-right font-medium">Sealed bytes</th>
                  <th className="px-2 py-2 font-medium">Sealed</th>
                  <th className="px-4 py-2 font-medium">Last check</th>
                </tr>
              </thead>
              <tbody>
                {artefacts.map((a) => (
                  <tr key={a.name} className="border-t border-zinc-800/70">
                    <td className="px-4 py-1.5">
                      <div className="font-mono text-zinc-200">{a.name}</div>
                      <div className="text-zinc-500">{a.description}</div>
                    </td>
                    <td className="px-2 py-1.5 text-zinc-400">{humanise(a.category)}</td>
                    <td className="px-2 py-1.5 text-right font-mono text-zinc-400">
                      {a.ciphertext_bytes} + {a.kem_ciphertext_bytes}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-zinc-500">{dateTime(a.sealed_at)}</td>
                    <td className={`px-4 py-1.5 ${a.last_check === "FAILED" ? "text-red-300" : a.last_check === "ok" ? "text-emerald-300" : "text-zinc-500"}`}>
                      {a.last_check}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Classical vs post-quantum: what protects what" icon={<KeyRound className="h-4 w-4 text-zinc-400" />}>
        <p className="mb-3 text-xs leading-relaxed text-zinc-500">
          Signing people in uses ordinary cryptography. The post-quantum layer protects what must stay trustworthy
          for years. SHA-256, AES and PBKDF2 are not post-quantum cryptography and are not labelled as such.
        </p>
        <ul className="space-y-2">
          {layers.map((l) => (
            <li key={l.protects} className="rounded-md border border-zinc-800 bg-zinc-950/40 p-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-zinc-200">{l.protects}</span>
                <span className={`ml-auto ${FAMILY_STYLE[l.family] ?? "text-zinc-400"}`}>{l.family}</span>
              </div>
              <div className="mt-0.5 font-mono text-zinc-400">{l.algorithm}</div>
              <div className="mt-0.5 text-zinc-500">{l.note}</div>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
