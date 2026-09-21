"use client";

import { AlertTriangle, CheckCircle2, KeyRound, Link2, Loader2, Lock, ShieldCheck, Skull } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import { humanise, short, time } from "@/lib/format";
import type { AuditListing, CryptoStatus, SealResult, Verification } from "@/lib/types";

import { Button, Card } from "./ui";

export function AuditPanel({ refreshKey, onReset }: { refreshKey: number; onReset: () => Promise<void> }) {
  const [crypto, setCrypto] = useState<CryptoStatus | null>(null);
  const [audit, setAudit] = useState<AuditListing | null>(null);
  const [verify, setVerify] = useState<Verification | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [sealName, setSealName] = useState("vault/swift-gateway");
  const [sealSecret, setSealSecret] = useState("sk_live_4f9a2c7e18b3");
  const [sealed, setSealed] = useState<SealResult | null>(null);

  const load = useCallback(async () => {
    const [c, a] = await Promise.all([api.crypto(), api.audit(30)]);
    setCrypto(c);
    setAudit(a);
  }, []);

  useEffect(() => {
    load().catch(() => {});
  }, [load, refreshKey]);

  async function run(label: string, fn: () => Promise<void>) {
    setBusy(label);
    try {
      await fn();
    } finally {
      setBusy(null);
    }
  }

  const tamperTarget = audit?.entries.find((e) => e.kind === "decision" && e.payload.action_taken !== "allow")
    ?? audit?.entries.find((e) => e.kind === "decision");

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Quantum-safe cryptography" icon={<Lock className="h-4 w-4 text-violet-400" />}>
        {crypto && (
          <div className="space-y-3">
            <div
              className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ring-1 ring-inset ${
                crypto.fully_quantum_safe
                  ? "bg-violet-500/10 text-violet-200 ring-violet-500/30"
                  : "bg-amber-500/10 text-amber-200 ring-amber-500/30"
              }`}
            >
              <ShieldCheck className="h-4 w-4" />
              {crypto.fully_quantum_safe
                ? "Every signature and sealed secret uses NIST post-quantum standards."
                : "Running on classical fallback — post-quantum library unavailable on this host."}
            </div>
            {[
              { k: "Audit log signing", v: crypto.signing, why: "A regulator must be able to trust a recorded decision for years. Signatures made today with ECDSA/Ed25519 become forgeable once a large quantum computer exists." },
              { k: "Credential sealing", v: crypto.sealing, why: "Harvest-now-decrypt-later: vault blobs stolen today must stay unreadable after quantum computers arrive." },
            ].map(({ k, v, why }) => (
              <div key={k} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs uppercase tracking-wider text-zinc-500">{k}</span>
                  <span className={`text-[11px] ${v.quantum_safe ? "text-violet-300" : "text-amber-300"}`}>
                    {v.quantum_safe ? "quantum-safe" : "classical"}
                  </span>
                </div>
                <div className="mt-1 font-mono text-sm text-zinc-100">{v.algorithm}</div>
                <div className="text-xs text-zinc-500">{v.standard} · public key {v.public_key_bytes.toLocaleString()} bytes</div>
                <p className="mt-1.5 text-xs leading-relaxed text-zinc-500">{why}</p>
              </div>
            ))}

            <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
              <div className="mb-2 flex items-center gap-1.5 text-xs uppercase tracking-wider text-zinc-500">
                <KeyRound className="h-3.5 w-3.5" /> Seal a credential
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <input
                  value={sealName}
                  onChange={(e) => setSealName(e.target.value)}
                  className="rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 font-mono text-xs text-zinc-200"
                  aria-label="Vault path"
                />
                <input
                  value={sealSecret}
                  onChange={(e) => setSealSecret(e.target.value)}
                  className="rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 font-mono text-xs text-zinc-200"
                  aria-label="Secret"
                />
              </div>
              <Button
                className="mt-2 text-xs"
                disabled={busy !== null || !sealName || !sealSecret}
                onClick={() =>
                  run("seal", async () => {
                    setSealed(await api.seal(sealName, sealSecret));
                    await load();
                  })
                }
              >
                {busy === "seal" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Lock className="h-3 w-3" />}
                Seal with {crypto.sealing.algorithm.split(" ")[0]}
              </Button>
              {sealed && (
                <div className="mt-2 space-y-1 font-mono text-[11px] text-zinc-500">
                  <div>KEM ciphertext: <span className="text-zinc-400">{short(sealed.kem_ciphertext, 48)}</span></div>
                  <div>AES-GCM ciphertext: <span className="text-zinc-400">{sealed.ciphertext}</span></div>
                  <div className={sealed.roundtrip_ok ? "text-emerald-400" : "text-red-400"}>
                    {sealed.roundtrip_ok ? "✓ unseals to the original" : "✗ roundtrip failed"} · logged as audit #{sealed.audit_seq} (secret not recorded)
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </Card>

      <Card
        title="Tamper-evident audit chain"
        icon={<Link2 className="h-4 w-4 text-sky-400" />}
        right={<span className="font-mono text-xs text-zinc-500">{audit?.total ?? 0} entries · {audit?.checkpoints.length ?? 0} signed</span>}
      >
        <p className="mb-3 text-xs leading-relaxed text-zinc-500">
          Each entry carries the SHA-256 of the one before it. The chain head is signed with ML-DSA at
          checkpoints and immediately after anything critical, so even an admin who recomputes every hash
          cannot produce a valid signature.
        </p>
        <div className="mb-3 flex flex-wrap gap-2">
          <Button
            variant="primary"
            disabled={busy !== null}
            onClick={() => run("verify", async () => setVerify(await api.verify()))}
          >
            {busy === "verify" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            Verify chain
          </Button>
          <Button
            variant="danger"
            disabled={busy !== null || !tamperTarget}
            title="Edit a past decision the way a rogue admin would"
            onClick={() =>
              run("tamper", async () => {
                if (!tamperTarget) return;
                const r = await api.tamper(tamperTarget.seq);
                setVerify(r.verify);
                await load();
              })
            }
          >
            <Skull className="h-4 w-4" />
            Forge entry #{tamperTarget?.seq ?? "—"}
          </Button>
          <Button variant="ghost" disabled={busy !== null} onClick={() => run("reset", async () => { await onReset(); setVerify(null); await load(); })}>
            Reset demo
          </Button>
        </div>

        {verify && (
          <div
            className={`mb-3 flex items-start gap-2 rounded-lg px-3 py-2 text-sm ring-1 ring-inset ${
              verify.ok ? "bg-emerald-500/10 text-emerald-200 ring-emerald-500/30" : "bg-red-500/10 text-red-200 ring-red-500/40"
            }`}
          >
            {verify.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />}
            <div>
              <div className="font-medium">{verify.ok ? "Chain intact" : `Tampering detected at entry #${verify.broken_at}`}</div>
              <div className="text-xs opacity-80">
                {verify.reason} · {verify.entries_checked} entries, {verify.checkpoints_checked} signatures checked
              </div>
            </div>
          </div>
        )}

        <ol className="max-h-[420px] space-y-1.5 overflow-auto pr-1">
          {audit?.entries.map((e) => (
            <li
              key={e.seq}
              className={`rounded-md border px-2.5 py-1.5 text-xs ${
                verify && !verify.ok && verify.broken_at === e.seq ? "border-red-500/60 bg-red-500/10" : "border-zinc-800 bg-zinc-950/40"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-zinc-500">#{e.seq}</span>
                <span className="text-zinc-300">{humanise(e.kind)}</span>
                <span className="ml-auto font-mono text-zinc-600">{time(e.ts)}</span>
              </div>
              <div className="mt-0.5 truncate text-zinc-400">
                {e.kind === "decision"
                  ? `${e.payload.actor} · ${humanise(String(e.payload.action))} → ${humanise(String(e.payload.action_taken))} (${e.payload.risk_total})`
                  : Object.entries(e.payload).slice(0, 3).map(([k, v]) => `${k}=${v}`).join(" · ")}
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-zinc-600">
                prev {short(e.prev_hash, 12)} → {short(e.entry_hash, 12)}
              </div>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
