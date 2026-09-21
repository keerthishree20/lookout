"use client";

import {
  Binoculars,
  FlaskConical,
  Gauge,
  Link2,
  Pause,
  Play,
  RotateCcw,
  Send,
  Users,
  WifiOff,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { AuditPanel } from "@/components/AuditPanel";
import { DecisionDetail } from "@/components/DecisionDetail";
import { EvaluationPanel } from "@/components/EvaluationPanel";
import { GatewayPanel } from "@/components/GatewayPanel";
import { IdentitiesPanel } from "@/components/IdentitiesPanel";
import { LiveFeed } from "@/components/LiveFeed";
import { ScenarioPanel } from "@/components/ScenarioPanel";
import { Button, Stat } from "@/components/ui";
import { API_URL, api, streamUrl } from "@/lib/api";
import type { Decision, Health, Scenario, Stats } from "@/lib/types";

const FEED_LIMIT = 300;

const TABS = [
  { key: "console", label: "Console", icon: Gauge },
  { key: "gateway", label: "Message gateway", icon: Send },
  { key: "identities", label: "Identities", icon: Users },
  { key: "audit", label: "Audit & QPC", icon: Link2 },
  { key: "evaluation", label: "Evaluation", icon: FlaskConical },
] as const;

type Tab = (typeof TABS)[number]["key"];

function merge(existing: Decision[], incoming: Decision[]): Decision[] {
  const seen = new Set(existing.map((d) => d.event.event_id));
  const fresh = incoming.filter((d) => !seen.has(d.event.event_id));
  if (!fresh.length) return existing;
  return [...fresh.reverse(), ...existing].slice(0, FEED_LIMIT);
}

export default function Home() {
  const [tab, setTab] = useState<Tab>("console");
  const [health, setHealth] = useState<Health | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [feed, setFeed] = useState<Decision[]>([]);
  const [selected, setSelected] = useState<Decision | null>(null);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [connected, setConnected] = useState(false);
  const [offline, setOffline] = useState(false);
  const [lastPeaks, setLastPeaks] = useState<Record<string, Decision>>({});
  const [refreshKey, setRefreshKey] = useState(0);
  const bump = () => setRefreshKey((k) => k + 1);

  const refreshStats = useCallback(() => {
    api
      .stats()
      .then((s) => {
        setStats(s);
        setOffline(false);
      })
      .catch(() => setOffline(true));
  }, []);

  // Initial load.
  useEffect(() => {
    api.health().then(setHealth).catch(() => setOffline(true));
    api.scenarios().then(setScenarios).catch(() => {});
    api.decisions(120).then((d) => setFeed(d)).catch(() => {});
    refreshStats();
    const t = setInterval(refreshStats, 3000);
    return () => clearInterval(t);
  }, [refreshStats]);

  // Live stream.
  const esRef = useRef<EventSource | null>(null);
  useEffect(() => {
    const es = new EventSource(streamUrl);
    esRef.current = es;
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("decision", (e) => {
      const d = JSON.parse((e as MessageEvent).data) as Decision;
      setFeed((prev) => merge(prev, [d]));
    });
    return () => es.close();
  }, []);

  async function runScenario(key: string) {
    const r = await api.runScenario(key);
    setFeed((prev) => merge(prev, r.decisions));
    setSelected(r.peak);
    setLastPeaks((p) => ({ ...p, [key]: r.peak }));
    refreshStats();
    bump();
  }

  async function reset() {
    await api.reset();
    setFeed([]);
    setSelected(null);
    setLastPeaks({});
    refreshStats();
    bump();
  }

  async function togglePause() {
    if (!stats) return;
    await api.traffic(stats.traffic_paused ? "resume" : "pause");
    refreshStats();
  }

  const flagged = stats ? stats.decisions - (stats.by_action.allow ?? 0) : 0;
  const alerts = stats?.by_action.block_and_alert ?? 0;
  const blocked = (stats?.by_action.block ?? 0) + alerts;

  return (
    <div className="mx-auto w-full max-w-[1500px] px-4 pb-16 sm:px-6">
      {/* header */}
      <header className="flex flex-wrap items-center justify-between gap-4 py-5">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-sky-500 to-violet-600 shadow-lg shadow-sky-900/40">
            <Binoculars className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-zinc-50">Lookout</h1>
            <p className="text-xs text-zinc-500">
              Privileged-access misuse &amp; insider-threat detection · Meridian Bank (simulated)
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {health && (
            <>
              <span className="rounded-md bg-zinc-900 px-2 py-1 text-zinc-400 ring-1 ring-zinc-800">
                model <span className={health.model_fitted ? "text-emerald-300" : "text-amber-300"}>{health.model_fitted ? "trained" : "cold"}</span>
              </span>
              <span className="rounded-md bg-violet-500/10 px-2 py-1 text-violet-300 ring-1 ring-violet-500/30">
                {health.signing} signing
              </span>
              <span className="rounded-md bg-zinc-900 px-2 py-1 text-zinc-400 ring-1 ring-zinc-800" title="Narratives are written by an LLM when GEMINI_API_KEY is set; otherwise by a deterministic template built from the same evidence.">
                narrator: {health.narrator}
              </span>
            </>
          )}
          <Button variant="ghost" onClick={togglePause} disabled={!stats}>
            {stats?.traffic_paused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
            {stats?.traffic_paused ? "Resume traffic" : "Pause traffic"}
          </Button>
          <Button variant="ghost" onClick={reset}>
            <RotateCcw className="h-4 w-4" /> Reset
          </Button>
        </div>
      </header>

      {offline && (
        <div className="mb-4 flex items-center gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <WifiOff className="h-4 w-4" />
          Cannot reach the Lookout API at <code className="font-mono">{API_URL}</code>. Start it with{" "}
          <code className="font-mono">uvicorn lookout.api:app --port 8077</code> from <code className="font-mono">backend/</code>.
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Decisions" value={stats?.decisions.toLocaleString() ?? "—"} hint={`${stats?.history_events.toLocaleString() ?? "—"} events learned from`} />
        <Stat label="Flagged" value={flagged.toLocaleString()} hint="step-up, hold or block" tone={flagged ? "warn" : "default"} />
        <Stat label="Blocked" value={blocked.toLocaleString()} hint={`${alerts} paged the SOC`} tone={blocked ? "danger" : "default"} />
        <Stat label="Quarantined" value={stats?.quarantined ?? "—"} hint="messages held for review" tone={stats?.quarantined ? "info" : "default"} />
        <Stat label="Identities" value={stats?.identities ?? "—"} hint="with learned baselines" />
        <Stat label="Audit chain" value={stats?.audit_entries.toLocaleString() ?? "—"} hint={`${stats?.audit_checkpoints ?? 0} ML-DSA checkpoints`} />
      </div>

      {/* tabs */}
      <nav className="mt-6 flex gap-1 overflow-x-auto border-b border-zinc-800" aria-label="Sections">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`-mb-px inline-flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm transition ${
              tab === key ? "border-sky-400 text-zinc-100" : "border-transparent text-zinc-500 hover:text-zinc-300"
            }`}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </nav>

      <main className="mt-4">
        {tab === "console" && (
          <div className="grid gap-4 lg:grid-cols-12">
            <div className="lg:col-span-3">
              <ScenarioPanel scenarios={scenarios} onRun={runScenario} lastPeaks={lastPeaks} />
            </div>
            <div className="min-w-0 lg:col-span-5">
              <LiveFeed
                decisions={feed}
                selectedId={selected?.event.event_id ?? null}
                onSelect={setSelected}
                flaggedOnly={flaggedOnly}
                onToggleFlagged={() => setFlaggedOnly((f) => !f)}
                connected={connected}
              />
            </div>
            <div className="lg:col-span-4">
              <div className="lg:sticky lg:top-4">
                <DecisionDetail decision={selected} />
              </div>
            </div>
          </div>
        )}
        {tab === "gateway" && (
          <GatewayPanel
            refreshKey={refreshKey}
            onDecision={(d) => {
              setSelected(d);
              setFeed((prev) => merge(prev, [d]));
              refreshStats();
            }}
          />
        )}
        {tab === "identities" && <IdentitiesPanel refreshKey={refreshKey} />}
        {tab === "audit" && <AuditPanel refreshKey={refreshKey} onReset={reset} />}
        {tab === "evaluation" && <EvaluationPanel />}

        {tab === "gateway" && selected && (
          <div className="mt-4 lg:max-w-2xl">
            <DecisionDetail decision={selected} />
          </div>
        )}
      </main>
    </div>
  );
}
