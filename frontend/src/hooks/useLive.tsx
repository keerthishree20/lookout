import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

import { ApiError, api, wsUrl } from "@/lib/api";
import type { Alert, Decision, Incident, Stats } from "@/lib/types";

/** Counters bumped by WebSocket events, so a page reloads only what changed. */
export interface Pulse {
  sessions: number;
  incidents: number;
  messages: number;
}

export interface LiveRisk {
  user: string;
  score: number;
  band: string;
  action: string;
}

const FEED_LIMIT = 300;

interface Live {
  feed: Decision[];
  alerts: Alert[];
  stats: Stats | null;
  connected: boolean;
  offline: boolean;
  selected: Decision | null;
  select: (d: Decision | null) => void;
  merge: (ds: Decision[]) => void;
  refresh: () => void;
  reset: () => Promise<void>;
  /** Bumped on reset / scenario runs so pages can reload their own data. */
  version: number;
  bump: () => void;
  pulse: Pulse;
  /** Latest risk per user, as it changes. */
  risk: Record<string, LiveRisk>;
}

const LiveContext = createContext<Live | null>(null);

function mergeInto(existing: Decision[], incoming: Decision[]): Decision[] {
  const seen = new Set(existing.map((d) => d.event.event_id));
  const fresh = incoming.filter((d) => !seen.has(d.event.event_id));
  if (!fresh.length) return existing;
  return [...fresh.reverse(), ...existing].slice(0, FEED_LIMIT);
}

export function LiveProvider({ children, onAuthLost }: { children: ReactNode; onAuthLost: () => void }) {
  const [feed, setFeed] = useState<Decision[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [connected, setConnected] = useState(false);
  const [offline, setOffline] = useState(false);
  const [selected, select] = useState<Decision | null>(null);
  const [version, setVersion] = useState(0);
  const bump = useCallback(() => setVersion((v) => v + 1), []);
  const [pulse, setPulse] = useState<Pulse>({ sessions: 0, incidents: 0, messages: 0 });
  const [risk, setRisk] = useState<Record<string, LiveRisk>>({});
  const [toast, setToast] = useState<Incident | null>(null);

  const refresh = useCallback(() => {
    api
      .stats()
      .then((s) => {
        setStats(s);
        setOffline(false);
      })
      .catch((e) => {
        if (e instanceof ApiError && (e.status === 401 || e.status === 403)) return onAuthLost();
        setOffline(true);
      });
  }, [onAuthLost]);

  useEffect(() => {
    api.decisions(120).then(setFeed).catch(() => {});
    api.alerts().then((a) => setAlerts(a.slice(0, 50))).catch(() => {});
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh]);

  // WebSocket live feed, reconnecting with backoff.
  const retry = useRef(0);
  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;
    const open = () => {
      ws = new WebSocket(wsUrl());
      ws.onopen = () => {
        retry.current = 0;
        setConnected(true);
      };
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data) as { type: string; data: unknown };
        if (msg.type === "decision") setFeed((prev) => mergeInto(prev, [msg.data as Decision]));
        if (msg.type === "alert") setAlerts((prev) => [msg.data as Alert, ...prev].slice(0, 50));
        if (msg.type === "session") setPulse((p) => ({ ...p, sessions: p.sessions + 1 }));
        if (msg.type === "message") setPulse((p) => ({ ...p, messages: p.messages + 1 }));
        if (msg.type === "risk") {
          const r = msg.data as LiveRisk;
          setRisk((prev) => ({ ...prev, [r.user]: r }));
        }
        if (msg.type === "incident") {
          const inc = msg.data as Incident;
          setPulse((p) => ({ ...p, incidents: p.incidents + 1 }));
          if (inc.severity === "CRITICAL") setToast(inc);
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (closed) return;
        const delay = Math.min(10_000, 500 * 2 ** retry.current++);
        timer = setTimeout(open, delay);
      };
    };
    open();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, []);

  const merge = useCallback((ds: Decision[]) => setFeed((prev) => mergeInto(prev, ds)), []);

  const reset = useCallback(async () => {
    await api.reset();
    setFeed([]);
    setAlerts([]);
    select(null);
    refresh();
    bump();
  }, [refresh, bump]);

  return (
    <LiveContext.Provider
      value={{ feed, alerts, stats, connected, offline, selected, select, merge, refresh, reset, version, bump, pulse, risk }}
    >
      {children}
      {toast && <CriticalToast incident={toast} onClose={() => setToast(null)} />}
    </LiveContext.Provider>
  );
}

export function useLive(): Live {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive outside LiveProvider");
  return ctx;
}

/** A critical incident, pushed over the WebSocket the moment it opens. */
function CriticalToast({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  useEffect(() => {
    const t = setTimeout(onClose, 12_000);
    return () => clearTimeout(t);
  }, [incident, onClose]);
  return (
    <div
      role="alert"
      className="fixed bottom-4 right-4 z-40 w-[min(360px,calc(100vw-2rem))] rounded-xl border border-red-500/60 bg-zinc-950/95 p-3 shadow-2xl"
    >
      <div className="flex items-start gap-2">
        <span className="rounded bg-red-600/30 px-1.5 py-0.5 text-[10px] font-semibold text-red-100">CRITICAL</span>
        <div className="min-w-0 flex-1 text-sm">
          <div className="truncate font-medium text-zinc-100">{incident.title}</div>
          <div className="text-xs text-zinc-400">
            {incident.id} · {incident.user} · risk {incident.risk_score.toFixed(0)}
          </div>
          <a href={`/incidents/${incident.id}`} className="text-xs text-sky-400 hover:underline">
            Open incident →
          </a>
        </div>
        <button onClick={onClose} aria-label="Dismiss" className="text-zinc-500 hover:text-zinc-200">
          ✕
        </button>
      </div>
    </div>
  );
}
