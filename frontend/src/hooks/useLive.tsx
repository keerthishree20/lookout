import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

import { ApiError, api, wsUrl } from "@/lib/api";
import type { Alert, Decision, Stats } from "@/lib/types";

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
      value={{ feed, alerts, stats, connected, offline, selected, select, merge, refresh, reset, version, bump }}
    >
      {children}
    </LiveContext.Provider>
  );
}

export function useLive(): Live {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive outside LiveProvider");
  return ctx;
}
