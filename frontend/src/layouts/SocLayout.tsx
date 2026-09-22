import {
  Activity,
  BellRing,
  Binoculars,
  BrainCircuit,
  FileWarning,
  FlaskConical,
  Gauge,
  Inbox,
  KeyRound,
  Link2,
  LogOut,
  Mail,
  Menu,
  MonitorSmartphone,
  Pause,
  Play,
  RotateCcw,
  ScanSearch,
  Settings,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  WifiOff,
  X,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { LiveProvider, useLive } from "@/hooks/useLive";
import { API_URL, api } from "@/lib/api";
import { clearSession, loadSession } from "@/lib/session";
import type { Health } from "@/lib/types";

type Item = { to: string; label: string; icon: LucideIcon; badge?: "alerts" | "incidents" | "honeypot" | "quarantine" };

const NAV: { group: string; items: Item[] }[] = [
  {
    group: "Overview",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: Gauge },
      { to: "/simulation", label: "Simulation", icon: FlaskConical },
      { to: "/activity", label: "Live activity", icon: Activity },
    ],
  },
  {
    group: "Threats",
    items: [
      { to: "/alerts", label: "Alerts", icon: BellRing, badge: "alerts" },
      { to: "/incidents", label: "Incidents", icon: ShieldAlert, badge: "incidents" },
      { to: "/honeypot", label: "Honeypot", icon: FileWarning, badge: "honeypot" },
    ],
  },
  {
    group: "Identity & access",
    items: [
      { to: "/users", label: "Users", icon: Users },
      { to: "/sessions", label: "Sessions", icon: MonitorSmartphone },
      { to: "/access-control", label: "Access control", icon: KeyRound },
      { to: "/privileged-access", label: "Privileged access", icon: ShieldCheck },
    ],
  },
  {
    group: "Communications",
    items: [
      { to: "/messages", label: "Messages", icon: Mail },
      { to: "/message-scanner", label: "Message scanner", icon: ScanSearch },
      { to: "/quarantine", label: "Quarantine", icon: Inbox, badge: "quarantine" },
    ],
  },
  {
    group: "Assurance",
    items: [
      { to: "/audit-logs", label: "Audit & quantum-safe", icon: Link2 },
      { to: "/ml-insights", label: "ML insights", icon: BrainCircuit },
    ],
  },
  {
    group: "Administration",
    items: [
      { to: "/security-policies", label: "Security policies", icon: SlidersHorizontal },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export const TITLES: Record<string, string> = Object.fromEntries(
  NAV.flatMap((g) => g.items.map((i) => [i.to, i.label])),
);

export function SocLayout() {
  const navigate = useNavigate();
  const session = loadSession();
  const isConsole = session && session.kind !== "employee";

  const onAuthLost = useCallback(() => {
    clearSession();
    navigate("/login", { replace: true });
  }, [navigate]);

  useEffect(() => {
    if (!isConsole) navigate("/login", { replace: true });
  }, [isConsole, navigate]);

  if (!isConsole) return null;
  return (
    <LiveProvider onAuthLost={onAuthLost}>
      <Shell username={session.profile.username} kind={session.kind} onSignOut={onAuthLost} />
    </LiveProvider>
  );
}

function Shell({ username, kind, onSignOut }: { username: string; kind: string; onSignOut: () => void }) {
  const { stats, offline, connected, reset, refresh } = useLive();
  const [health, setHealth] = useState<Health | null>(null);
  const [open, setOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
  }, []);
  useEffect(() => setOpen(false), [location.pathname]);

  const badges = useMemo(
    () => ({
      alerts: stats?.open_alerts ?? 0,
      incidents: stats?.open_incidents ?? 0,
      honeypot: stats?.in_honeypot ?? 0,
      quarantine: stats?.quarantined ?? 0,
    }),
    [stats],
  );
  const title =
    TITLES[location.pathname] ??
    (location.pathname.startsWith("/users/") ? "User risk profile" : location.pathname.startsWith("/incidents/") ? "Incidents" : "Lookout");

  async function signOut() {
    await api.logout().catch(() => {});
    onSignOut();
  }

  async function togglePause() {
    if (!stats) return;
    await api.traffic(stats.traffic_paused ? "resume" : "pause");
    refresh();
  }

  const sidebar = (
    <nav className="flex h-full flex-col gap-5 overflow-y-auto px-3 py-4" aria-label="Console">
      <div className="flex items-center gap-2.5 px-2">
        <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-sky-500 to-violet-600">
          <Binoculars className="h-4.5 w-4.5 text-white" />
        </div>
        <div>
          <div className="text-sm font-semibold text-zinc-50">Lookout</div>
          <div className="text-[11px] text-zinc-500">SOC · Meridian Bank</div>
        </div>
      </div>
      {NAV.map((g) => (
        <div key={g.group}>
          <div className="mb-1 px-2 text-[10px] font-medium uppercase tracking-wider text-zinc-600">{g.group}</div>
          <ul className="space-y-0.5">
            {g.items.map(({ to, label, icon: Icon, badge }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition ${
                      isActive ? "bg-sky-500/10 text-sky-200" : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
                    }`
                  }
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span className="flex-1 truncate">{label}</span>
                  {badge && badges[badge] > 0 && (
                    <span className="rounded bg-red-500/20 px-1.5 text-[10px] font-semibold text-red-200">{badges[badge]}</span>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <div className="mt-auto px-2 text-[11px] text-zinc-600">
        Simulated bank. All people and data are synthetic.
      </div>
    </nav>
  );

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 border-r border-zinc-800/80 bg-zinc-950/70 lg:block">{sidebar}</aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 border-r border-zinc-800 bg-zinc-950">
            <button onClick={() => setOpen(false)} className="absolute right-2 top-3 p-1 text-zinc-500" aria-label="Close menu">
              <X className="h-5 w-5" />
            </button>
            {sidebar}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex flex-wrap items-center gap-2 border-b border-zinc-800/80 bg-zinc-950/80 px-4 py-3 backdrop-blur sm:px-6">
          <button onClick={() => setOpen(true)} className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-800 lg:hidden" aria-label="Open menu">
            <Menu className="h-5 w-5" />
          </button>
          <h1 className="mr-auto text-base font-semibold text-zinc-100">{title}</h1>
          <span className={`inline-flex items-center gap-1 text-[11px] ${connected ? "text-emerald-400" : "text-zinc-500"}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? "animate-pulse bg-emerald-400" : "bg-zinc-600"}`} />
            {connected ? "live" : "reconnecting"}
          </span>
          {health && (
            <span className="hidden rounded-md bg-violet-500/10 px-2 py-1 text-[11px] text-violet-300 ring-1 ring-violet-500/30 sm:inline">
              {health.signing}
            </span>
          )}
          <button
            onClick={togglePause}
            disabled={!stats}
            className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs text-zinc-300 ring-1 ring-inset ring-zinc-800 hover:bg-zinc-800"
          >
            {stats?.traffic_paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            <span className="hidden sm:inline">{stats?.traffic_paused ? "Resume traffic" : "Pause traffic"}</span>
          </button>
          <button
            onClick={reset}
            className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs text-zinc-300 ring-1 ring-inset ring-zinc-800 hover:bg-zinc-800"
            title="Rebuild the simulated bank from scratch"
          >
            <RotateCcw className="h-3.5 w-3.5" /> <span className="hidden sm:inline">Reset</span>
          </button>
          <button
            onClick={signOut}
            className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs text-zinc-300 ring-1 ring-inset ring-zinc-800 hover:bg-zinc-800"
            title={`Signed in as ${username} (${kind === "superadmin" ? "Super Admin" : "SOC analyst"})`}
          >
            <LogOut className="h-3.5 w-3.5" /> {username}
          </button>
        </header>

        {offline && (
          <div className="mx-4 mt-4 flex items-center gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200 sm:mx-6">
            <WifiOff className="h-4 w-4" />
            Cannot reach the Lookout API at <code className="font-mono">{API_URL || window.location.origin}</code>.
          </div>
        )}

        <main className="min-w-0 flex-1 px-4 py-5 sm:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
