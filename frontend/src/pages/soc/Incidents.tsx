import { BrainCircuit, FileWarning, Loader2, Plus, ShieldAlert, UserCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { Button, Card, Empty } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { ApiError, api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import { loadSession } from "@/lib/session";
import type { AlertStatus, Incident, IncidentDetail } from "@/lib/types";

const STATUSES: AlertStatus[] = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];
const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-600/25 text-red-100",
  HIGH: "bg-orange-500/15 text-orange-200",
  MEDIUM: "bg-amber-500/15 text-amber-200",
  LOW: "bg-zinc-800 text-zinc-300",
};

export function Incidents() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { version, alerts } = useLive();
  const [list, setList] = useState<Incident[]>([]);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    api.incidents().then(setList).catch(() => {});
  }, []);
  useEffect(load, [load, version, alerts.length]);

  return (
    <div className="grid gap-4 xl:grid-cols-5">
      <Card
        title={`Incidents (${list.length})`}
        icon={<ShieldAlert className="h-4 w-4 text-red-400" />}
        right={
          <Button variant="ghost" className="text-xs" onClick={() => setCreating((c) => !c)}>
            <Plus className="h-3.5 w-3.5" /> New
          </Button>
        }
        className="xl:col-span-2"
      >
        {creating && <CreateIncident onDone={(inc) => { setCreating(false); load(); if (inc) navigate(`/incidents/${inc.id}`); }} />}
        {list.length === 0 ? (
          <Empty>No incidents. High and critical alerts open one automatically, per person.</Empty>
        ) : (
          <ul className="space-y-1.5">
            {list.map((i) => (
              <li key={i.id}>
                <Link
                  to={`/incidents/${i.id}`}
                  className={`block rounded-lg border px-3 py-2 transition ${
                    i.id === id ? "border-sky-500/50 bg-sky-500/5" : "border-zinc-800 bg-zinc-950/40 hover:border-zinc-700"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-zinc-500">{i.id}</span>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${SEVERITY_STYLE[i.severity] ?? SEVERITY_STYLE.LOW}`}>{i.severity}</span>
                    <span className="ml-auto text-[11px] text-zinc-500">{i.status.replace("_", " ")}</span>
                  </div>
                  <div className="mt-1 text-sm text-zinc-200">{i.title}</div>
                  <div className="mt-0.5 text-[11px] text-zinc-500">
                    {i.alert_count} alert{i.alert_count === 1 ? "" : "s"} · risk {i.risk_score.toFixed(0)} · {humanise(i.threat_type)}
                    {i.assigned_to ? ` · ${i.assigned_to}` : ""}
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <div className="xl:col-span-3">
        {id ? <IncidentView id={id} onChange={load} /> : <Card title="Incident"><Empty>Select an incident.</Empty></Card>}
      </div>
    </div>
  );
}

function CreateIncident({ onDone }: { onDone: (inc?: Incident) => void }) {
  const [title, setTitle] = useState("");
  const [user, setUser] = useState("s.iyer");
  const [severity, setSeverity] = useState("MEDIUM");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const field = "rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200";
  return (
    <form
      className="mb-3 space-y-2 rounded-lg border border-zinc-800 bg-zinc-950/50 p-3"
      onSubmit={async (e) => {
        e.preventDefault();
        try {
          onDone(await api.createIncident({ title, user, severity, description }));
        } catch (err) {
          setError(err instanceof ApiError ? err.detail : String(err));
        }
      }}
    >
      <input className={`${field} w-full`} placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} aria-label="Title" />
      <div className="flex gap-2">
        <input className={`${field} flex-1`} placeholder="User" value={user} onChange={(e) => setUser(e.target.value)} aria-label="User" />
        <select className={field} value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <textarea className={`${field} w-full`} rows={2} placeholder="What was reported" value={description} onChange={(e) => setDescription(e.target.value)} aria-label="Description" />
      {error && <p className="text-xs text-red-400">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" variant="primary" className="text-xs" disabled={title.length < 3}>Open incident</Button>
        <Button variant="ghost" className="text-xs" onClick={() => onDone()}>Cancel</Button>
      </div>
    </form>
  );
}

function IncidentView({ id, onChange }: { id: string; onChange: () => void }) {
  const [inc, setInc] = useState<IncidentDetail | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const me = loadSession()?.profile.username ?? "soc.analyst";

  const load = useCallback(() => {
    api.incident(id).then(setInc).catch((e) => setError(e instanceof ApiError ? e.detail : String(e)));
  }, [id]);
  useEffect(load, [load]);

  async function act(label: string, fn: () => Promise<unknown>) {
    setBusy(label);
    setError(null);
    try {
      await fn();
      load();
      onChange();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(null);
    }
  }

  if (error && !inc) return <Card title="Incident"><p className="text-sm text-red-400">{error}</p></Card>;
  if (!inc) return <Card title="Incident"><p className="text-sm text-zinc-500">Loading…</p></Card>;

  return (
    <Card
      title={<>{inc.id} · {inc.title}</>}
      icon={<ShieldAlert className="h-4 w-4 text-red-400" />}
      right={<span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${SEVERITY_STYLE[inc.severity] ?? SEVERITY_STYLE.LOW}`}>{inc.severity}</span>}
    >
      <div className="space-y-4 text-sm">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
          <dt className="text-zinc-500">User</dt>
          <dd><Link className="text-sky-300" to={`/users/${encodeURIComponent(inc.user)}`}>{inc.user}</Link></dd>
          <dt className="text-zinc-500">Threat type</dt>
          <dd className="text-zinc-200">{humanise(inc.threat_type)}</dd>
          <dt className="text-zinc-500">Risk</dt>
          <dd className="font-mono text-zinc-200">{inc.risk_score.toFixed(0)}</dd>
          <dt className="text-zinc-500">Analyst</dt>
          <dd className="text-zinc-200">{inc.assigned_to ?? "unassigned"}</dd>
          <dt className="text-zinc-500">Opened</dt>
          <dd className="text-zinc-300">{dateTime(inc.created_at)}</dd>
          <dt className="text-zinc-500">Status</dt>
          <dd>
            <select
              value={inc.status}
              onChange={(e) => act("status", () => api.incidentStatus(inc.id, e.target.value))}
              className="rounded border border-zinc-700 bg-zinc-950 px-1.5 py-0.5 text-[11px] text-zinc-200"
              aria-label="Incident status"
            >
              {STATUSES.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
            </select>
          </dd>
        </dl>

        <div className="flex flex-wrap gap-2">
          <Button className="text-xs" disabled={busy !== null} onClick={() => act("assign", () => api.assignIncident(inc.id, me))}>
            <UserCheck className="h-3.5 w-3.5" /> Assign to me
          </Button>
          <Button className="text-xs" disabled={busy !== null} onClick={() => act("revoke", () => api.incidentAction(inc.id, "revoke_sessions"))}>
            Revoke sessions
          </Button>
          <Button variant="danger" className="text-xs" disabled={busy !== null} onClick={() => act("disable", () => api.incidentAction(inc.id, "disable_account"))}>
            Block user
          </Button>
          <Button variant="ghost" className="text-xs" disabled={busy !== null} onClick={() => act("enable", () => api.incidentAction(inc.id, "enable_account"))}>
            Re-enable account
          </Button>
          <Button variant="ghost" className="text-xs" disabled={busy !== null} onClick={() => act("resolve", () => api.incidentStatus(inc.id, "RESOLVED"))}>
            Resolve
          </Button>
          {busy && <Loader2 className="h-4 w-4 animate-spin text-zinc-500" />}
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}

        <section>
          <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">AI explanation</h3>
          <p className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs leading-relaxed text-zinc-300">{inc.ai_explanation || "—"}</p>
          {inc.ml_opinion && (
            <p className="mt-1.5 flex items-center gap-1.5 text-[11px] text-violet-200">
              <BrainCircuit className="h-3.5 w-3.5" /> ML second opinion: {humanise(inc.ml_opinion.classification)} ({(inc.ml_opinion.confidence * 100).toFixed(0)}%)
            </p>
          )}
        </section>

        {inc.honeypot && (
          <section className="rounded-lg border border-fuchsia-500/30 bg-fuchsia-500/5 p-3 text-xs">
            <div className="flex items-center gap-1.5 font-medium text-fuchsia-100">
              <FileWarning className="h-3.5 w-3.5" /> In the honeypot since {dateTime(inc.honeypot.since)}
            </div>
            <p className="mt-1 text-fuchsia-100/80">{inc.honeypot.reason}</p>
            <Link to="/honeypot" className="mt-1 inline-block text-sky-300">See their activity in the fake world →</Link>
          </section>
        )}

        <section>
          <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Timeline</h3>
          <ol className="space-y-1 border-l border-zinc-800 pl-3 text-xs">
            {inc.timeline.map((t, i) => (
              <li key={i}>
                <span className="font-mono text-[10px] text-zinc-600">{dateTime(t.ts)}</span>{" "}
                <span className="rounded bg-zinc-800 px-1 text-[10px] uppercase text-zinc-400">{t.kind}</span>{" "}
                <span className="text-zinc-300">{t.text}</span>
              </li>
            ))}
          </ol>
        </section>

        <section>
          <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Evidence ({inc.alerts.length} alerts)</h3>
          <ul className="space-y-1 text-xs">
            {inc.alerts.map((a) => (
              <li key={a.id} className="rounded border border-zinc-800 bg-zinc-950/40 px-2 py-1.5">
                <span className="font-mono text-zinc-500">{a.id}</span> <span className="text-zinc-200">{a.alert_type}</span>{" "}
                <span className="font-mono text-zinc-400">risk {a.risk_score.toFixed(0)}</span>
                <div className="mt-0.5 text-zinc-500">{a.reasons[0]}</div>
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Actions taken</h3>
          <ul className="space-y-0.5 text-xs text-zinc-400">
            {inc.actions_taken.length === 0 && <li>None yet.</li>}
            {inc.actions_taken.map((a, i) => (
              <li key={i}>
                <span className="font-mono text-[10px] text-zinc-600">{dateTime(a.ts)}</span> {a.by}: {humanise(a.action)}
                {a.detail ? ` (${a.detail})` : ""}
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Notes</h3>
          <ul className="mb-2 space-y-1 text-xs">
            {inc.notes.map((n, i) => (
              <li key={i} className="text-zinc-300">
                <span className="text-zinc-500">{n.by}:</span> {n.text}
              </li>
            ))}
          </ul>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (!note.trim()) return;
              act("note", () => api.noteIncident(inc.id, note.trim())).then(() => setNote(""));
            }}
          >
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Add an investigation note"
              className="min-w-0 flex-1 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-200"
              aria-label="Note"
            />
            <Button type="submit" className="text-xs" disabled={!note.trim() || busy !== null}>Add</Button>
          </form>
        </section>
      </div>
    </Card>
  );
}
