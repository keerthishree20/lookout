import { ArrowLeft } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { ChartCard, RiskLine, STATUS } from "@/components/charts";
import { Card, ClassChip, Stat } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { Policy, ThreatClass, UserRisk } from "@/lib/types";

export function UserDetail() {
  const { id = "" } = useParams();
  const { version } = useLive();
  const [data, setData] = useState<UserRisk | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [policy, setPolicy] = useState<Pick<Policy, "medium" | "high" | "critical">>({ medium: 30, high: 60, critical: 85 });

  useEffect(() => {
    setError(null);
    api.userRisk(id).then(setData).catch((e) => setError(String(e.detail ?? e)));
    api.policy().then(setPolicy).catch(() => {});
  }, [id, version]);

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!data) return <p className="text-sm text-zinc-500">Loading…</p>;

  const trend = data.trend.map((t) => ({
    label: new Date(t.ts).toLocaleString("en-GB", { day: "2-digit", hour: "2-digit", minute: "2-digit" }),
    risk: t.risk,
    action: humanise(t.action),
  }));
  // Highlight sudden change: the biggest jump between consecutive events.
  let jump = { from: 0, to: 0, at: "" };
  data.trend.forEach((t, i) => {
    const prev = data.trend[i - 1];
    if (prev && t.risk - prev.risk > jump.to - jump.from) jump = { from: prev.risk, to: t.risk, at: t.ts };
  });

  return (
    <div className="space-y-4">
      <Link to="/users" className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
        <ArrowLeft className="h-3 w-3" /> All users
      </Link>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-xl font-semibold text-zinc-50">{data.user}</h2>
        <span className="text-sm text-zinc-500">{humanise(data.role)}</span>
        {data.classification !== "benign" && <ClassChip cls={data.classification as ThreatClass} />}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Current risk" value={data.current_risk.toFixed(0)} tone={data.current_risk >= policy.high ? "danger" : data.current_risk >= policy.medium ? "warn" : "ok"} />
        <Stat label="Peak risk" value={data.peak_risk.toFixed(0)} tone={data.peak_risk >= policy.high ? "danger" : "default"} />
        <Stat label="Alerts" value={data.alerts.length} tone={data.alerts.length ? "danger" : "default"} />
        <Stat label="Messages sent" value={data.messages} />
      </div>

      <ChartCard
        title="Risk trend"
        subtitle={
          jump.to - jump.from >= 20
            ? `Sudden change: ${jump.from.toFixed(0)} → ${jump.to.toFixed(0)} at ${dateTime(jump.at)}`
            : "Risk of each scored activity, oldest to newest"
        }
        table={{ columns: ["When", "Activity", "Risk"], rows: trend.map((t) => [t.label, t.action, t.risk]) }}
      >
        <RiskLine
          data={trend}
          dataKey="risk"
          name="Risk"
          thresholds={[
            { value: policy.medium, label: "Medium", color: STATUS.medium },
            { value: policy.high, label: "High", color: STATUS.high },
            { value: policy.critical, label: "Critical", color: STATUS.critical },
          ]}
        />
      </ChartCard>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Login history">
          {data.logins.length === 0 ? (
            <p className="text-sm text-zinc-500">No sign-ins scored yet.</p>
          ) : (
            <ul className="space-y-1.5 text-xs">
              {[...data.logins].reverse().map((l, i) => (
                <li key={i} className="flex flex-wrap justify-between gap-2 border-b border-zinc-800/60 pb-1.5">
                  <span className={l.success ? "text-zinc-300" : "text-red-300"}>{l.success ? "Signed in" : "Failed"} · {l.city}</span>
                  <span className="font-mono text-zinc-500">{l.device}</span>
                  <span className="font-mono text-zinc-600">{dateTime(l.ts)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Devices and locations">
          <Tally title="Devices" data={data.devices} />
          <div className="mt-3" />
          <Tally title="Locations" data={data.locations} />
        </Card>
        <Card title="Resources accessed">
          <Tally title="Resource" data={data.resources} />
        </Card>
      </div>

      <Card title={`Alerts (${data.alerts.length})`}>
        {data.alerts.length === 0 ? (
          <p className="text-sm text-zinc-500">None.</p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {data.alerts.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-zinc-500">{a.id}</span>
                <span className="text-zinc-200">{a.alert_type}</span>
                <span className="font-mono text-xs text-zinc-400">risk {a.risk_score.toFixed(0)}</span>
                <span className="text-xs text-zinc-500">{a.status}</span>
                {a.incident_id && (
                  <Link className="text-xs text-sky-400" to={`/incidents/${a.incident_id}`}>
                    {a.incident_id}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function Tally({ title, data }: { title: string; data: Record<string, number> }) {
  const entries = Object.entries(data).slice(0, 8);
  if (!entries.length) return <p className="text-xs text-zinc-500">No data.</p>;
  return (
    <table className="w-full text-left text-xs">
      <thead className="text-zinc-500">
        <tr>
          <th className="pb-1 font-medium">{title}</th>
          <th className="pb-1 text-right font-medium">Events</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k} className="border-t border-zinc-800/60">
            <td className="py-1 font-mono text-zinc-300">{k}</td>
            <td className="py-1 text-right font-mono text-zinc-400">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
