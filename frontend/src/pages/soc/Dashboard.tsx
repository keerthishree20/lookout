import { BellRing } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { CategoryBars, ChartCard, RiskLine, STATUS, StackedTimeBars } from "@/components/charts";
import { Stat } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { DashboardStats, Policy, RiskTrendBucket } from "@/lib/types";

const BANDS = ["low", "medium", "high", "critical"] as const;

export function Dashboard() {
  const { alerts, stats, version } = useLive();
  const [dash, setDash] = useState<DashboardStats | null>(null);
  const [trend, setTrend] = useState<RiskTrendBucket[]>([]);
  const [policy, setPolicy] = useState<Pick<Policy, "medium" | "high" | "critical">>({ medium: 30, high: 60, critical: 80 });

  useEffect(() => {
    const load = () => {
      api.dashboard().then(setDash).catch(() => {});
      api.riskTrends(24).then((r) => setTrend(r.buckets)).catch(() => {});
    };
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [version]);

  useEffect(() => {
    api.policy().then(setPolicy).catch(() => {});
  }, [version]);

  const series = trend.map((b) => ({
    label: new Date(b.start).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }),
    allowed: b.count - b.flagged,
    flagged: b.flagged,
    peak: b.peak,
    login_anomalies: b.login_anomalies ?? 0,
    privilege_escalations: b.privilege_escalations ?? 0,
  }));
  const outcomes = dash?.message_outcomes;
  const messageResults = outcomes
    ? [
        { name: "Delivered", value: outcomes.delivered },
        { name: "Verification required", value: outcomes.verification },
        { name: "Quarantined", value: outcomes.quarantined },
        { name: "Blocked", value: outcomes.blocked },
      ]
    : [];
  const threat = Object.entries(dash?.threat_distribution ?? {}).map(([k, v]) => ({ name: humanise(k), value: v }));
  const bands = BANDS.map((b) => ({ name: b[0].toUpperCase() + b.slice(1), value: dash?.score_distribution[b] ?? 0 }));
  const alertTypes = Object.entries(dash?.alerts_by_type ?? {}).map(([k, v]) => ({ name: k, value: v }));

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <Stat label="Users" value={dash?.total_users ?? "—"} hint="with baselines" />
        <Stat label="Active sessions" value={dash?.active_sessions ?? "—"} hint="signed in now" />
        <Stat label="High-risk users" value={dash?.high_risk_users ?? "—"} hint={`peak ≥ ${policy.high}`} tone={dash?.high_risk_users ? "danger" : "default"} />
        <Stat label="Critical alerts" value={dash?.critical_alerts ?? "—"} hint="open" tone={dash?.critical_alerts ? "danger" : "default"} />
        <Stat label="Blocked messages" value={dash?.blocked_messages ?? "—"} hint="stopped at gateway" tone={dash?.blocked_messages ? "warn" : "default"} />
        <Stat label="Quarantined" value={dash?.quarantined_messages ?? "—"} hint="awaiting review" tone={dash?.quarantined_messages ? "info" : "default"} />
        <Stat label="Privileged accounts" value={dash?.privileged_accounts ?? "—"} hint="enhanced monitoring" />
        <Stat label="Decoys served" value={stats?.honeypots_served ?? "—"} hint={`${stats?.in_honeypot ?? 0} in honeypot`} tone={stats?.honeypots_served ? "danger" : "default"} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartCard
          title="Activity over time"
          subtitle="Scored events per interval, split by whether Lookout let them through"
          table={{ columns: ["Interval", "Allowed", "Flagged"], rows: series.map((s) => [s.label, s.allowed, s.flagged]) }}
        >
          <StackedTimeBars data={series} keys={["allowed", "flagged"]} labels={["Allowed", "Flagged"]} />
        </ChartCard>
        <ChartCard
          title="Peak risk per interval"
          subtitle="Highest score seen in each interval, against the live band thresholds"
          table={{ columns: ["Interval", "Peak risk"], rows: series.map((s) => [s.label, s.peak]) }}
        >
          <RiskLine
            data={series}
            dataKey="peak"
            name="Peak risk"
            thresholds={[
              { value: policy.medium, label: "Medium", color: STATUS.medium },
              { value: policy.high, label: "High", color: STATUS.high },
              { value: policy.critical, label: "Critical", color: STATUS.critical },
            ]}
          />
        </ChartCard>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <ChartCard
          title="Risk score distribution"
          subtitle="Decisions per band"
          table={{ columns: ["Band", "Decisions"], rows: bands.map((b) => [b.name, b.value]) }}
        >
          <CategoryBars data={bands} colors={BANDS.map((b) => STATUS[b])} height={180} />
        </ChartCard>
        <ChartCard
          title="Threat classification"
          subtitle="Flagged decisions by insider type"
          table={{ columns: ["Class", "Decisions"], rows: threat.map((t) => [t.name, t.value]) }}
        >
          <CategoryBars data={threat} height={180} />
        </ChartCard>
        <ChartCard
          title="Message scanning results"
          subtitle="Every outbound message the gateway has scored, by outcome"
          table={{ columns: ["Outcome", "Messages"], rows: messageResults.map((m) => [m.name, m.value]) }}
        >
          <CategoryBars
            data={messageResults}
            colors={[STATUS.low, STATUS.medium, "#3987e5", STATUS.critical]}
            height={180}
          />
        </ChartCard>
        <ChartCard
          title="Login anomalies and privilege escalation attempts"
          subtitle={`Per interval · ${dash?.login_anomalies ?? 0} flagged sign-ins and ${dash?.privilege_escalation_attempts ?? 0} escalation attempts in total`}
          table={{
            columns: ["Interval", "Login anomalies", "Escalation attempts"],
            rows: series.map((r) => [r.label, r.login_anomalies, r.privilege_escalations]),
          }}
        >
          <StackedTimeBars
            data={series}
            keys={["login_anomalies", "privilege_escalations"]}
            labels={["Login anomalies", "Privilege escalation attempts"]}
            height={180}
          />
        </ChartCard>
        <ChartCard
          title="Alerts by type"
          subtitle="High and critical alerts raised"
          table={{ columns: ["Type", "Alerts"], rows: alertTypes.map((a) => [a.name, a.value]) }}
        >
          <CategoryBars data={alertTypes} height={180} />
        </ChartCard>
      </div>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/60">
        <header className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
            <BellRing className="h-4 w-4 text-red-400" /> Live alerts
          </h2>
          <Link to="/alerts" className="text-xs text-sky-400 hover:text-sky-300">All alerts →</Link>
        </header>
        {alerts.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-zinc-500">No alerts. Run a scenario from Simulation to see one arrive here in real time.</p>
        ) : (
          <ul className="divide-y divide-zinc-800/70">
            {alerts.slice(0, 8).map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm">
                <span
                  className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                    a.severity === "CRITICAL" ? "bg-red-600/25 text-red-100" : "bg-orange-500/15 text-orange-200"
                  }`}
                >
                  {a.severity}
                </span>
                <span className="font-medium text-zinc-100">{a.alert_type}</span>
                <span className="text-zinc-400">{a.user}</span>
                <span className="font-mono text-xs text-zinc-500">risk {a.risk_score.toFixed(0)}</span>
                <span className="ml-auto font-mono text-xs text-zinc-600">{dateTime(a.ts)}</span>
                {a.incident_id && (
                  <Link to={`/incidents/${a.incident_id}`} className="text-xs text-sky-400 hover:text-sky-300">
                    {a.incident_id}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
