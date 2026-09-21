"use client";

import { FileSignature, Gavel, MapPin, Monitor, ShieldAlert, Sparkles, User } from "lucide-react";

import { dateTime, humanise } from "@/lib/format";
import type { Decision } from "@/lib/types";

import { ActionChip, BandChip, Card, ClassChip, Empty } from "./ui";

/** The explainability panel: every number on it traces back to a named rule
 *  or to the capped behavioural-model contribution. */
export function DecisionDetail({ decision }: { decision: Decision | null }) {
  if (!decision) {
    return (
      <Card title="Why?" icon={<Sparkles className="h-4 w-4 text-sky-400" />}>
        <Empty>Select any decision in the feed to see exactly why Lookout scored it the way it did.</Empty>
      </Card>
    );
  }

  const { event, risk } = decision;
  const ruleSignals = risk.signals.filter((s) => s.name !== "behavioural_model");
  const model = risk.signals.find((s) => s.name === "behavioural_model");
  const maxPoints = Math.max(1, ...risk.signals.map((s) => s.points));
  const step = event.meta?.step_up_required as string | undefined;

  return (
    <Card
      title="Why?"
      icon={<Sparkles className="h-4 w-4 text-sky-400" />}
      right={<span className="font-mono text-xs text-zinc-500">audit #{decision.audit_seq ?? "—"}</span>}
    >
      <div className="space-y-4">
        {/* verdict */}
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="font-mono text-5xl font-semibold tabular-nums text-zinc-50">
              {risk.total.toFixed(0)}
              <span className="text-lg text-zinc-500">/100</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <BandChip band={risk.band} />
              <ActionChip action={decision.action_taken} />
              {decision.threat_class !== "benign" && <ClassChip cls={decision.threat_class} />}
            </div>
          </div>
          {decision.quarantine_id && (
            <span className="rounded-md bg-sky-500/10 px-2 py-1 font-mono text-xs text-sky-300 ring-1 ring-sky-500/30">
              {decision.quarantine_id}
            </span>
          )}
        </div>

        {/* narrative */}
        <p className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-sm leading-relaxed text-zinc-300">
          {decision.narrative}
        </p>

        {decision.policy && (
          <div className="flex items-start gap-2 rounded-lg bg-sky-500/10 px-3 py-2 text-sm text-sky-200 ring-1 ring-sky-500/30">
            <Gavel className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              <strong className="font-semibold">Held by policy.</strong> {decision.policy}
            </span>
          </div>
        )}

        {step && (
          <div className="flex items-center gap-2 rounded-lg bg-amber-500/10 px-3 py-2 text-sm text-amber-200 ring-1 ring-amber-500/30">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            Risk-based auth required: <strong className="font-semibold">{humanise(step)}</strong>
          </div>
        )}

        {/* the arithmetic */}
        <div>
          <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-zinc-500">
            How the score was built
          </h3>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 font-mono text-xs text-zinc-400">
            ( {risk.rule_points.toFixed(1)} rules + {risk.model_points.toFixed(1)} model ) ×{" "}
            {risk.privilege_multiplier.toFixed(2)} privilege
            <span className="text-zinc-600"> = </span>
            <span className="text-zinc-100">{risk.total.toFixed(1)}</span>
            {(risk.rule_points + risk.model_points) * risk.privilege_multiplier > 100 && (
              <span className="text-zinc-600"> (capped at 100)</span>
            )}
          </div>
        </div>

        {/* signals */}
        <div>
          <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-zinc-500">
            Evidence ({ruleSignals.length} rule{ruleSignals.length === 1 ? "" : "s"} fired)
          </h3>
          {ruleSignals.length === 0 && !model && (
            <p className="text-sm text-zinc-500">No detector fired. Nothing about this looked unusual.</p>
          )}
          <ul className="space-y-2">
            {[...ruleSignals, ...(model ? [model] : [])].map((s) => (
              <li key={s.name} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
                <div className="mb-1.5 flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-sky-300">{s.name}</span>
                  <span className="font-mono text-xs tabular-nums text-zinc-400">
                    +{s.points.toFixed(1)}
                  </span>
                </div>
                <div className="mb-2 h-1 overflow-hidden rounded-full bg-zinc-800">
                  <div
                    className={s.name === "behavioural_model" ? "h-full bg-violet-500" : "h-full bg-sky-500"}
                    style={{ width: `${(s.points / maxPoints) * 100}%` }}
                  />
                </div>
                <p className="text-xs leading-relaxed text-zinc-400">{s.explanation}</p>
                {s.indicates.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {s.indicates.map((c, i) => (
                      <span
                        key={c}
                        className={`rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${
                          i === 0 ? "bg-zinc-800 text-zinc-300" : "text-zinc-500"
                        }`}
                        title={i === 0 ? "primary evidence" : "secondary evidence (half weight)"}
                      >
                        {humanise(c)}
                      </span>
                    ))}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>

        {/* the event */}
        <div>
          <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Event</h3>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-xs">
            <dt className="flex items-center gap-1 text-zinc-500"><User className="h-3 w-3" />Actor</dt>
            <dd className="text-zinc-300">{event.actor} · {humanise(event.actor_role)}</dd>
            <dt className="text-zinc-500">Action</dt>
            <dd className="text-zinc-300">
              {humanise(event.action)}
              {event.resource && <span className="text-zinc-500"> on </span>}
              <span className="font-mono">{event.resource}</span>
              {!event.success && <span className="text-red-400"> (failed)</span>}
            </dd>
            <dt className="flex items-center gap-1 text-zinc-500"><MapPin className="h-3 w-3" />From</dt>
            <dd className="text-zinc-300">
              {event.geo.city}, {event.geo.country} · <span className="font-mono">{event.source_ip}</span>
            </dd>
            <dt className="flex items-center gap-1 text-zinc-500"><Monitor className="h-3 w-3" />Device</dt>
            <dd className="font-mono text-zinc-300">{event.device_id}</dd>
            <dt className="text-zinc-500">When</dt>
            <dd className="text-zinc-300">{dateTime(event.ts)}</dd>
            {event.message && (
              <>
                <dt className="text-zinc-500">Message</dt>
                <dd className="text-zinc-300">
                  {event.message.recipient_count.toLocaleString()} × {event.message.channel} to{" "}
                  {event.message.audience}
                  {event.message.body && (
                    <span className="mt-1 block rounded bg-zinc-950 p-2 font-mono text-[11px] text-zinc-400">
                      {event.message.body}
                    </span>
                  )}
                </dd>
              </>
            )}
            <dt className="flex items-center gap-1 text-zinc-500"><FileSignature className="h-3 w-3" />Session</dt>
            <dd className="font-mono text-zinc-400">{String(event.meta?.session_id ?? "—")}</dd>
          </dl>
        </div>
      </div>
    </Card>
  );
}
