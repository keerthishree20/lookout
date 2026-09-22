import { FlaskConical, Info, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { humanise, pct } from "@/lib/format";
import type { Evaluation } from "@/lib/types";

import { ActionChip, Card, ClassChip, Stat } from "./ui";

export function EvaluationPanel() {
  const [data, setData] = useState<Evaluation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.evaluation().then(setData).catch((e) => setError(String(e)));
  }, []);

  if (error) return <Card title="Detection quality"><p className="text-sm text-red-400">{error}</p></Card>;
  if (!data)
    return (
      <Card title="Detection quality" icon={<FlaskConical className="h-4 w-4 text-sky-400" />}>
        <div className="flex items-center gap-2 text-sm text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Replaying ~1,000 labelled events…
        </div>
      </Card>
    );

  const o = data.overall;
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-200/90">
        <Info className="mt-0.5 h-4 w-4 shrink-0" />
        <p>
          These numbers are measured on <strong>synthetic</strong> data from Lookout&apos;s own generator: a month of
          ordinary work for 12 staff, then a held-out week the model never saw, plus the six scenarios. They show
          the detectors are internally consistent and do not fire on ordinary work — including legitimate bulk
          campaigns and weekend on-call admin. They are <strong>not</strong> a claim about accuracy on a real
          bank&apos;s logs, which no project without access to those logs can make.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Precision" value={pct(o.precision)} hint={`${o.true_positive} of ${o.true_positive + o.false_positive} alerts real`} tone="ok" />
        <Stat label="Recall" value={pct(o.recall)} hint={`${o.true_positive} of ${o.true_positive + o.false_negative} incident events`} tone="ok" />
        <Stat label="F1" value={o.f1.toFixed(3)} />
        <Stat label="False-positive rate" value={pct(o.false_positive_rate, 2)} hint={`${o.false_positive} of ${data.benign_events} benign`} tone={o.false_positive ? "warn" : "ok"} />
        <Stat label="Classification" value={pct(data.classification.accuracy)} hint={`${data.classification.correct}/${data.classification.total} named correctly`} tone="info" />
      </div>

      <Card title="Per scenario (incident events only)" icon={<FlaskConical className="h-4 w-4 text-sky-400" />}>
        <div className="-mx-4 -mb-4 overflow-x-auto">
          <table className="w-full min-w-[620px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">Scenario</th>
                <th className="px-2 py-2 font-medium">Detected</th>
                <th className="px-2 py-2 font-medium">Peak</th>
                <th className="px-2 py-2 font-medium">Strongest response</th>
                <th className="px-4 py-2 font-medium">Classified as</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.per_scenario).map(([k, r]) => (
                <tr key={k} className="border-t border-zinc-800/70">
                  <td className="px-4 py-2 text-zinc-200">{humanise(k)}</td>
                  <td className="px-2 py-2 font-mono text-xs">
                    <span className={r.detected === r.events ? "text-emerald-300" : "text-amber-300"}>
                      {r.detected}/{r.events}
                    </span>
                  </td>
                  <td className="px-2 py-2 font-mono text-xs text-zinc-300">{r.peak_score.toFixed(0)}</td>
                  <td className="px-2 py-2"><ActionChip action={r.strongest_action} /></td>
                  <td className="px-4 py-2"><ClassChip cls={r.classified_as} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-6 text-xs leading-relaxed text-zinc-500">
          The known miss is the 02:14 login that opens the exfiltration scenario: an unusual hour on its own is not
          enough to block someone. The 412,000-row query four minutes later is blocked before any data leaves.
        </p>
      </Card>
    </div>
  );
}
