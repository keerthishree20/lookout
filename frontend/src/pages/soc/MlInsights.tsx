import { BrainCircuit, Info } from "lucide-react";
import { useEffect, useState } from "react";

import { CategoryBars, ChartCard } from "@/components/charts";
import { EvaluationPanel } from "@/components/EvaluationPanel";
import { Card, Stat } from "@/components/ui";
import { api } from "@/lib/api";
import { humanise, pct } from "@/lib/format";
import type { MlMetrics, SplitMetrics } from "@/lib/types";

/** The supervised classifier's real training results, and the rule engine's
 *  detection evaluation, side by side. */
export function MlInsights() {
  const [m, setM] = useState<MlMetrics | null>(null);
  const [split, setSplit] = useState<"random_split_25pct" | "unseen_employees">("random_split_25pct");

  useEffect(() => {
    api.mlMetrics().then(setM).catch(() => {});
  }, []);

  const s = m?.[split];
  const importance = (m?.feature_importance ?? [])
    .slice(0, 10)
    .map(([k, v]) => ({ name: humanise(k), value: Math.round(v * 1000) / 10 }));

  return (
    <div className="space-y-5">
      <div className="flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-200/90">
        <Info className="mt-0.5 h-4 w-4 shrink-0" />
        <p>
          The classifier is trained on <strong>{m?.dataset.rows.toLocaleString() ?? "10,000+"} synthetic sessions</strong>{" "}
          from Lookout's own simulator (realistic class imbalance; threats are spliced into real simulated work days at
          random intensities). The numbers below are its actual evaluation, weak class included. They are not a claim
          about real bank data, which should replace this dataset in production.
        </p>
      </div>

      {m && s && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
              <BrainCircuit className="h-4 w-4 text-violet-400" /> Supervised classifier
            </h2>
            <span className="text-xs text-zinc-500">{m.model}</span>
            <div className="ml-auto flex rounded-md ring-1 ring-zinc-800">
              {(
                [
                  ["random_split_25pct", "25% random test split"],
                  ["unseen_employees", "Unseen employees"],
                ] as const
              ).map(([k, label]) => (
                <button
                  key={k}
                  onClick={() => setSplit(k)}
                  className={`px-2.5 py-1 text-xs ${split === k ? "bg-sky-500/15 text-sky-200" : "text-zinc-400 hover:text-zinc-200"}`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          {split === "unseen_employees" && (
            <p className="text-xs text-zinc-500">
              Trained without {s.held_out_users?.join(", ")} and tested only on them. This is the harder, more honest test.
            </p>
          )}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="Accuracy" value={pct(s.accuracy)} hint={`n = ${s.n.toLocaleString()}`} />
            <Stat label="Macro F1" value={s.macro_f1.toFixed(3)} />
            <Stat label="ROC-AUC (macro)" value={s.roc_auc_ovr_macro.toFixed(3)} />
            <Stat label="PR-AUC (macro)" value={s.pr_auc_macro.toFixed(3)} />
            <Stat label="Threat recall" value={pct(s.threat_recall)} hint="threats not called normal" tone="ok" />
            <Stat
              label="False alarms"
              value={pct(s.normal_false_alarm_rate, 2)}
              hint="of normal sessions"
              tone={s.normal_false_alarm_rate > 0.03 ? "warn" : "ok"}
            />
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <PerClass s={s} />
            <Confusion s={s} />
          </div>
          <ChartCard
            title="Feature importance"
            subtitle="Mean decrease in impurity (%) in the served model"
            table={{ columns: ["Feature", "Importance %"], rows: importance.map((i) => [i.name, i.value]) }}
          >
            <CategoryBars data={importance} height={300} />
          </ChartCard>
        </>
      )}

      <h2 className="pt-2 text-sm font-semibold text-zinc-200">Rule engine: detection evaluation</h2>
      <EvaluationPanel />
    </div>
  );
}

function PerClass({ s }: { s: SplitMetrics }) {
  return (
    <Card title="Per-class results">
      <table className="w-full text-left text-sm">
        <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
          <tr>
            <th className="py-1 font-medium">Class</th>
            <th className="py-1 text-right font-medium">Precision</th>
            <th className="py-1 text-right font-medium">Recall</th>
            <th className="py-1 text-right font-medium">F1</th>
            <th className="py-1 text-right font-medium">PR-AUC</th>
            <th className="py-1 text-right font-medium">n</th>
          </tr>
        </thead>
        <tbody className="font-mono text-xs">
          {Object.entries(s.per_class).map(([cls, v]) => (
            <tr key={cls} className="border-t border-zinc-800/70">
              <td className="py-1.5 font-sans text-sm text-zinc-200">{humanise(cls)}</td>
              <td className={`py-1.5 text-right ${v.precision < 0.7 ? "text-amber-300" : "text-zinc-300"}`}>{v.precision.toFixed(3)}</td>
              <td className={`py-1.5 text-right ${v.recall < 0.7 ? "text-amber-300" : "text-zinc-300"}`}>{v.recall.toFixed(3)}</td>
              <td className="py-1.5 text-right text-zinc-300">{v.f1.toFixed(3)}</td>
              <td className="py-1.5 text-right text-zinc-300">{v.pr_auc.toFixed(3)}</td>
              <td className="py-1.5 text-right text-zinc-500">{v.support}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-[11px] text-zinc-500">Values under 0.70 are highlighted: that class is the model's weak spot.</p>
    </Card>
  );
}

function Confusion({ s }: { s: SplitMetrics }) {
  const { labels, rows_true_cols_pred: rows } = s.confusion_matrix;
  const max = Math.max(1, ...rows.flat());
  return (
    <Card title="Confusion matrix">
      <div className="overflow-x-auto">
        <table className="text-center text-xs">
          <thead>
            <tr>
              <th className="px-2 py-1 text-left text-[10px] font-medium text-zinc-500">true ↓ / predicted →</th>
              {labels.map((l) => (
                <th key={l} className="px-2 py-1 font-medium text-zinc-400">{humanise(l)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={labels[i]}>
                <th className="px-2 py-1 text-left font-medium text-zinc-400">{humanise(labels[i])}</th>
                {row.map((v, j) => {
                  // One hue, darker = more sessions. The count is always
                  // printed, so colour is never the only channel.
                  const a = v === 0 ? 0 : 0.12 + 0.75 * Math.sqrt(v / max);
                  return (
                    <td
                      key={j}
                      className={`px-3 py-1.5 font-mono ${i === j ? "font-semibold text-zinc-50" : v ? "text-amber-200" : "text-zinc-600"}`}
                      style={{ background: `rgba(57,135,229,${a})` }}
                    >
                      {v}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-[11px] text-zinc-500">Diagonal = correct. Off-diagonal counts are mistakes, shown in amber.</p>
    </Card>
  );
}
