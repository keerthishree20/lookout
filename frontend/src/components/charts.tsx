// Chart building blocks. Colours come from the validated reference palette
// (dark steps, checked against the dark surface for colour-blind separation);
// status colours are used only where the data *is* a state (risk bands).
// Every chart can flip to a table, so nothing is conveyed by colour alone.

import { Table2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export const SERIES = ["#3987e5", "#d95926"] as const; // categorical slots 1-2 (dark)
export const SEQ = "#3987e5"; // single-hue magnitude
export const STATUS = {
  low: "#0ca30c",
  medium: "#fab219",
  high: "#ec835a",
  critical: "#d03b3b",
} as const;

const AXIS = { stroke: "#52525b", fontSize: 11, tickLine: false, axisLine: false } as const;
const GRID = "#27272a";
const TOOLTIP = {
  contentStyle: { background: "#18181b", border: "1px solid #3f3f46", borderRadius: 8, fontSize: 12 },
  labelStyle: { color: "#e4e4e7" },
  itemStyle: { color: "#d4d4d8" },
  cursor: { fill: "rgba(255,255,255,0.04)" },
};

export function ChartCard({
  title,
  subtitle,
  table,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  table: { columns: string[]; rows: (string | number)[][] };
  children: ReactNode;
  className?: string;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className={`rounded-xl border border-zinc-800 bg-zinc-900/60 ${className}`}>
      <header className="flex items-start justify-between gap-2 border-b border-zinc-800 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-zinc-200">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-zinc-500">{subtitle}</p>}
        </div>
        <button
          onClick={() => setAsTable((t) => !t)}
          className={`inline-flex items-center gap-1 rounded px-1.5 py-1 text-[11px] ring-1 ring-inset ${
            asTable ? "bg-sky-500/10 text-sky-300 ring-sky-500/40" : "text-zinc-500 ring-zinc-800 hover:text-zinc-300"
          }`}
          aria-pressed={asTable}
          title="Show the data as a table"
        >
          <Table2 className="h-3 w-3" /> Table
        </button>
      </header>
      <div className="p-4">
        {asTable ? (
          <div className="max-h-64 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-zinc-500">
                <tr>{table.columns.map((c) => <th key={c} className="py-1 pr-3 font-medium">{c}</th>)}</tr>
              </thead>
              <tbody className="text-zinc-300">
                {table.rows.map((r, i) => (
                  <tr key={i} className="border-t border-zinc-800/70">
                    {r.map((v, j) => <td key={j} className="py-1 pr-3 font-mono">{v}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          children
        )}
      </div>
    </section>
  );
}

/** Horizontal bars for counts per category: one hue, identity by label. */
export function CategoryBars({
  data,
  colors,
  height = 220,
}: {
  data: { name: string; value: number }[];
  colors?: string[];
  height?: number;
}) {
  if (!data.length) return <Empty />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }} barCategoryGap={6}>
        <CartesianGrid horizontal={false} stroke={GRID} />
        <XAxis type="number" allowDecimals={false} {...AXIS} />
        <YAxis type="category" dataKey="name" width={150} {...AXIS} tick={{ fill: "#a1a1aa", fontSize: 11 }} />
        <Tooltip {...TOOLTIP} />
        <Bar dataKey="value" name="Count" radius={[0, 4, 4, 0]} maxBarSize={18} label={{ position: "right", fill: "#a1a1aa", fontSize: 11 }}>
          {data.map((d, i) => (
            <Cell key={d.name} fill={colors?.[i] ?? SEQ} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Two series stacked per time bucket, with a legend. */
export function StackedTimeBars({
  data,
  keys,
  labels,
  height = 220,
}: {
  data: Record<string, string | number>[];
  keys: [string, string];
  labels: [string, string];
  height?: number;
}) {
  if (!data.length) return <Empty />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ left: -12, right: 8, top: 8, bottom: 0 }} barCategoryGap={2}>
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="label" {...AXIS} minTickGap={24} />
        <YAxis allowDecimals={false} {...AXIS} />
        <Tooltip {...TOOLTIP} />
        <Legend wrapperStyle={{ fontSize: 11, color: "#a1a1aa" }} iconType="square" iconSize={9} />
        <Bar dataKey={keys[0]} name={labels[0]} stackId="a" fill={SERIES[0]} stroke="#18181b" strokeWidth={1} />
        <Bar dataKey={keys[1]} name={labels[1]} stackId="a" fill={SERIES[1]} stroke="#18181b" strokeWidth={1} radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/** One line over time, with labelled reference lines for the band thresholds. */
export function RiskLine({
  data,
  dataKey,
  name,
  thresholds,
  height = 220,
}: {
  data: Record<string, string | number>[];
  dataKey: string;
  name: string;
  thresholds?: { value: number; label: string; color: string }[];
  height?: number;
}) {
  if (!data.length) return <Empty />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ left: -12, right: 16, top: 8, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="label" {...AXIS} minTickGap={24} />
        <YAxis domain={[0, 100]} {...AXIS} />
        <Tooltip {...TOOLTIP} cursor={{ stroke: "#52525b" }} />
        {thresholds?.map((t) => (
          <ReferenceLine
            key={t.label}
            y={t.value}
            stroke={t.color}
            strokeDasharray="4 4"
            strokeOpacity={0.6}
            label={{ value: t.label, position: "insideTopRight", fill: "#a1a1aa", fontSize: 10 }}
          />
        ))}
        <Line type="monotone" dataKey={dataKey} name={name} stroke={SEQ} strokeWidth={2} dot={false} activeDot={{ r: 4, stroke: "#18181b", strokeWidth: 2 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

function Empty() {
  return <div className="grid h-40 place-items-center text-sm text-zinc-500">No data yet. Run a scenario from Simulation.</div>;
}
