import type { ReactNode } from "react";

import { ACTION_STYLE, BAND_STYLE, CLASS_STYLE } from "@/lib/format";
import type { ActionTaken, Band, ThreatClass } from "@/lib/types";

export function Card({
  title,
  icon,
  right,
  children,
  className = "",
}: {
  title?: ReactNode;
  icon?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-zinc-800 bg-zinc-900/60 backdrop-blur ${className}`}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold tracking-wide text-zinc-200">
            {icon}
            {title}
          </h2>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

function Chip({ className, children }: { className: string; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${className}`}
    >
      {children}
    </span>
  );
}

export function BandChip({ band }: { band: Band }) {
  const s = BAND_STYLE[band];
  return (
    <Chip className={s.chip}>
      <span aria-hidden>{s.dot}</span>
      {s.label}
    </Chip>
  );
}

export function ActionChip({ action }: { action: ActionTaken }) {
  const s = ACTION_STYLE[action];
  return <Chip className={s.chip}>{s.label}</Chip>;
}

export function ClassChip({ cls }: { cls: ThreatClass }) {
  const s = CLASS_STYLE[cls];
  return <Chip className={`bg-transparent ${s.chip}`}>{s.label}</Chip>;
}

export function ScoreBar({ score, band }: { score: number; band: Band }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-zinc-800">
        <div
          className={`h-full ${BAND_STYLE[band].bar} transition-[width] duration-500`}
          style={{ width: `${Math.max(2, Math.min(100, score))}%` }}
        />
      </div>
      <span className="w-8 text-right font-mono text-xs tabular-nums text-zinc-300">
        {score.toFixed(0)}
      </span>
    </div>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "default" | "danger" | "warn" | "info" | "ok";
}) {
  const toneClass = {
    default: "text-zinc-100",
    danger: "text-red-300",
    warn: "text-amber-300",
    info: "text-sky-300",
    ok: "text-emerald-300",
  }[tone];
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${toneClass}`}>
        {value}
      </div>
      {hint && <div className="mt-0.5 text-xs text-zinc-500">{hint}</div>}
    </div>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "default",
  type = "button",
  className = "",
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "default" | "primary" | "danger" | "ghost";
  type?: "button" | "submit";
  className?: string;
  title?: string;
}) {
  const v = {
    default: "bg-zinc-800 text-zinc-100 hover:bg-zinc-700 ring-zinc-700",
    primary: "bg-sky-600 text-white hover:bg-sky-500 ring-sky-500",
    danger: "bg-red-600/90 text-white hover:bg-red-500 ring-red-500",
    ghost: "bg-transparent text-zinc-300 hover:bg-zinc-800 ring-zinc-800",
  }[variant];
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium ring-1 ring-inset transition disabled:cursor-not-allowed disabled:opacity-50 ${v} ${className}`}
    >
      {children}
    </button>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-zinc-800 px-4 py-8 text-center text-sm text-zinc-500">
      {children}
    </div>
  );
}
