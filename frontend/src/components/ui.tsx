import { type ReactNode, useEffect, useState } from "react";
import { createPortal } from "react-dom";

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

/** A modal dialog: Escape or the backdrop closes it. Rendered into <body> so
 *  no ancestor (a card with backdrop-blur, say) can clip or reposition it. */
export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 pt-[8vh] backdrop-blur-sm"
      onClick={onClose}
      role="presentation"
    >
      <div
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        className={`w-full ${wide ? "max-w-3xl" : "max-w-lg"} rounded-xl border border-zinc-700 bg-zinc-900 shadow-2xl`}
      >
        <header className="flex items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
          <h2 className="min-w-0 truncate text-sm font-semibold text-zinc-100">{title}</h2>
          <button onClick={onClose} className="rounded p-1 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100" aria-label="Close">
            ✕
          </button>
        </header>
        <div className="max-h-[75vh] overflow-y-auto p-4">{children}</div>
      </div>
    </div>,
    document.body,
  );
}

/** Client-side paging for tables; resets to page 1 when the rows change size. */
export function usePaged<T>(rows: T[], pageSize = 15) {
  const [page, setPage] = useState(1);
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  useEffect(() => {
    if (page > pages) setPage(1);
  }, [page, pages]);
  const current = Math.min(page, pages);
  return {
    items: rows.slice((current - 1) * pageSize, current * pageSize),
    page: current,
    pages,
    setPage,
    total: rows.length,
  };
}

export function Pagination({
  page,
  pages,
  total,
  setPage,
}: {
  page: number;
  pages: number;
  total: number;
  setPage: (p: number) => void;
}) {
  if (pages <= 1) return <div className="px-4 py-2 text-xs text-zinc-500">{total} row{total === 1 ? "" : "s"}</div>;
  return (
    <div className="flex items-center justify-between gap-2 px-4 py-2 text-xs text-zinc-400">
      <span>
        {total} rows · page {page} of {pages}
      </span>
      <div className="flex gap-1">
        <Button variant="ghost" className="px-2 py-0.5 text-xs" disabled={page <= 1} onClick={() => setPage(page - 1)}>
          ‹ Prev
        </Button>
        <Button variant="ghost" className="px-2 py-0.5 text-xs" disabled={page >= pages} onClick={() => setPage(page + 1)}>
          Next ›
        </Button>
      </div>
    </div>
  );
}

export function SearchBox({
  value,
  onChange,
  placeholder = "Search",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <input
      type="search"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full min-w-0 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-sky-500 focus:outline-none sm:w-56"
    />
  );
}

export function Select({
  value,
  onChange,
  options,
  label,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  label: string;
}) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100 focus:border-sky-500 focus:outline-none"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}
