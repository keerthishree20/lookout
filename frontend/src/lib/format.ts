import type { ActionTaken, Band, ThreatClass } from "./types";

export const BAND_STYLE: Record<Band, { label: string; dot: string; chip: string; bar: string }> = {
  low: {
    label: "Low",
    dot: "🟢",
    chip: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
    bar: "bg-emerald-500",
  },
  medium: {
    label: "Medium",
    dot: "🟡",
    chip: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
    bar: "bg-amber-400",
  },
  // The spec's risk colours: low green, medium yellow, high orange, critical red.
  high: {
    label: "High",
    dot: "🟠",
    chip: "bg-orange-500/10 text-orange-300 ring-orange-500/40",
    bar: "bg-orange-500",
  },
  critical: {
    label: "Critical",
    dot: "🔴",
    chip: "bg-red-600/15 text-red-200 ring-red-500/70",
    bar: "bg-red-600",
  },
};

export const ACTION_STYLE: Record<ActionTaken, { label: string; chip: string }> = {
  allow: { label: "Allowed", chip: "bg-zinc-800 text-zinc-300 ring-zinc-700" },
  step_up: {
    label: "Step-up auth",
    chip: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  },
  quarantine: {
    label: "Quarantined",
    chip: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
  },
  block: { label: "Blocked", chip: "bg-red-500/10 text-red-300 ring-red-500/40" },
  block_and_alert: {
    label: "Blocked + SOC alert",
    chip: "bg-red-600/20 text-red-100 ring-red-500/70",
  },
};

export const CLASS_STYLE: Record<ThreatClass, { label: string; chip: string }> = {
  benign: { label: "Benign", chip: "text-zinc-400 ring-zinc-700" },
  negligent: { label: "Negligent", chip: "text-amber-300 ring-amber-500/40" },
  malicious: { label: "Malicious", chip: "text-red-300 ring-red-500/50" },
  compromised: { label: "Compromised", chip: "text-fuchsia-300 ring-fuchsia-500/50" },
  privilege_abuse: {
    label: "Privilege abuse",
    chip: "text-orange-300 ring-orange-500/50",
  },
};

export function humanise(s: string): string {
  return s.replaceAll("_", " ");
}

export function time(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function dateTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function pct(n: number, digits = 1): string {
  return `${(n * 100).toFixed(digits)}%`;
}

export function short(hash: string, n = 10): string {
  return hash.length > n ? `${hash.slice(0, n)}…` : hash;
}
