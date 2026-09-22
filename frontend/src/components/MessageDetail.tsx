import { dateTime, humanise } from "@/lib/format";
import type { MessageComponents, MessageRow } from "@/lib/types";

const COMPONENT_LABELS: Record<keyof MessageComponents, string> = {
  url: "URL",
  sender_behaviour: "Sender behaviour",
  content: "Content",
  destination: "Destination",
  privilege: "Privilege",
  volume: "Volume",
};

/** The spec's message risk formula: six parts that add up to the score. */
export function ComponentBars({ components, total }: { components: MessageComponents; total: number }) {
  return (
    <div className="space-y-1.5">
      {(Object.keys(COMPONENT_LABELS) as (keyof MessageComponents)[]).map((k) => (
        <div key={k} className="grid grid-cols-[120px_minmax(0,1fr)_40px] items-center gap-2 text-xs">
          <span className="text-zinc-400">{COMPONENT_LABELS[k]}</span>
          <div className="h-1.5 overflow-hidden rounded-full bg-zinc-800">
            <div className="h-full bg-sky-500" style={{ width: `${Math.min(100, components[k])}%` }} />
          </div>
          <span className="text-right font-mono tabular-nums text-zinc-300">{components[k].toFixed(1)}</span>
        </div>
      ))}
      <div className="grid grid-cols-[120px_minmax(0,1fr)_40px] gap-2 border-t border-zinc-800 pt-1.5 text-xs">
        <span className="font-medium text-zinc-200">Message risk</span>
        <span />
        <span className="text-right font-mono font-semibold text-zinc-100">{total.toFixed(1)}</span>
      </div>
    </div>
  );
}

/** Everything the spec asks an analyst to see about one message. */
export function MessageDetail({ row, policy }: { row: MessageRow; policy?: string | null }) {
  return (
    <div className="space-y-4 text-sm">
      <dl className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
        <dt className="text-zinc-500">Message ID</dt>
        <dd className="break-all font-mono text-zinc-300">{row.message_id}</dd>
        <dt className="text-zinc-500">Sender</dt>
        <dd className="text-zinc-200">
          {row.sender} <span className="text-zinc-500">({humanise(row.sender_role)})</span>
        </dd>
        <dt className="text-zinc-500">Recipient</dt>
        <dd className="text-zinc-200">
          {row.recipient} · {row.recipient_count.toLocaleString()} · {row.channel.toUpperCase()}
        </dd>
        <dt className="text-zinc-500">Timestamp</dt>
        <dd className="font-mono text-zinc-300">{dateTime(row.timestamp)}</dd>
        <dt className="text-zinc-500">Status</dt>
        <dd className="text-zinc-200">{humanise(row.status.toLowerCase())}</dd>
        <dt className="text-zinc-500">Risk score</dt>
        <dd className="font-mono text-zinc-100">
          {row.risk_score.toFixed(1)} · {row.risk_level}
        </dd>
        <dt className="text-zinc-500">Classification</dt>
        <dd className="text-zinc-200">{humanise(row.classification)}</dd>
      </dl>

      {row.subject && <p className="text-xs text-zinc-400">Subject: {row.subject}</p>}
      <p className="whitespace-pre-wrap break-words rounded bg-zinc-950 p-2 font-mono text-[11px] text-zinc-300">{row.body}</p>
      {row.attachments.length > 0 && (
        <p className="text-xs text-zinc-400">
          Attachments: {row.attachments.map((a) => `${a.name} (${Math.round(a.size_kb)} KB)`).join(", ")}
        </p>
      )}

      <section>
        <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Reasons</h3>
        <ul className="list-disc space-y-0.5 pl-4 text-xs text-zinc-300">
          {row.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
        {policy && <p className="mt-1 text-xs text-sky-200/80">Held by policy: {policy}</p>}
      </section>

      {row.urls.length > 0 && (
        <section>
          <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Detected URLs</h3>
          <ul className="space-y-1.5">
            {row.urls.map((u) => (
              <li key={u.url} className="rounded border border-zinc-800 p-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="break-all font-mono text-zinc-200">{u.url}</span>
                  <span className={`ml-auto font-mono ${u.suspicious ? "text-orange-300" : "text-emerald-300"}`}>
                    URL risk {u.risk_score}
                  </span>
                </div>
                <ul className="mt-1 list-disc pl-4 text-zinc-500">
                  {u.findings.map((f) => (
                    <li key={f}>{f}</li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Message risk breakdown</h3>
        <ComponentBars components={row.components} total={row.risk_score} />
      </section>
    </div>
  );
}
