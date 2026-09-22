import { Inbox } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { ActionChip, Button, Card, Empty } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import { loadSession } from "@/lib/session";
import type { Decision } from "@/lib/types";

type Held = Decision & { quarantine_id: string };

/** Messages held rather than delivered. Only security staff can release one. */
export function Quarantine() {
  const { version, refresh } = useLive();
  const [rows, setRows] = useState<Held[]>([]);
  const me = loadSession()?.profile.username ?? "soc";
  const load = useCallback(() => {
    api.quarantine().then(setRows).catch(() => {});
  }, []);
  useEffect(load, [load, version]);

  return (
    <Card title={`Quarantined messages (${rows.length})`} icon={<Inbox className="h-4 w-4 text-sky-400" />}>
      {rows.length === 0 ? (
        <Empty>Nothing held. High-risk messages, and any customer message with a suspicious link, land here.</Empty>
      ) : (
        <ul className="space-y-2">
          {rows.map((q) => (
            <li key={q.quarantine_id} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-sky-300">{q.quarantine_id}</span>
                <span className="text-zinc-200">{q.event.actor}</span>
                <span className="text-xs text-zinc-500">
                  → {q.event.message?.recipient_count.toLocaleString()} {q.event.message?.audience} · {q.event.message?.channel}
                </span>
                <span className="ml-auto font-mono text-xs text-zinc-500">{dateTime(q.event.ts)}</span>
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                <span className="font-mono text-zinc-300">risk {q.risk.total.toFixed(0)}</span>
                <ActionChip action={q.action_taken} />
                <span className="text-zinc-500">{humanise(q.threat_class)}</span>
              </div>
              {q.event.message?.body && (
                <p className="mt-2 rounded bg-zinc-950 p-2 font-mono text-[11px] text-zinc-400">{q.event.message.body}</p>
              )}
              <ul className="mt-2 list-disc space-y-0.5 pl-4 text-xs text-zinc-500">
                {q.risk.signals.slice(0, 3).map((s) => <li key={s.name}>{s.explanation}</li>)}
              </ul>
              {q.policy && <p className="mt-1 text-xs text-sky-200/80">Held by policy: {q.policy}</p>}
              <div className="mt-2 flex gap-2">
                <Button className="text-xs" onClick={() => api.release(q.quarantine_id, me).then(() => { load(); refresh(); })}>
                  Release
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
