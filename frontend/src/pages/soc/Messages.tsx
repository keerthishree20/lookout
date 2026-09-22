import { Mail } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { ActionChip, BandChip, Card, Empty } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime } from "@/lib/format";
import type { Decision } from "@/lib/types";

/** Every outbound staff message the gateway has scored. */
export function Messages() {
  const { feed, version, select } = useLive();
  const [history, setHistory] = useState<Decision[]>([]);
  useEffect(() => {
    api.decisions(500).then(setHistory).catch(() => {});
  }, [version]);

  const seen = new Set<string>();
  const messages = [...feed, ...history].filter((d) => {
    if (d.event.action !== "send_message" || seen.has(d.event.event_id)) return false;
    seen.add(d.event.event_id);
    return true;
  });

  return (
    <Card
      title={`Outbound messages (${messages.length})`}
      icon={<Mail className="h-4 w-4 text-sky-400" />}
      right={<Link to="/message-scanner" className="text-xs text-sky-400">Scan a message →</Link>}
    >
      {messages.length === 0 ? (
        <Empty>No messages yet. Live traffic sends some; the Message scanner and scenarios send more.</Empty>
      ) : (
        <div className="-mx-4 -mb-4 overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">When</th>
                <th className="px-2 py-2 font-medium">Sender</th>
                <th className="px-2 py-2 font-medium">Channel</th>
                <th className="px-2 py-2 font-medium">Recipients</th>
                <th className="px-2 py-2 font-medium">URLs</th>
                <th className="px-2 py-2 font-medium">Risk</th>
                <th className="px-4 py-2 font-medium">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {messages.map((d) => {
                const m = d.event.message!;
                return (
                  <tr key={d.event.event_id} onClick={() => select(d)} className="cursor-pointer border-t border-zinc-800/70 hover:bg-zinc-800/40">
                    <td className="px-4 py-2 font-mono text-xs text-zinc-500">{dateTime(d.event.ts)}</td>
                    <td className="px-2 py-2 text-zinc-200">{d.event.actor}</td>
                    <td className="px-2 py-2 text-xs uppercase text-zinc-400">{m.channel}</td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-300">
                      {m.recipient_count.toLocaleString()} <span className="text-zinc-500">{m.audience}</span>
                    </td>
                    <td className="max-w-[240px] truncate px-2 py-2 font-mono text-[11px] text-zinc-500">{m.urls.join(" ") || "—"}</td>
                    <td className="px-2 py-2"><BandChip band={d.risk.band} /></td>
                    <td className="px-4 py-2"><ActionChip action={d.action_taken} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
