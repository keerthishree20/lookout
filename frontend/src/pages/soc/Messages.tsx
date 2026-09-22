import { Mail } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { MessageDetail } from "@/components/MessageDetail";
import { Card, Empty, Modal, Pagination, SearchBox, Select, usePaged } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { MessageRow, MessageStatus } from "@/lib/types";

const STATUS_STYLE: Record<MessageStatus, string> = {
  DELIVERED: "text-emerald-300",
  VERIFICATION_REQUIRED: "text-amber-300",
  QUARANTINED: "text-sky-300",
  BLOCKED: "text-red-300",
};

/** Every outbound staff message the gateway has scanned. */
export function Messages() {
  const { version, pulse } = useLive();
  const [rows, setRows] = useState<MessageRow[]>([]);
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<MessageRow | null>(null);

  useEffect(() => {
    api.messages(status).then(setRows).catch(() => {});
  }, [version, status, pulse.messages]);

  const needle = search.trim().toLowerCase();
  const filtered = rows.filter(
    (r) => !needle || `${r.sender} ${r.recipient} ${r.subject} ${r.body}`.toLowerCase().includes(needle),
  );
  const paged = usePaged(filtered, 15);

  return (
    <Card
      title={`Outbound messages (${filtered.length})`}
      icon={<Mail className="h-4 w-4 text-sky-400" />}
      right={
        <div className="flex flex-wrap items-center gap-2">
          <Select
            label="Status"
            value={status}
            onChange={setStatus}
            options={[
              { value: "", label: "All outcomes" },
              { value: "DELIVERED", label: "Delivered" },
              { value: "VERIFICATION_REQUIRED", label: "Verification required" },
              { value: "QUARANTINED", label: "Quarantined" },
              { value: "BLOCKED", label: "Blocked" },
            ]}
          />
          <SearchBox value={search} onChange={setSearch} placeholder="Sender, recipient, text" />
          <Link to="/message-scanner" className="text-xs text-sky-400">
            Scan a message →
          </Link>
        </div>
      }
    >
      {filtered.length === 0 ? (
        <Empty>No messages match. Live traffic sends some; the Message scanner and scenarios send more.</Empty>
      ) : (
        <div className="-mx-4 -mb-4">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="px-4 py-2 font-medium">When</th>
                  <th className="px-2 py-2 font-medium">Sender</th>
                  <th className="px-2 py-2 font-medium">Channel</th>
                  <th className="px-2 py-2 font-medium">Recipient</th>
                  <th className="px-2 py-2 font-medium">URLs</th>
                  <th className="px-2 py-2 font-medium">Risk</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {paged.items.map((m) => (
                  <tr
                    key={m.message_id}
                    onClick={() => setOpen(m)}
                    className="cursor-pointer border-t border-zinc-800/70 hover:bg-zinc-800/40"
                  >
                    <td className="px-4 py-2 font-mono text-xs text-zinc-500">{dateTime(m.timestamp)}</td>
                    <td className="px-2 py-2 text-zinc-200">{m.sender}</td>
                    <td className="px-2 py-2 text-xs uppercase text-zinc-400">{m.channel}</td>
                    <td className="max-w-[200px] truncate px-2 py-2 text-xs text-zinc-300">{m.recipient}</td>
                    <td className="max-w-[220px] truncate px-2 py-2 font-mono text-[11px] text-zinc-500">
                      {m.urls.map((u) => `${u.host} (${u.risk_score})`).join(", ") || "—"}
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-200">
                      {m.risk_score.toFixed(0)} <span className="text-zinc-500">{m.risk_level}</span>
                    </td>
                    <td className={`px-4 py-2 text-xs ${STATUS_STYLE[m.status]}`}>{humanise(m.status.toLowerCase())}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination {...paged} />
        </div>
      )}
      {open && (
        <Modal title={`Message from ${open.sender}`} onClose={() => setOpen(null)} wide>
          <MessageDetail row={open} />
        </Modal>
      )}
    </Card>
  );
}
