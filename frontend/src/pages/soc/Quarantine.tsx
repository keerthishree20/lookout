import { Inbox } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { MessageDetail } from "@/components/MessageDetail";
import { Button, Card, Empty, Modal, Pagination, SearchBox, usePaged } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { ApiError, api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { HeldMessage } from "@/lib/types";

type Verb = "release" | "block" | "delete" | "investigate";

const VERBS: { verb: Verb; label: string; variant: "default" | "primary" | "danger" | "ghost"; confirm?: string }[] = [
  { verb: "release", label: "Release", variant: "default", confirm: "Deliver this message to its recipients?" },
  { verb: "block", label: "Block", variant: "danger" },
  { verb: "delete", label: "Delete", variant: "ghost", confirm: "Discard this message for good?" },
  { verb: "investigate", label: "Investigate", variant: "primary" },
];

/** Messages held rather than delivered. Only security staff can act on them. */
export function Quarantine() {
  const { version, refresh, pulse } = useLive();
  const [rows, setRows] = useState<HeldMessage[]>([]);
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<HeldMessage | null>(null);
  const [confirm, setConfirm] = useState<{ row: HeldMessage; verb: Verb; text: string } | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(() => {
    api.quarantine().then(setRows).catch(() => {});
  }, []);
  useEffect(load, [load, version, pulse.messages]);

  async function act(row: HeldMessage, verb: Verb) {
    const id = row.quarantine_id;
    try {
      if (verb === "release") await api.release(id);
      if (verb === "block") await api.blockHeld(id);
      if (verb === "delete") await api.deleteHeld(id);
      if (verb === "investigate") {
        const r = await api.investigateHeld(id);
        setNote(`${id} is under investigation in ${r.incident_id}.`);
      } else {
        setNote(`${id} ${verb === "block" ? "blocked" : verb === "delete" ? "deleted" : "released"}.`);
      }
      setOpen(null);
      load();
      refresh();
    } catch (e) {
      setNote(e instanceof ApiError ? e.detail : "Action failed.");
    }
  }

  function request(row: HeldMessage, verb: Verb) {
    const v = VERBS.find((x) => x.verb === verb)!;
    if (v.confirm) setConfirm({ row, verb, text: v.confirm });
    else act(row, verb);
  }

  const needle = search.trim().toLowerCase();
  const filtered = rows.filter(
    (r) => !needle || `${r.message.sender} ${r.message.recipient} ${r.message.body} ${r.quarantine_id}`.toLowerCase().includes(needle),
  );
  const paged = usePaged(filtered, 10);

  return (
    <Card
      title={`Quarantined messages (${rows.length})`}
      icon={<Inbox className="h-4 w-4 text-sky-400" />}
      right={<SearchBox value={search} onChange={setSearch} placeholder="Sender, recipient, text" />}
    >
      {note && <p className="mb-3 rounded-md bg-sky-500/10 px-3 py-2 text-xs text-sky-200">{note}</p>}
      {filtered.length === 0 ? (
        <Empty>Nothing held. High-risk messages, and any customer message with a suspicious link, land here.</Empty>
      ) : (
        <div className="-mx-4 -mb-4">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="px-4 py-2 font-medium">Message</th>
                  <th className="px-2 py-2 font-medium">Sender</th>
                  <th className="px-2 py-2 font-medium">Recipient</th>
                  <th className="px-2 py-2 font-medium">Time</th>
                  <th className="px-2 py-2 font-medium">Risk</th>
                  <th className="px-2 py-2 font-medium">URLs</th>
                  <th className="px-2 py-2 font-medium">Classification</th>
                  <th className="px-2 py-2 font-medium">Review</th>
                  <th className="px-4 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {paged.items.map((r) => (
                  <tr key={r.quarantine_id} className="border-t border-zinc-800/70 align-top">
                    <td className="px-4 py-2">
                      <button onClick={() => setOpen(r)} className="font-mono text-xs text-sky-300 hover:underline">
                        {r.quarantine_id}
                      </button>
                      <p className="mt-0.5 max-w-[220px] truncate text-xs text-zinc-500" title={r.message.body}>
                        {r.message.reasons[0] ?? r.message.body}
                      </p>
                    </td>
                    <td className="px-2 py-2 text-zinc-200">{r.message.sender}</td>
                    <td className="max-w-[160px] truncate px-2 py-2 text-xs text-zinc-400" title={r.message.recipient}>
                      {r.message.recipient}
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-500">{dateTime(r.message.timestamp)}</td>
                    <td className="px-2 py-2 font-mono text-xs text-zinc-200">
                      {r.message.risk_score.toFixed(0)} <span className="text-zinc-500">{r.message.risk_level}</span>
                    </td>
                    <td className="max-w-[180px] truncate px-2 py-2 font-mono text-[11px] text-zinc-500">
                      {r.message.urls.map((u) => `${u.host} (${u.risk_score})`).join(", ") || "—"}
                    </td>
                    <td className="px-2 py-2 text-xs text-zinc-400">{humanise(r.message.classification)}</td>
                    <td className="px-2 py-2 text-xs">
                      {r.review.status === "INVESTIGATING" ? (
                        <Link to={`/incidents/${r.review.incident_id}`} className="text-amber-300 hover:underline">
                          Investigating
                        </Link>
                      ) : (
                        <span className="text-zinc-500">Held</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex flex-wrap gap-1">
                        {VERBS.map((v) => (
                          <Button key={v.verb} variant={v.variant} className="px-2 py-0.5 text-xs" onClick={() => request(r, v.verb)}>
                            {v.label}
                          </Button>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination {...paged} />
        </div>
      )}

      {open && (
        <Modal title={`Held message ${open.quarantine_id}`} onClose={() => setOpen(null)} wide>
          <MessageDetail row={open.message} policy={open.policy} />
          <div className="mt-4 flex flex-wrap gap-2 border-t border-zinc-800 pt-3">
            {VERBS.map((v) => (
              <Button key={v.verb} variant={v.variant} onClick={() => request(open, v.verb)}>
                {v.label}
              </Button>
            ))}
          </div>
        </Modal>
      )}
      {confirm && (
        <Modal title="Please confirm" onClose={() => setConfirm(null)}>
          <p className="text-sm text-zinc-300">{confirm.text}</p>
          <p className="mt-1 text-xs text-zinc-500">
            {confirm.row.quarantine_id} from {confirm.row.message.sender}. The decision is written to the signed audit log.
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => {
                const c = confirm;
                setConfirm(null);
                act(c.row, c.verb);
              }}
            >
              {humanise(confirm.verb)}
            </Button>
          </div>
        </Modal>
      )}
    </Card>
  );
}
