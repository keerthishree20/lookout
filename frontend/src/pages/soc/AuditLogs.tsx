import { ScrollText } from "lucide-react";
import { useEffect, useState } from "react";

import { AuditPanel } from "@/components/AuditPanel";
import { ProtectedStorePanel } from "@/components/ProtectedStorePanel";
import { Card, Empty, Pagination, SearchBox, Select, usePaged } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime, humanise, short } from "@/lib/format";
import type { AuditEntry } from "@/lib/types";

const KINDS = [
  { value: "", label: "Everything" },
  { value: "decision", label: "Decisions" },
  { value: "auth.", label: "Sign-ins" },
  { value: "quarantine.", label: "Quarantine" },
  { value: "honeypot", label: "Honeypot" },
  { value: "policy.", label: "Policy changes" },
  { value: "admin.", label: "Admin operations" },
  { value: "session.", label: "Sessions" },
  { value: "incident.", label: "Incidents" },
  { value: "integrity.", label: "Integrity alerts" },
];

export function AuditLogs() {
  const { version, reset } = useLive();
  return (
    <div className="space-y-4">
      <AuditPanel refreshKey={version} onReset={reset} />
      <ProtectedStorePanel refreshKey={version} />
      <FullAuditLog refreshKey={version} />
    </div>
  );
}

/** Every security-sensitive action, searchable and filterable. */
function FullAuditLog({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [kind, setKind] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    api
      .auditLogs(1000, kind)
      .then((r) => {
        setEntries(r.entries);
        setTotal(r.total);
      })
      .catch(() => {});
  }, [refreshKey, kind]);

  const needle = search.trim().toLowerCase();
  const filtered = entries.filter((e) => !needle || JSON.stringify(e.payload).toLowerCase().includes(needle) || e.kind.includes(needle));
  const paged = usePaged(filtered, 20);

  return (
    <Card
      title={`Audit log (${total} entries)`}
      icon={<ScrollText className="h-4 w-4 text-sky-400" />}
      right={
        <div className="flex flex-wrap gap-2">
          <Select label="Kind" value={kind} onChange={setKind} options={KINDS} />
          <SearchBox value={search} onChange={setSearch} placeholder="User, action, id" />
        </div>
      }
    >
      {filtered.length === 0 ? (
        <Empty>No entries match.</Empty>
      ) : (
        <div className="-mx-4 -mb-4">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-xs">
              <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="px-4 py-2 font-medium">#</th>
                  <th className="px-2 py-2 font-medium">When</th>
                  <th className="px-2 py-2 font-medium">Action</th>
                  <th className="px-2 py-2 font-medium">Detail</th>
                  <th className="px-4 py-2 font-medium">Integrity hash</th>
                </tr>
              </thead>
              <tbody>
                {paged.items.map((e) => (
                  <tr key={e.seq} className="border-t border-zinc-800/70">
                    <td className="px-4 py-1.5 font-mono text-zinc-500">{e.seq}</td>
                    <td className="px-2 py-1.5 font-mono text-zinc-500">{dateTime(e.ts)}</td>
                    <td className="px-2 py-1.5 text-zinc-200">{humanise(e.kind)}</td>
                    <td className="max-w-[360px] truncate px-2 py-1.5 text-zinc-400">
                      {e.kind === "decision"
                        ? `${e.payload.actor} · ${humanise(String(e.payload.action))} → ${humanise(String(e.payload.action_taken))} (${e.payload.risk_total})`
                        : Object.entries(e.payload).slice(0, 4).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ")}
                    </td>
                    <td className="px-4 py-1.5 font-mono text-zinc-600">{short(e.entry_hash, 14)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination {...paged} />
        </div>
      )}
    </Card>
  );
}
