import { MonitorSmartphone } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { Button, Card, Empty, SearchBox } from "@/components/ui";
import { useLive } from "@/hooks/useLive";
import { api } from "@/lib/api";
import { dateTime, humanise } from "@/lib/format";
import type { SessionRow } from "@/lib/types";

export function Sessions() {
  const { version, pulse } = useLive();
  const [rows, setRows] = useState<SessionRow[]>([]);
  const [search, setSearch] = useState("");
  const load = useCallback(() => {
    api.sessions().then(setRows).catch(() => {});
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load, version, pulse.sessions]);

  return (
    <Card
      title={`Active sessions (${rows.length})`}
      icon={<MonitorSmartphone className="h-4 w-4 text-sky-400" />}
      right={<SearchBox value={search} onChange={setSearch} placeholder="User, kind, role" />}
    >
      <p className="mb-3 text-xs text-zinc-500">
        Signed-in portal and console sessions. Revoking ends the session at once, and any further use of it is
        scored as a replayed token.
      </p>
      {rows.length === 0 ? (
        <Empty>Nobody is signed in.</Empty>
      ) : (
        <div className="-mx-4 -mb-4 overflow-x-auto">
          <table className="w-full min-w-[620px] text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">Session</th>
                <th className="px-2 py-2 font-medium">User</th>
                <th className="px-2 py-2 font-medium">Kind</th>
                <th className="px-2 py-2 font-medium">Role</th>
                <th className="px-2 py-2 font-medium">Expires</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows
                .filter((s) => !search.trim() || `${s.username} ${s.kind} ${s.role ?? ""}`.toLowerCase().includes(search.trim().toLowerCase()))
                .map((s) => (
                <tr key={s.session_id} className="border-t border-zinc-800/70">
                  <td className="px-4 py-2 font-mono text-xs text-zinc-400">{s.session_id}</td>
                  <td className="px-2 py-2 text-zinc-200">{s.username}</td>
                  <td className="px-2 py-2 text-xs text-zinc-400">{s.kind}</td>
                  <td className="px-2 py-2 text-xs text-zinc-400">{humanise(s.role ?? "")}</td>
                  <td className="px-2 py-2 font-mono text-xs text-zinc-500">{dateTime(s.expires)}</td>
                  <td className="px-4 py-2 text-right">
                    <Button variant="ghost" className="text-xs" onClick={() => api.revokeSession(s.session_id).then(load)}>
                      Revoke
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
