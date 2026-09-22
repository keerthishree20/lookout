import { CheckCircle2, Inbox, Loader2, MailWarning, Send, ShieldX } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import { humanise } from "@/lib/format";
import type { Attachment, Decision, GatewayResult, HeldMessage } from "@/lib/types";

import { ComponentBars } from "./MessageDetail";
import { ActionChip, BandChip, Button, Card, ClassChip, Empty } from "./ui";

const SENDERS = [
  ["m.d'souza", "officer"],
  ["p.nair", "officer"],
  ["s.iyer", "teller"],
  ["r.krishnan", "teller"],
  ["l.mathew", "manager"],
  ["n.pillai", "domain admin"],
  ["k.venkatesh", "analyst"],
] as const;

type Preset = {
  label: string;
  sender: string;
  count: number;
  body: string;
  channel?: string;
  audience?: string;
  recipient?: string;
  attachment?: string;
};

const PRESETS: Preset[] = [
  {
    label: "Phishing blast",
    sender: "m.d'souza",
    count: 50000,
    body: "Meridian Bank: your account will be suspended in 24h. Re-verify KYC now: http://meridian-bank.secure-verify.top/re-kyc",
  },
  {
    label: "Lookalike domain",
    sender: "p.nair",
    count: 1,
    body: "Please log in to confirm your loan: https://meridianbamk.com/login",
  },
  {
    label: "Shortened link",
    sender: "l.mathew",
    count: 800,
    body: "Festive cashback offer, claim here: https://bit.ly/3mB-offer",
  },
  {
    label: "Scam, no link",
    sender: "s.iyer",
    count: 1,
    body: "This is the Meridian fraud team. Please reply with the OTP you just received so we can stop the fraudulent debit.",
  },
  {
    label: "Customer data to Gmail",
    sender: "k.venkatesh",
    count: 1,
    channel: "email",
    audience: "internal",
    recipient: "k.venkat.home@gmail.com",
    body: "Account no 502128842312, Aadhaar 2345 6789 0123, PAN ABCDE1234F, card 4111 1111 1111 1111",
  },
  {
    label: "Disguised attachment",
    sender: "r.krishnan",
    count: 40,
    channel: "email",
    body: "Please find your updated statement attached.",
    attachment: "statement.pdf.exe, 180",
  },
  {
    label: "Legitimate",
    sender: "p.nair",
    count: 1,
    body: "Hi, your loan documents are ready: https://secure.meridianbank.com/loans",
  },
];

/** "name.ext, size KB; other.ext, size" -> attachment metadata. */
function parseAttachments(text: string): Attachment[] {
  return text
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const [name, size] = part.split(",").map((x) => x.trim());
      return { name, size_kb: Number(size) || 0, content_type: "" };
    });
}

export function GatewayPanel({
  onDecision,
  refreshKey,
}: {
  onDecision: (d: Decision) => void;
  refreshKey: number;
}) {
  const [sender, setSender] = useState<string>(PRESETS[0].sender);
  const [count, setCount] = useState<number>(PRESETS[0].count);
  const [audience, setAudience] = useState("customer");
  const [channel, setChannel] = useState("sms");
  const [body, setBody] = useState(PRESETS[0].body);
  const [recipient, setRecipient] = useState("");
  const [attachments, setAttachments] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<GatewayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [queue, setQueue] = useState<HeldMessage[]>([]);

  const loadQueue = useCallback(() => {
    api.quarantine().then(setQueue).catch(() => setQueue([]));
  }, []);

  useEffect(() => {
    loadQueue();
  }, [loadQueue, refreshKey]);

  async function scan() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.scanMessage({
        sender,
        channel,
        recipient_count: count,
        audience,
        body,
        recipient,
        attachments: parseAttachments(attachments),
      });
      setResult(r);
      onDecision(r.decision);
      loadQueue();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const verdict = result
    ? result.delivered
      ? { icon: <CheckCircle2 className="h-5 w-5" />, text: "Delivered", tone: "text-emerald-300 bg-emerald-500/10 ring-emerald-500/30" }
      : result.held
        ? { icon: <Inbox className="h-5 w-5" />, text: "Held in quarantine for review", tone: "text-sky-300 bg-sky-500/10 ring-sky-500/30" }
        : result.requires_step_up
          ? { icon: <MailWarning className="h-5 w-5" />, text: "Held until sender completes step-up authentication", tone: "text-amber-300 bg-amber-500/10 ring-amber-500/30" }
          : { icon: <ShieldX className="h-5 w-5" />, text: "Blocked", tone: "text-red-300 bg-red-500/10 ring-red-500/40" }
    : null;

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <Card
        title="Outbound message gateway"
        icon={<Send className="h-4 w-4 text-sky-400" />}
        className="lg:col-span-3"
      >
        <p className="mb-3 text-xs leading-relaxed text-zinc-500">
          Every staff SMS, email and push passes through here before it leaves the bank. Links are
          extracted from the body — a sender cannot hide one by leaving it out of a separate field.
        </p>
        <div className="mb-3 flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              onClick={() => {
                setSender(p.sender);
                setCount(p.count);
                setBody(p.body);
                setChannel(p.channel ?? "sms");
                setAudience(p.audience ?? "customer");
                setRecipient(p.recipient ?? "");
                setAttachments(p.attachment ?? "");
                setResult(null);
              }}
              className="rounded-md px-2 py-1 text-xs text-zinc-400 ring-1 ring-inset ring-zinc-700 transition hover:bg-zinc-800 hover:text-zinc-200"
            >
              {p.label}
            </button>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <label className="col-span-2 text-xs text-zinc-400 sm:col-span-1">
            Sender
            <select
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200"
            >
              {SENDERS.map(([a, r]) => (
                <option key={a} value={a}>{a} ({r})</option>
              ))}
            </select>
          </label>
          <label className="text-xs text-zinc-400">
            Recipients
            <input
              type="number"
              min={1}
              value={count}
              onChange={(e) => setCount(Math.max(1, Number(e.target.value) || 1))}
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 font-mono text-sm text-zinc-200"
            />
          </label>
          <label className="text-xs text-zinc-400">
            Audience
            <select
              value={audience}
              onChange={(e) => setAudience(e.target.value)}
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200"
            >
              <option value="customer">customers</option>
              <option value="internal">internal</option>
            </select>
          </label>
          <label className="text-xs text-zinc-400">
            Channel
            <select
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200"
            >
              <option value="sms">SMS</option>
              <option value="email">Email</option>
              <option value="push">Push</option>
              <option value="notification">Notification</option>
            </select>
          </label>
        </div>
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="text-xs text-zinc-400">
            Recipient <span className="text-zinc-600">(address, number or segment)</span>
            <input
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder="optional"
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200"
            />
          </label>
          <label className="text-xs text-zinc-400">
            Attachments <span className="text-zinc-600">(name, KB; …)</span>
            <input
              value={attachments}
              onChange={(e) => setAttachments(e.target.value)}
              placeholder="e.g. report.xlsx, 9000"
              className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 font-mono text-sm text-zinc-200"
            />
          </label>
        </div>
        <label className="mt-3 block text-xs text-zinc-400">
          Message
          <textarea
            rows={3}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className="mt-1 w-full resize-y rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 font-mono text-sm text-zinc-200"
          />
        </label>
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary" onClick={scan} disabled={busy || !body.trim()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            Send through gateway
          </Button>
          {error && <span className="text-xs text-red-400">{error}</span>}
        </div>

        {result && verdict && (
          <div className="mt-4 space-y-3">
            <div className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium ring-1 ring-inset ${verdict.tone}`}>
              {verdict.icon}
              {verdict.text}
              <span className="ml-auto flex gap-1.5">
                <BandChip band={result.decision.risk.band} />
                {result.decision.threat_class !== "benign" && <ClassChip cls={result.decision.threat_class} />}
              </span>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
              <div className="mb-1 flex items-baseline justify-between">
                <span className="text-[11px] uppercase tracking-wider text-zinc-500">Message risk score</span>
                <span className="font-mono text-2xl font-semibold text-zinc-100">
                  {result.decision.risk.total.toFixed(0)}
                </span>
              </div>
              <p className="text-xs leading-relaxed text-zinc-400">{result.decision.narrative}</p>
              <div className="mt-3">
                <ComponentBars components={result.message_risk.components} total={result.message_risk.score} />
              </div>
            </div>
            {result.urls.map((u) => (
              <div key={u.url} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
                <div className="flex items-center justify-between gap-2">
                  <code className="truncate text-xs text-zinc-300">{u.url}</code>
                  <span className={`shrink-0 font-mono text-xs ${u.suspicious ? "text-orange-300" : "text-emerald-300"}`}>
                    {u.suspicious ? "suspicious" : "clean"} · URL risk {u.risk_score}
                  </span>
                </div>
                {u.impersonates && (
                  <div className="mt-1 text-xs text-red-300">Impersonates {u.impersonates}</div>
                )}
                <ul className="mt-1.5 list-disc space-y-0.5 pl-4 text-xs text-zinc-500">
                  {u.findings.map((f) => <li key={f}>{f}</li>)}
                </ul>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card
        title={`Quarantine (${queue.length})`}
        icon={<Inbox className="h-4 w-4 text-sky-400" />}
        className="lg:col-span-2"
      >
        <p className="mb-3 text-xs leading-relaxed text-zinc-500">
          High-risk messages are held rather than destroyed, so a reviewer can release a false alarm.
          Every release is written to the signed audit log.
        </p>
        {queue.length === 0 ? (
          <Empty>No messages held.</Empty>
        ) : (
          <ul className="space-y-2">
            {queue.map((q) => (
              <li key={q.quarantine_id} className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-sky-300">{q.quarantine_id}</span>
                  <ActionChip action={q.action_taken} />
                </div>
                <div className="mt-1 text-sm text-zinc-300">
                  {q.event.actor} → {q.event.message?.recipient_count.toLocaleString()} {q.event.message?.audience}
                </div>
                <div className="mt-0.5 text-xs text-zinc-500">
                  score {q.risk.total.toFixed(0)} · {q.risk.signals.map((s) => humanise(s.name)).join(", ")}
                </div>
                <div className="mt-2 flex gap-2">
                  <Button
                    variant="ghost"
                    className="text-xs"
                    onClick={async () => {
                      await api.release(q.quarantine_id);
                      loadQueue();
                    }}
                  >
                    Release
                  </Button>
                  <Button variant="ghost" className="text-xs" onClick={() => onDecision(q)}>
                    Inspect
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
