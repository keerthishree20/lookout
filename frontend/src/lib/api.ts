import type {
  AuditListing,
  CryptoStatus,
  Decision,
  Evaluation,
  GatewayResult,
  Health,
  Identity,
  Scenario,
  ScenarioRun,
  SealResult,
  Stats,
  UrlVerdict,
  Verification,
} from "./types";

// 8077 rather than the usual 8000, which is the first port every other local
// FastAPI project grabs.
export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8077"
).replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* body was not JSON */
    }
    throw new Error(`${res.status} ${detail}`);
  }
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

export const api = {
  health: () => request<Health>("/api/health"),
  stats: () => request<Stats>("/api/stats"),
  crypto: () => request<CryptoStatus>("/api/crypto"),
  decisions: (limit = 80, flaggedOnly = false) =>
    request<Decision[]>(
      `/api/decisions?limit=${limit}&flagged_only=${flaggedOnly}`,
    ),
  scenarios: () => request<Scenario[]>("/api/scenarios"),
  runScenario: (key: string) =>
    post<ScenarioRun>(`/api/scenarios/${encodeURIComponent(key)}/run`),
  traffic: (mode: "pause" | "resume") =>
    post<{ traffic_paused: boolean }>(`/api/traffic/${mode}`),
  reset: () => post<Stats>("/api/reset"),
  scanMessage: (body: {
    sender: string;
    channel: string;
    recipient_count: number;
    audience: string;
    body: string;
  }) => post<GatewayResult>("/api/messages/scan", body),
  inspectUrl: (url: string) => post<UrlVerdict>("/api/urls/inspect", { url }),
  quarantine: () =>
    request<(Decision & { quarantine_id: string })[]>("/api/quarantine"),
  release: (qid: string, reviewer: string) =>
    post<{ released: string }>(`/api/quarantine/${qid}/release`, { reviewer }),
  users: () => request<Identity[]>("/api/users"),
  audit: (limit = 40) => request<AuditListing>(`/api/audit?limit=${limit}`),
  verify: () => request<Verification>("/api/audit/verify"),
  tamper: (seq: number) =>
    post<{ tampered: number; verify: Verification }>(`/api/audit/tamper/${seq}`),
  seal: (name: string, secret: string) =>
    post<SealResult>("/api/credentials/seal", { name, secret }),
  evaluation: (refresh = false) =>
    request<Evaluation>(`/api/evaluation?refresh=${refresh}`),
};

export const streamUrl = `${API_URL}/api/stream`;
