import { token, type StoredSession } from "./session";
import type {
  AuditListing,
  CryptoStatus,
  CustomerPage,
  Decision,
  DemoAccount,
  Evaluation,
  GatewayResult,
  Health,
  HoneypotListing,
  Identity,
  Scenario,
  ScenarioRun,
  SealResult,
  Stats,
  TraceResult,
  UrlVerdict,
  Verification,
} from "./types";

// 8077 rather than the usual 8000, which is the first port every other local
// FastAPI project grabs.
export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8077"
).replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(`${status} ${detail}`);
  }
}

function authHeaders(): Record<string, string> {
  const t = token();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function raw(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(init?.headers ?? {}),
    },
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
    throw new ApiError(res.status, detail);
  }
  return res;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  return (await raw(path, init)).json() as Promise<T>;
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

  // auth
  login: (username: string, password: string) =>
    post<StoredSession>("/api/auth/login", { username, password }),
  logout: () => post<{ ok: boolean }>("/api/auth/logout"),
  me: () => request<{ kind: StoredSession["kind"]; profile: StoredSession["profile"] }>("/api/auth/me"),
  demoAccounts: () => request<DemoAccount[]>("/api/auth/demo-accounts"),

  // employee portal
  customers: (q = "", offset = 0, limit = 50) =>
    request<CustomerPage>(
      `/api/portal/customers?q=${encodeURIComponent(q)}&offset=${offset}&limit=${limit}`,
    ),
  /** Returns the PDF and the filename the server chose. */
  exportPdf: async (body: { count?: number; customer_ids?: string[] }) => {
    const res = await raw("/api/portal/export", {
      method: "POST",
      body: JSON.stringify(body),
    });
    const disposition = res.headers.get("content-disposition") ?? "";
    const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? "customers.pdf";
    return { blob: await res.blob(), filename };
  },

  // honeypot (SOC)
  honeypots: () => request<HoneypotListing>("/api/honeypots"),
  trace: (q: string) => request<TraceResult>(`/api/honeypots/trace?q=${encodeURIComponent(q)}`),
  clearWatchlist: (actor: string, reviewer: string) =>
    post<{ cleared: string }>(
      `/api/honeypots/watchlist/${encodeURIComponent(actor)}/clear`,
      { reviewer },
    ),
};

/** EventSource cannot send headers, so the token rides in the query string. */
export const streamUrl = () =>
  `${API_URL}/api/stream?token=${encodeURIComponent(token() ?? "")}`;
