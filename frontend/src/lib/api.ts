import axios, { AxiosError, type AxiosRequestConfig } from "axios";

import { token, type StoredSession } from "./session";
import type {
  AccessCheckResult,
  AccessRequest,
  AccountRow,
  AccountView,
  AdminUserRow,
  Alert,
  Artefact,
  Attachment,
  AuditListing,
  CryptoStatus,
  CustomerPage,
  DashboardStats,
  DbStatus,
  Decision,
  DemoAccount,
  Evaluation,
  GatewayResult,
  Health,
  HeldMessage,
  HoneypotListing,
  Identity,
  Incident,
  IncidentDetail,
  LoginRisk,
  MessageRow,
  MfaChallenge,
  MlMetrics,
  MyProfile,
  NotifyStatus,
  Policy,
  Receipt,
  RiskExplanation,
  RiskTrendBucket,
  RoleRow,
  RuntimeConfig,
  Scenario,
  ScenarioRun,
  SealResult,
  SessionRow,
  Stats,
  TeamOverview,
  TraceResult,
  TransferResult,
  UrlVerdict,
  UserRisk,
  Verification,
} from "./types";

// 8077 rather than the usual 8000, which is the first port every other local
// FastAPI project grabs. In Docker the site and API share an origin, so the
// build sets VITE_API_URL to "" and requests go to /api on the same host.
const configured = import.meta.env.VITE_API_URL as string | undefined;
export const API_URL = (configured ?? "http://localhost:8077").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(`${status} ${detail}`);
  }
}

const http = axios.create({ baseURL: API_URL, headers: { "Content-Type": "application/json" } });

http.interceptors.request.use((config) => {
  const t = token();
  if (t) config.headers.set("Authorization", `Bearer ${t}`);
  return config;
});

function toApiError(e: unknown): never {
  if (e instanceof AxiosError) {
    if (e.response) {
      const detail = (e.response.data as { detail?: unknown } | undefined)?.detail;
      throw new ApiError(e.response.status, typeof detail === "string" ? detail : e.response.statusText);
    }
    throw new ApiError(0, "network error");
  }
  throw e;
}

async function request<T>(path: string, config?: AxiosRequestConfig): Promise<T> {
  try {
    return (await http.request<T>({ url: path, ...config })).data;
  } catch (e) {
    return toApiError(e);
  }
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, data?: unknown) => request<T>(path, { method: "POST", data });
const put = <T>(path: string, data?: unknown) => request<T>(path, { method: "PUT", data });

/** Sign-in context for the demo: where, on what and when the sign-in claims to come from. */
export interface SignInContext {
  device_id?: string;
  city?: string;
  ip?: string;
  at_hour?: number;
}

export type LoginResult = (StoredSession & { risk?: LoginRisk }) | MfaChallenge;

const q = encodeURIComponent;

export const api = {
  // console
  health: () => get<Health>("/api/health"),
  stats: () => get<Stats>("/api/stats"),
  crypto: () => get<CryptoStatus>("/api/crypto"),
  decisions: (limit = 80, flaggedOnly = false) =>
    get<Decision[]>(`/api/decisions?limit=${limit}&flagged_only=${flaggedOnly}`),
  scenarios: () => get<Scenario[]>("/api/scenarios"),
  runScenario: (key: string) => post<ScenarioRun>(`/api/scenarios/${q(key)}/run`),
  traffic: (mode: "pause" | "resume") => post<{ traffic_paused: boolean }>(`/api/traffic/${mode}`),
  reset: () => post<Stats>("/api/reset"),
  scanMessage: (body: {
    sender: string;
    channel: string;
    recipient_count: number;
    audience: string;
    body: string;
    subject?: string;
    recipient?: string;
    attachments?: Attachment[];
  }) => post<GatewayResult>("/api/messages/scan", body),
  messages: (status = "", search = "") =>
    get<MessageRow[]>(`/api/messages?limit=1000${status ? `&status=${q(status)}` : ""}${search ? `&q=${q(search)}` : ""}`),
  message: (id: string) => get<MessageRow>(`/api/messages/${q(id)}`),
  inspectUrl: (url: string) => post<UrlVerdict>("/api/urls/inspect", { url }),
  quarantine: () => get<HeldMessage[]>("/api/quarantine"),
  release: (qid: string) => post<{ released: string }>(`/api/quarantine/${q(qid)}/release`, {}),
  blockHeld: (qid: string) => post<{ blocked: string }>(`/api/quarantine/${q(qid)}/block`),
  deleteHeld: (qid: string) => post<{ deleted: string }>(`/api/quarantine/${q(qid)}/delete`),
  investigateHeld: (qid: string) =>
    post<{ investigating: string; incident_id: string }>(`/api/quarantine/${q(qid)}/investigate`),
  users: () => get<Identity[]>("/api/users"),
  userRisk: (actor: string) => get<UserRisk>(`/api/users/${q(actor)}/risk`),
  userActivity: (actor: string, limit = 50) => get<Decision[]>(`/api/users/${q(actor)}/activity?limit=${limit}`),
  audit: (limit = 40) => get<AuditListing>(`/api/audit?limit=${limit}`),
  verify: () => get<Verification>("/api/audit/verify"),
  tamper: (seq: number) => post<{ tampered: number; verify: Verification }>(`/api/audit/tamper/${seq}`),
  seal: (name: string, secret: string) => post<SealResult>("/api/credentials/seal", { name, secret }),
  artefacts: () => get<{ artefacts: Artefact[]; algorithm: string; quantum_safe: boolean }>("/api/crypto/artefacts"),
  verifyArtefacts: () =>
    post<{ ok: boolean; results: { name: string; ok: boolean; reason: string }[]; alert?: Alert }>(
      "/api/crypto/artefacts/verify",
    ),
  tamperArtefact: (name: string) => post<{ tampered: string }>(`/api/crypto/artefacts/tamper?name=${q(name)}`),
  auditLogs: (limit = 500, action = "") =>
    get<AuditListing>(`/api/audit-logs?limit=${limit}${action ? `&action=${q(action)}` : ""}`),
  evaluation: (refresh = false) => get<Evaluation>(`/api/evaluation?refresh=${refresh}`),
  explanation: (eventId: string) => get<RiskExplanation>(`/api/risk/${q(eventId)}/explanation`),
  mlMetrics: () => get<MlMetrics>("/api/ml/metrics"),
  dashboard: () => get<DashboardStats>("/api/dashboard/statistics"),
  riskTrends: (buckets = 24) => get<{ buckets: RiskTrendBucket[] }>(`/api/dashboard/risk-trends?buckets=${buckets}`),
  alerts: (status?: string) => get<Alert[]>(`/api/alerts${status ? `?status=${q(status)}` : ""}`),
  alertStatus: (id: string, status: string) => post<Alert>(`/api/alerts/${q(id)}/status`, { status }),
  incidents: () => get<Incident[]>("/api/incidents"),
  incident: (id: string) => get<IncidentDetail>(`/api/incidents/${q(id)}`),
  createIncident: (body: { title: string; user: string; severity: string; description: string }) =>
    post<Incident>("/api/incidents", body),
  assignIncident: (id: string, analyst: string) => post<Incident>(`/api/incidents/${q(id)}/assign`, { analyst }),
  noteIncident: (id: string, text: string) => post<Incident>(`/api/incidents/${q(id)}/notes`, { text }),
  incidentStatus: (id: string, status: string) => post<Incident>(`/api/incidents/${q(id)}/status`, { status }),
  incidentAction: (id: string, action: string, reason = "incident response") =>
    post<Incident>(`/api/incidents/${q(id)}/actions`, { action, reason }),
  /** The incident as a PDF an auditor can read. */
  incidentReport: async (id: string) => {
    const res = await http.get<Blob>(`/api/incidents/${q(id)}/report`, { responseType: "blob" });
    const disposition = String(res.headers["content-disposition"] ?? "");
    return {
      blob: res.data,
      filename: /filename="([^"]+)"/.exec(disposition)?.[1] ?? `incident_${id}.pdf`,
    };
  },
  sessions: () => get<SessionRow[]>("/api/sessions"),
  revokeSession: (id: string) => post<{ revoked: string }>(`/api/sessions/${q(id)}/revoke`),
  accounts: () => get<AccountRow[]>("/api/accounts"),
  disableAccount: (u: string, reason: string) => post<{ disabled: string }>(`/api/accounts/${q(u)}/disable`, { reason }),
  enableAccount: (u: string) => post<{ enabled: string }>(`/api/accounts/${q(u)}/enable`),
  accessCheck: (user: string, resource: string) => post<AccessCheckResult>("/api/access/check", { user, resource }),
  dbStatus: () => get<DbStatus>("/api/db/status"),

  policy: () => get<Policy>("/api/policy"),

  // super admin
  policies: () => get<Policy>("/api/admin/policies"),
  updatePolicies: (body: Partial<Policy>) =>
    put<{ policy: Policy; changed: Record<string, { from: unknown; to: unknown }> }>("/api/admin/policies", body),
  adminRequests: () => get<AccessRequest[]>("/api/admin/access-requests"),
  adminDecide: (id: string, approve: boolean, note = "") =>
    post<AccessRequest>(`/api/admin/access-requests/${q(id)}/decide`, { approve, note }),
  roles: () =>
    get<{ roles: RoleRow[]; resource_min_level: Record<string, number>; overrides: Record<string, string> }>(
      "/api/admin/roles",
    ),
  updateRoles: (resource_min_level: Record<string, number>) =>
    put<{ changed: Record<string, { from: number; to: number }> }>("/api/admin/roles", { resource_min_level }),
  notifications: () => get<NotifyStatus>("/api/admin/notifications"),
  updateNotifications: (body: Record<string, unknown>) => put<NotifyStatus>("/api/admin/notifications", body),
  testNotification: () =>
    post<{ results: { channel: string; ok: boolean; detail: string }[] }>("/api/admin/notifications/test"),
  config: () => get<RuntimeConfig>("/api/admin/config"),
  updateConfig: (body: Partial<RuntimeConfig>) =>
    put<{ config: RuntimeConfig; changed: Record<string, unknown> }>("/api/admin/config", body),

  // auth
  login: (username: string, password: string, context: SignInContext = {}) =>
    post<LoginResult>("/api/auth/login", { username, password, ...context }),
  verifyMfa: (challenge_id: string, otp: string) =>
    post<StoredSession & { risk?: LoginRisk }>("/api/auth/mfa/verify", { challenge_id, otp }),
  logout: () => post<{ ok: boolean }>("/api/auth/logout"),
  me: () => get<{ kind: StoredSession["kind"]; profile: StoredSession["profile"] }>("/api/auth/me"),
  demoAccounts: () => get<DemoAccount[]>("/api/auth/demo-accounts"),

  // employee portal
  customers: (search = "", offset = 0, limit = 50) =>
    get<CustomerPage>(`/api/portal/customers?q=${q(search)}&offset=${offset}&limit=${limit}`),
  /** Returns the PDF and the filename the server chose. */
  exportPdf: async (body: { count?: number; customer_ids?: string[] }) => {
    try {
      const res = await http.post<Blob>("/api/portal/export", body, { responseType: "blob" });
      const disposition = String(res.headers["content-disposition"] ?? "");
      const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? "customers.pdf";
      return { blob: res.data, filename };
    } catch (e) {
      // Error bodies arrive as a Blob when responseType is blob.
      if (e instanceof AxiosError && e.response?.data instanceof Blob) {
        const text = await e.response.data.text();
        let detail = e.response.statusText;
        try {
          detail = JSON.parse(text).detail ?? detail;
        } catch {
          /* not JSON */
        }
        throw new ApiError(e.response.status, detail);
      }
      return toApiError(e);
    }
  },
  account: (accountNo: string) => get<AccountView>(`/api/portal/accounts/${q(accountNo)}`),
  transfers: () => get<Receipt[]>("/api/portal/transfers"),
  transfer: (body: { from_account: string; to_account: string; to_name: string; to_ifsc: string; amount: number; remarks: string }) =>
    post<TransferResult>("/api/portal/transfers", body),
  verifyTransfer: (challenge_id: string, code: string) =>
    post<TransferResult>("/api/portal/transfers/verify", { challenge_id, code }),
  myAccessRequests: () =>
    get<{ requestable: Record<string, string>; requests: AccessRequest[] }>("/api/portal/access-requests"),
  requestAccess: (resource: string, reason: string) => post<AccessRequest>("/api/portal/access-requests", { resource, reason }),
  myProfile: () => get<MyProfile>("/api/portal/me"),
  myActivity: () => get<{ ts: string; activity: string; resource: string }[]>("/api/portal/activity"),
  myResources: () => get<{ resource: string; min_level: number; in_role: boolean }[]>("/api/portal/resources"),
  openResource: (resource: string, otp?: string) =>
    post<{ decision: string; access?: string; monitoring?: string; reason?: string; demo_otp?: string }>(
      `/api/portal/resources/${q(resource)}/open`,
      otp ? { otp } : {},
    ),

  // privileged administrator (employee portal)
  adminUsers: () => get<AdminUserRow[]>("/api/portal/admin/users"),
  adminDisable: (u: string, reason: string) =>
    post<{ disabled: string; monitored: { risk: number; action: string } }>(`/api/portal/admin/users/${q(u)}/disable`, { reason }),
  adminEnable: (u: string) =>
    post<{ enabled: string; monitored: { risk: number; action: string } }>(`/api/portal/admin/users/${q(u)}/enable`),
  adminRole: (u: string, role: string) =>
    post<{ from: string; to: string; monitored: { risk: number; action: string } }>(`/api/portal/admin/users/${q(u)}/role`, { role }),
  adminCommsPolicy: () =>
    get<Pick<Policy, "customer_comms_roles" | "bulk_comms_roles" | "bulk_threshold" | "privileged_comms_step_up">>(
      "/api/portal/admin/comms-policy",
    ),
  adminPutCommsPolicy: (body: Partial<Pick<Policy, "customer_comms_roles" | "bulk_comms_roles" | "bulk_threshold">>) =>
    put<{ changed: Record<string, unknown>; monitored: { risk: number; action: string } }>("/api/portal/admin/comms-policy", body),

  // manager
  team: () => get<TeamOverview>("/api/team/overview"),
  teamRequests: () => get<AccessRequest[]>("/api/team/access-requests"),
  teamDecide: (id: string, approve: boolean, note = "") =>
    post<AccessRequest>(`/api/team/access-requests/${q(id)}/decide`, { approve, note }),

  // honeypot (SOC)
  honeypots: () => get<HoneypotListing>("/api/honeypots"),
  trace: (needle: string) => get<TraceResult>(`/api/honeypots/trace?q=${q(needle)}`),
  clearWatchlist: (actor: string, reviewer: string) =>
    post<{ cleared: string }>(`/api/honeypots/watchlist/${q(actor)}/clear`, { reviewer }),
};

/** WebSocket live feed; the token rides in the query string because browsers
 *  cannot set headers on a WebSocket upgrade. */
export function wsUrl(): string {
  const base = API_URL || window.location.origin;
  return `${base.replace(/^http/, "ws")}/api/ws?token=${q(token() ?? "")}`;
}
