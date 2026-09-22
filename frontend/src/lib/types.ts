// Mirrors backend/lookout/models.py. Keep the two in step.

export type Role =
  | "teller"
  | "officer"
  | "analyst"
  | "manager"
  | "dba"
  | "sysadmin"
  | "domain_admin";

export type Band = "low" | "medium" | "high" | "critical";

export type ActionTaken =
  | "allow"
  | "step_up"
  | "quarantine"
  | "block"
  | "block_and_alert";

export type ThreatClass =
  | "benign"
  | "negligent"
  | "malicious"
  | "compromised"
  | "privilege_abuse";

export interface Geo {
  city: string;
  country: string;
  lat: number;
  lon: number;
}

export interface Attachment {
  name: string;
  size_kb: number;
  content_type: string;
}

export interface MessagePayload {
  channel: string;
  recipient_count: number;
  audience: string;
  recipient?: string;
  subject: string;
  body: string;
  urls: string[];
  attachments?: Attachment[];
}

export interface LookoutEvent {
  event_id: string;
  ts: string;
  actor: string;
  actor_role: Role;
  action: string;
  resource: string;
  source_ip: string;
  device_id: string;
  geo: Geo;
  success: boolean;
  message: MessagePayload | null;
  meta: Record<string, unknown>;
  scenario: string | null;
}

export interface Signal {
  name: string;
  points: number;
  explanation: string;
  detail: Record<string, unknown>;
  indicates: ThreatClass[];
}

export interface RiskScore {
  total: number;
  band: Band;
  rule_points: number;
  model_points: number;
  privilege_multiplier: number;
  signals: Signal[];
}

export interface Decision {
  event: LookoutEvent;
  risk: RiskScore;
  action_taken: ActionTaken;
  threat_class: ThreatClass;
  narrative: string;
  audit_seq: number | null;
  quarantine_id: string | null;
  /** Set when a hard policy raised the response above what the score alone would do. */
  policy: string | null;
  /** Supervised classifier's advisory opinion on the whole session. */
  ml: MlOpinion | null;
}

export interface MlOpinion {
  classification: string;
  confidence: number;
  probabilities: Record<string, number>;
  session_events: number;
  features: Record<string, number>;
}

export interface Stats {
  history_events: number;
  identities: number;
  decisions: number;
  model_fitted: boolean;
  model_trained_on: number;
  mean_risk: number;
  quarantined: number;
  audit_entries: number;
  audit_checkpoints: number;
  by_action: Partial<Record<ActionTaken, number>>;
  by_threat_class: Partial<Record<ThreatClass, number>>;
  clock: string;
  traffic_paused: boolean;
  exports: number;
  honeypots_served: number;
  transfer_decoys: number;
  in_honeypot: number;
  open_alerts: number;
  open_incidents: number;
  active_sessions: number;
}

export interface Health {
  ok: boolean;
  model_fitted: boolean;
  narrator: "llm" | "template";
  signing: string;
}

export interface Scenario {
  key: string;
  title: string;
  /** The demo button, in the spec's words ("Simulate Impossible Travel"). */
  button: string;
  summary: string;
  covers: string[];
}

export interface ScenarioRun {
  scenario: Scenario;
  decisions: Decision[];
  peak: Decision;
}

export interface UrlVerdict {
  url: string;
  host: string;
  score: number;
  /** The same score on 0-100. */
  risk_score: number;
  suspicious: boolean;
  findings: string[];
  impersonates: string | null;
  features?: Record<string, number | boolean | string>;
}

export type MessageComponents = Record<
  "url" | "sender_behaviour" | "content" | "destination" | "privilege" | "volume",
  number
>;

export interface GatewayResult {
  delivered: boolean;
  held: boolean;
  requires_step_up: boolean;
  urls: UrlVerdict[];
  message_risk: { score: number; level: string; components: MessageComponents };
  decision: Decision;
}

export type MessageStatus = "DELIVERED" | "VERIFICATION_REQUIRED" | "QUARANTINED" | "BLOCKED";

export interface MessageRow {
  message_id: string;
  quarantine_id: string | null;
  sender: string;
  sender_role: string;
  recipient: string;
  recipient_count: number;
  channel: string;
  subject: string;
  body: string;
  attachments: Attachment[];
  timestamp: string;
  status: MessageStatus;
  risk_score: number;
  risk_level: string;
  reasons: string[];
  urls: UrlVerdict[];
  classification: string;
  components: MessageComponents;
}

export interface HeldMessage extends Decision {
  quarantine_id: string;
  review: { status: string; by?: string; incident_id?: string };
  message: MessageRow;
}

export interface CryptoLayer {
  protects: string;
  algorithm: string;
  family: string;
  note: string;
}

export interface Artefact {
  name: string;
  category: string;
  description: string;
  algorithm: string;
  plaintext_bytes: number;
  ciphertext_bytes: number;
  kem_ciphertext_bytes: number;
  sha256_prefix: string;
  sealed_at: string;
  last_check: string;
}

export interface LoginRisk {
  risk_score: number;
  risk_level: string;
  reason: string[];
  action: string;
}

export interface MfaChallenge {
  mfa_required: true;
  challenge_id: string;
  factor: string;
  demo_otp: string;
  risk: LoginRisk;
}

export interface RoleRow {
  role: string;
  privilege_level: number;
  privileged_administrator: boolean;
  members: string[];
  resources: string[];
  customer_messaging: boolean;
  bulk_messaging: boolean;
  transfer_limit: number | null;
}

export interface RuntimeConfig {
  live_traffic: boolean;
  traffic_interval: number;
  show_demo_accounts: boolean;
  allow_tamper_demo: boolean;
  login_mfa: boolean;
}

export interface MyProfile {
  username: string;
  email: string;
  role: string;
  privilege_level: number;
  privileged_administrator: boolean;
  city: string;
  device: string;
  working_hours: string;
  may_message_customers: boolean;
}

export interface AdminUserRow {
  username: string;
  role: string;
  roster_role: string;
  privilege_level: number;
  city: string;
  status: string;
}

export interface CryptoStatus {
  signing: {
    algorithm: string;
    standard: string;
    quantum_safe: boolean;
    public_key_bytes: number;
    public_key: string;
  };
  sealing: {
    algorithm: string;
    standard: string;
    quantum_safe: boolean;
    public_key_bytes: number;
  };
  fully_quantum_safe: boolean;
  layers?: CryptoLayer[];
}

export interface AuditEntry {
  seq: number;
  ts: string;
  kind: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

export interface Checkpoint {
  seq: number;
  head_hash: string;
  ts: string;
  algorithm: string;
  quantum_safe: boolean;
  signature: string;
}

export interface AuditListing {
  entries: AuditEntry[];
  checkpoints: Checkpoint[];
  total: number;
}

export interface Verification {
  ok: boolean;
  entries_checked: number;
  checkpoints_checked: number;
  broken_at: number | null;
  reason: string;
}

export interface SealResult {
  name: string;
  audit_seq: number;
  kem_ciphertext: string;
  nonce: string;
  ciphertext: string;
  algorithm: string;
  roundtrip_ok: boolean;
}

export interface RunningStat {
  n: number;
  mean: number;
  std: number;
}

export interface Identity {
  actor: string;
  role: Role;
  events: number;
  trained: boolean;
  usual_hours: number[];
  countries: string[];
  devices: string[];
  records_per_query: RunningStat;
  recipients_per_message: RunningStat;
  last_login: { ts: string | null; city: string };
  action_mix: Record<string, number>;
  peak_risk: number;
  decisions: number;
}

export interface DemoAccount {
  username: string;
  password: string;
  kind: "employee" | "soc" | "superadmin";
  role: string;
  city: string;
}

export interface MaskedCustomer {
  customer_id: string;
  name: string;
  account_no: string;
  product: string;
  city: string;
  phone: string;
  email: string;
  kyc: string;
}

export interface CustomerPage {
  total: number;
  rows: MaskedCustomer[];
  max_export: number;
}

export interface ExportRecord {
  doc_ref: string;
  actor: string;
  role: string;
  requested: number;
  decoy: boolean;
  reason: string;
  ts: string;
  risk_total: number;
  action_taken: ActionTaken;
  audit_seq: number | null;
  filename: string;
  canary_count: number;
  canaries?: string[];
}

export interface TransferDecoy {
  reference: string;
  utr: string;
  actor: string;
  role: string;
  ts: string;
  from_account: string;
  from_name: string;
  to_account: string;
  to_name: string;
  to_ifsc: string;
  external: boolean;
  amount: number;
  reason: string;
  risk_total: number;
  action_taken: ActionTaken;
  audit_seq: number | null;
  shown_balance_after: number;
  real_funds_moved: boolean;
}

export interface WatchEntry {
  actor: string;
  since: string;
  reason: string;
  activity: ({ ts: string; what: string } & Record<string, unknown>)[];
}

export interface HoneypotListing {
  threshold: number;
  watchlist: string[];
  watch: WatchEntry[];
  served: ExportRecord[];
  transfer_decoys: TransferDecoy[];
  exports: ExportRecord[];
}

export interface TraceResult {
  found: boolean;
  query: string;
  matched_by?: "doc_ref" | "canary_account" | "transaction_ref";
  kind?: "export" | "transfer";
  record?: ExportRecord | TransferDecoy;
}

export interface AccountView {
  customer_id: string;
  masked: string;
  name: string;
  product: string;
  city: string;
  balance: number;
}

export interface Receipt {
  reference: string;
  utr: string;
  ts: string;
  status: string;
  from_account: string;
  from_name: string;
  to_account: string;
  to_name: string;
  to_ifsc: string;
  amount: number;
  remarks: string;
  balance_after: number;
}

export type TransferResult =
  | { status: "SUCCESS"; receipt: Receipt }
  | { status: "VERIFICATION_REQUIRED"; challenge_id: string; sent_to: string; demo_code: string };

export interface Evaluation {
  overall: {
    true_positive: number;
    false_positive: number;
    true_negative: number;
    false_negative: number;
    precision: number;
    recall: number;
    f1: number;
    false_positive_rate: number;
  };
  benign_events: number;
  incident_events: number;
  classification: { correct: number; total: number; accuracy: number };
  per_scenario: Record<
    string,
    {
      events: number;
      detected: number;
      peak_score: number;
      strongest_action: ActionTaken;
      classified_as: ThreatClass;
    }
  >;
  worst_false_positives: {
    actor: string;
    action: string;
    score: number;
    taken: ActionTaken;
    signals: string;
  }[];
}

export interface ShapItem {
  feature: string;
  value: number;
  contribution: number;
}

export interface RiskExplanation {
  event_id: string;
  risk_score: number;
  risk_level: string;
  action: ActionTaken;
  classification: ThreatClass;
  reasons: string[];
  arithmetic: { rule_points: number; model_points: number; privilege_multiplier: number };
  ml_second_opinion:
    | { available: false }
    | { available: true; classification: string; confidence: number; probabilities: Record<string, number>; shap: ShapItem[] };
}

export interface ClassMetrics {
  precision: number;
  recall: number;
  f1: number;
  support: number;
  pr_auc: number;
}

export interface SplitMetrics {
  accuracy: number;
  macro_f1: number;
  roc_auc_ovr_macro: number;
  pr_auc_macro: number;
  threat_recall: number;
  normal_false_alarm_rate: number;
  per_class: Record<string, ClassMetrics>;
  confusion_matrix: { labels: string[]; rows_true_cols_pred: number[][] };
  n: number;
  held_out_users?: string[];
}

export interface MlMetrics {
  model: string;
  dataset: { rows: number; synthetic: boolean; class_counts: Record<string, number> };
  random_split_25pct: SplitMetrics;
  unseen_employees: SplitMetrics;
  feature_importance: [string, number][];
}

export interface DashboardStats {
  total_users: number;
  active_sessions: number;
  high_risk_users: number;
  critical_alerts: number;
  blocked_messages: number;
  quarantined_messages: number;
  privileged_accounts: number;
  threat_distribution: Record<string, number>;
  score_distribution: Record<string, number>;
  alerts_by_type: Record<string, number>;
  message_outcomes: Record<"delivered" | "verification" | "quarantined" | "blocked", number>;
  login_anomalies: number;
  privilege_escalation_attempts: number;
}

export interface RiskTrendBucket {
  start: string;
  count: number;
  flagged: number;
  mean: number;
  peak: number;
  login_anomalies: number;
  privilege_escalations: number;
  messages_held: number;
}

export type AlertStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";

export interface Alert {
  id: string;
  severity: "HIGH" | "CRITICAL";
  user: string;
  alert_type: string;
  event_id: string;
  event: string;
  risk_score: number;
  ts: string;
  description: string;
  reasons: string[];
  recommended_action: string;
  classification: string;
  status: AlertStatus;
  incident_id: string | null;
}

export interface Incident {
  id: string;
  title: string;
  threat_type: string;
  user: string;
  severity: string;
  risk_score: number;
  status: AlertStatus;
  assigned_to: string | null;
  created_at: string;
  resolved_at: string | null;
  alert_count: number;
}

export interface IncidentDetail extends Incident {
  alert_ids: string[];
  evidence: string[];
  ai_explanation: string;
  ml_opinion: Omit<MlOpinion, "features"> | null;
  actions_taken: { ts: string; by: string; action: string; detail?: string }[];
  notes: { ts: string; by: string; text: string }[];
  timeline: { ts: string; kind: string; text: string }[];
  alerts: Alert[];
  honeypot: WatchEntry | null;
}

export interface SessionRow {
  session_id: string;
  username: string;
  kind: string;
  role: string;
  expires: string;
}

export interface AccountRow {
  username: string;
  kind: string;
  role: string;
  privilege_level: number | null;
  disabled: boolean;
  disabled_by: string | null;
  disabled_reason: string | null;
  active_sessions: number;
}

export interface AccessCheckResult {
  user: string;
  role: string;
  resource: string;
  decision: "ALLOWED" | "MFA_REQUIRED" | "RESTRICTED" | "DENIED" | "BLOCK_AND_REVOKE";
  reason: string;
  current_risk: number;
  risk_band: Band;
  monitoring: "standard" | "enhanced";
}

export interface AccessRequest {
  id: string;
  user: string;
  role: string;
  resource: string;
  resource_name: string;
  reason: string;
  status: "PENDING" | "APPROVED" | "DENIED";
  approver: string;
  decided_by: string | null;
  note: string;
  created_at: string;
  decided_at: string | null;
}

export interface TeamOverview {
  manager: string;
  branch: string;
  members: {
    user: string;
    role: string;
    activities: number;
    flagged: number;
    peak_risk: number;
    last_activity: string | null;
    risk_trend: number[];
  }[];
}

export interface Policy {
  medium: number;
  high: number;
  critical: number;
  honeypot_export_threshold: number;
  transfer_limits: Record<string, number>;
  customer_comms_roles: string[];
  bulk_comms_roles: string[];
  bulk_threshold: number;
  privileged_comms_step_up: boolean;
}

export interface UserRisk {
  user: string;
  role: string;
  current_risk: number;
  peak_risk: number;
  classification: string;
  trend: { ts: string; risk: number; action: string }[];
  logins: { ts: string; city: string; device: string; ip: string; success: boolean; risk: number }[];
  devices: Record<string, number>;
  locations: Record<string, number>;
  resources: Record<string, number>;
  messages: number;
  message_activity: MessageRow[];
  sessions: {
    session_id: string;
    start: string;
    end: string;
    device: string;
    ip: string;
    city: string;
    events: number;
    peak_risk: number;
    ended: string;
  }[];
  daily_risk: { day: string; peak_risk: number }[];
  sudden_changes: { ts: string; from: number; to: number; event_id: string; action: string; why: string }[];
  alerts: Alert[];
}

export type DbStatus =
  | { enabled: false; reason: string }
  | {
      enabled: true;
      url: string;
      dialect: string;
      run_id: string;
      rows: Record<string, number>;
      audit_chain: { ok: boolean; rows: number; broken_at: number | null };
    };
