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

export interface MessagePayload {
  channel: string;
  recipient_count: number;
  audience: string;
  subject: string;
  body: string;
  urls: string[];
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
  suspicious: boolean;
  findings: string[];
  impersonates: string | null;
}

export interface GatewayResult {
  delivered: boolean;
  held: boolean;
  requires_step_up: boolean;
  urls: UrlVerdict[];
  decision: Decision;
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
