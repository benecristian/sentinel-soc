export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type AlertStatus = "new" | "investigating" | "resolved" | "false_positive";
export type IncidentStatus =
  | "open"
  | "investigating"
  | "containment"
  | "eradication"
  | "recovery"
  | "closed";
export type EventType =
  | "authentication"
  | "network_connection"
  | "firewall"
  | "dns_query"
  | "http_request"
  | "process_execution";
export type EventOutcome = "success" | "failure" | "unknown";
export type UserRole = "viewer" | "analyst" | "admin";

export interface User {
  id: string;
  username: string;
  display_name: string;
  role: UserRole;
  is_active?: boolean;
  last_login_at?: string | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface DashboardOverview {
  kpis: {
    total_events: number;
    events_in_window: number;
    events_per_hour: number;
    synthetic_events: number;
    total_alerts: number;
    open_alerts: number;
    critical_or_high_open_alerts: number;
    open_incidents: number;
    enabled_rules: number;
  };
  timeline: Array<{
    hour: string;
    label: string;
    events: number;
    alerts: number;
  }>;
  severity_distribution: Array<{
    severity: Severity;
    count: number;
  }>;
  event_type_distribution: Array<{
    event_type: string;
    count: number;
  }>;
  top_source_ips: Array<{
    source_ip: string;
    event_count: number;
    failure_count: number;
  }>;
  recent_alerts: Array<{
    id: string;
    reference: string;
    rule_id: string;
    rule_name: string;
    severity: Severity;
    status: AlertStatus;
    title: string;
    source_ip: string | null;
    username: string | null;
    mitre_technique_id: string | null;
    event_count: number;
    created_at: string;
    last_seen: string;
  }>;
}

export interface InvestigationNote {
  id: string;
  alert_id: string | null;
  incident_id: string | null;
  author: User | null;
  body: string;
  created_at: string;
}

export interface AlertSummary {
  id: string;
  reference: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  status: AlertStatus;
  title: string;
  source_ip: string | null;
  username: string | null;
  hostname: string | null;
  mitre_technique_id: string | null;
  event_count: number;
  first_seen: string;
  last_seen: string;
  assigned_to: string | null;
  assignee: User | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

export interface AlertDetail extends AlertSummary {
  description: string;
  evidence: Record<string, unknown>;
  incident_id: string | null;
  investigation_steps: string[];
  remediation_steps: string[];
  notes: InvestigationNote[];
}

export interface TimelineEntry {
  id: string;
  occurred_at: string;
  entry_type: string;
  summary: string;
  details: Record<string, unknown>;
  actor_id: string | null;
}

export interface IncidentSummary {
  id: string;
  reference: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  lead_analyst_id: string | null;
  lead_analyst: User | null;
  alert_count: number;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  recommended_actions: string[];
  findings: string;
  resolution_summary: string;
  alerts: AlertSummary[];
  timeline: TimelineEntry[];
  notes: InvestigationNote[];
}

export interface SecurityEvent {
  id: string;
  ingestion_batch_id: string | null;
  timestamp: string;
  ingested_at: string;
  event_type: EventType;
  event_action: string | null;
  event_outcome: EventOutcome;
  severity: Severity;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  username: string | null;
  hostname: string | null;
  service: string | null;
  log_source: string;
  raw_event: string;
  normalized_event: Record<string, unknown>;
  is_synthetic: boolean;
}

export interface IngestionBatch {
  id: string;
  source_kind: "upload" | "api" | "simulation";
  original_filename: string | null;
  parser: string;
  received_count: number;
  accepted_count: number;
  rejected_count: number;
  duplicate_count: number;
  ignored_count: number;
  alerts_created: number;
  alerts_updated: number;
  events_start: string | null;
  events_end: string | null;
  error_samples: Array<Record<string, unknown>>;
  started_at: string;
  completed_at: string | null;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  enabled: boolean;
  threshold: number;
  time_window_seconds: number;
  parameters: Record<string, unknown>;
  investigation_steps: string[];
  remediation_steps: string[];
  version: number;
  updated_at: string;
  mitre_techniques: Array<{
    technique_id: string;
    technique_name: string;
    is_primary: boolean;
  }>;
}

export interface MitreTechniqueItem {
  id: string;
  name: string;
  description: string;
  parent_id: string | null;
  url: string;
  attack_version: string;
  coverage: "implemented" | "disabled" | "documented";
  alert_count: number;
  tactics: Array<{ id: string; name: string; shortname: string }>;
  rules: Array<{
    id: string;
    name: string;
    severity: Severity;
    enabled: boolean;
    is_primary: boolean;
  }>;
}

export interface MitreCoverageMatrix {
  attack_version: string;
  attribution: string;
  summary: {
    total_techniques: number;
    implemented_count: number;
    disabled_count: number;
    documented_count: number;
  };
  tactics: Array<{
    id: string;
    name: string;
    shortname: string;
    description: string;
    url: string;
    display_order: number;
    implemented_count: number;
    total_count: number;
    techniques: MitreTechniqueItem[];
  }>;
}

export interface SimulationScenario {
  id: string;
  name: string;
  category: string;
  description: string;
  expected_rules: string[];
  mitre_techniques: string[];
  default_seed: number;
}

export interface SimulationRun {
  id: string;
  scenario_id: string;
  status: "running" | "completed" | "failed";
  seed: number;
  parameters: Record<string, unknown>;
  events_generated: number;
  alerts_generated: number;
  error: string | null;
  started_at: string;
  completed_at: string | null;
}
