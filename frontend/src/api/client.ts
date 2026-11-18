import type {
  AlertDetail,
  AlertSummary,
  DashboardOverview,
  DetectionRule,
  IncidentDetail,
  IncidentSummary,
  IngestionBatch,
  InvestigationNote,
  MitreCoverageMatrix,
  Page,
  SecurityEvent,
  SimulationRun,
  SimulationScenario,
  User,
} from "../types/soc";

const API_BASE = "/api/v1";
const CSRF_HEADER = { "X-Requested-With": "SentinelSOC" };

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("X-Requested-With", CSRF_HEADER["X-Requested-With"]);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    let code = "http_error";
    let message = `Request failed (${response.status})`;
    try {
      const data = await response.json();
      if (data?.error) {
        code = data.error.code || code;
        message = data.error.message || message;
        if (Array.isArray(data.error.details) && data.error.details.length > 0) {
          const detailMsg = data.error.details
            .map((d: { loc?: string[]; msg?: string }) =>
              `${(d.loc || []).join(".")}: ${d.msg || ""}`
            )
            .join("; ");
          message = `${message} (${detailMsg})`;
        }
      }
    } catch {
      // ignore JSON parse error on non-JSON failure responses
    }
    throw new ApiError(response.status, code, message);
  }

  return (await response.json()) as T;
}

export const api = {
  // Auth & Users
  login: (username: string, password: string) =>
    request<User>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ message: string }>("/auth/logout", { method: "POST" }),
  me: () => request<User>("/auth/me"),
  listUsers: () => request<User[]>("/users"),

  // Dashboard
  getOverview: (hours = 24) =>
    request<DashboardOverview>(`/dashboard/overview?hours=${hours}`),

  // Alerts
  listAlerts: (params: Record<string, string | number | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, String(v));
    }
    const query = qs.toString();
    return request<Page<AlertSummary>>(`/alerts${query ? `?${query}` : ""}`);
  },
  getAlert: (alertId: string) => request<AlertDetail>(`/alerts/${alertId}`),
  updateAlert: (
    alertId: string,
    payload: { status?: string; assigned_to?: string | null; note?: string }
  ) =>
    request<AlertDetail>(`/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  getAlertEvents: (alertId: string) =>
    request<Page<SecurityEvent>>(`/alerts/${alertId}/events?limit=100`),
  addAlertNote: (alertId: string, body: string) =>
    request<InvestigationNote>(`/alerts/${alertId}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    }),

  // Incidents
  listIncidents: (params: Record<string, string | number | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, String(v));
    }
    const query = qs.toString();
    return request<Page<IncidentSummary>>(`/incidents${query ? `?${query}` : ""}`);
  },
  getIncident: (incidentId: string) =>
    request<IncidentDetail>(`/incidents/${incidentId}`),
  createIncident: (payload: {
    title: string;
    description: string;
    severity: string;
    alert_ids: string[];
    recommended_actions?: string[];
  }) =>
    request<IncidentDetail>("/incidents", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateIncident: (incidentId: string, payload: Record<string, unknown>) =>
    request<IncidentDetail>(`/incidents/${incidentId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  attachIncidentAlerts: (incidentId: string, alertIds: string[]) =>
    request<IncidentDetail>(`/incidents/${incidentId}/alerts`, {
      method: "POST",
      body: JSON.stringify({ alert_ids: alertIds }),
    }),
  detachIncidentAlert: (incidentId: string, alertId: string) =>
    request<IncidentDetail>(`/incidents/${incidentId}/alerts/${alertId}`, {
      method: "DELETE",
    }),
  addIncidentNote: (incidentId: string, body: string) =>
    request<InvestigationNote>(`/incidents/${incidentId}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    }),

  // Events & Ingestion
  listEvents: (params: Record<string, string | number | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, String(v));
    }
    const query = qs.toString();
    return request<Page<SecurityEvent>>(`/events${query ? `?${query}` : ""}`);
  },
  uploadLogFile: (file: File, format = "auto") => {
    const form = new FormData();
    form.append("file", file);
    form.append("format", format);
    return request<IngestionBatch>("/events/upload", {
      method: "POST",
      body: form,
    });
  },
  listIngestionBatches: () =>
    request<Page<IngestionBatch>>("/ingestion/batches?limit=15"),

  // Detections
  listRules: () => request<DetectionRule[]>("/detections/rules"),
  updateRule: (ruleId: string, payload: Record<string, unknown>) =>
    request<DetectionRule>(`/detections/rules/${ruleId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  runDetections: (hours = 24) =>
    request<{
      rules_evaluated: number;
      findings_count: number;
      alerts_created: number;
      alerts_updated: number;
    }>("/detections/run", {
      method: "POST",
      body: JSON.stringify({ hours }),
    }),

  // MITRE ATT&CK
  getMitreCoverage: () => request<MitreCoverageMatrix>("/mitre/coverage"),

  // Threat Hunting
  listHuntQueries: () =>
    request<{
      queries: Array<{
        id: string;
        name: string;
        hypothesis: string;
        mitre_techniques: string[];
      }>;
      allowed_json_fields: string[];
    }>("/hunting/queries"),
  runHuntQuery: (queryId: string) =>
    request<{
      query: { id: string; name: string; hypothesis: string; mitre_techniques: string[] };
      total_results: number;
      results: Array<Record<string, unknown>>;
    }>(`/hunting/queries/${queryId}/run`, { method: "POST" }),
  pivotIp: (ip: string) =>
    request<Record<string, unknown>>(`/hunting/entities/ip/${encodeURIComponent(ip)}`),
  pivotUser: (username: string) =>
    request<Record<string, unknown>>(
      `/hunting/entities/user/${encodeURIComponent(username)}`
    ),

  // Simulations
  getSimulations: () =>
    request<{
      scenarios: SimulationScenario[];
      recent_runs: SimulationRun[];
    }>("/simulations"),
  runSimulation: (scenarioId: string, seed?: number) =>
    request<SimulationRun>(`/simulations/${scenarioId}/run`, {
      method: "POST",
      body: JSON.stringify(seed ? { seed } : {}),
    }),

  // Reports & System
  getIncidentReportJson: (incidentId: string) =>
    request<Record<string, unknown>>(`/reports/incidents/${incidentId}`),
  getIncidentReportPdfUrl: (incidentId: string) =>
    `${API_BASE}/reports/incidents/${incidentId}/pdf`,
  getSystemInfo: () => request<Record<string, unknown>>("/system/info"),
};
