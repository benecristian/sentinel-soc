import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  CheckCircle2,
  Flame,
  MessageSquarePlus,
  Search,
  UserCheck,
} from "lucide-react";
import { api } from "../api/client";
import type {
  AlertDetail,
  AlertStatus,
  AlertSummary,
  SecurityEvent,
  Severity,
  User,
} from "../types/soc";
import {
  AlertStatusBadge,
  OutcomeBadge,
  SeverityBadge,
  SyntheticBadge,
  formatUtc,
} from "../components/ui/Badges";

export function AlertsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>(
    searchParams.get("status") || ""
  );
  const [severityFilter, setSeverityFilter] = useState<string>(
    searchParams.get("severity") || ""
  );
  const [query, setQuery] = useState<string>(searchParams.get("q") || "");
  const [loading, setLoading] = useState(true);

  const [selectedId, setSelectedId] = useState<string | null>(
    searchParams.get("selected")
  );
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [relatedEvents, setRelatedEvents] = useState<SecurityEvent[]>([]);
  const [users, setUsers] = useState<User[]>([]);

  const [noteInput, setNoteInput] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionStatus, setActionStatus] = useState<string | null>(null);

  async function loadAlerts() {
    setLoading(true);
    try {
      const page = await api.listAlerts({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        q: query || undefined,
        limit: 100,
      });
      setAlerts(page.items);
      setTotal(page.total);
      if (!selectedId && page.items.length > 0) {
        setSelectedId(page.items[0].id);
      }
    } finally {
      setLoading(false);
    }
  }

  async function loadAlertDetail(id: string) {
    setActionError(null);
    const [d, evPage] = await Promise.all([
      api.getAlert(id),
      api.getAlertEvents(id),
    ]);
    setDetail(d);
    setRelatedEvents(evPage.items);
  }

  useEffect(() => {
    void api.listUsers().then(setUsers).catch(() => {});
  }, []);

  useEffect(() => {
    void loadAlerts();
  }, [statusFilter, severityFilter]);

  useEffect(() => {
    if (selectedId) {
      void loadAlertDetail(selectedId);
      setSearchParams(
        (prev) => {
          prev.set("selected", selectedId);
          return prev;
        },
        { replace: true }
      );
    }
  }, [selectedId]);

  async function handleStatusChange(newStatus: AlertStatus) {
    if (!detail) return;
    setActionError(null);
    setActionStatus(null);
    try {
      const updated = await api.updateAlert(detail.id, {
        status: newStatus,
        note: noteInput.trim() || undefined,
      });
      setDetail(updated);
      setNoteInput("");
      setActionStatus(`Alert transitioned to ${newStatus}`);
      await loadAlerts();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Update failed");
    }
  }

  async function handleAssign(userId: string) {
    if (!detail) return;
    setActionError(null);
    try {
      const updated = await api.updateAlert(detail.id, {
        assigned_to: userId || null,
      });
      setDetail(updated);
      await loadAlerts();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Assignment failed");
    }
  }

  async function handleAddNote(e: FormEvent) {
    e.preventDefault();
    if (!detail || !noteInput.trim()) return;
    setActionError(null);
    try {
      await api.addAlertNote(detail.id, noteInput.trim());
      setNoteInput("");
      await loadAlertDetail(detail.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Failed to add note");
    }
  }

  async function handleEscalateToIncident() {
    if (!detail) return;
    setActionError(null);
    try {
      const inc = await api.createIncident({
        title: `Incident from ${detail.reference}: ${detail.title}`,
        description: detail.description,
        severity: detail.severity as Severity,
        alert_ids: [detail.id],
        recommended_actions: detail.remediation_steps,
      });
      navigate(`/incidents?selected=${inc.id}`);
    } catch (err) {
      setActionError(
        err instanceof Error ? err.message : "Failed to create incident"
      );
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Security Alerts &amp; Triage Queue
          </h1>
          <p className="text-sm text-slate-400">
            Investigate rule findings, inspect supporting log evidence, record triage notes, or escalate to an incident.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400">
          Showing {alerts.length} of {total} alerts
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl bg-slate-900/70 border border-slate-800 p-3.5">
        <select
          aria-label="Filter by status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-slate-200"
        >
          <option value="">All Statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>

        <select
          aria-label="Filter by severity"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-slate-200"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void loadAlerts();
          }}
          className="flex-1 min-w-[220px] flex gap-2"
        >
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search reference, title, rule, description..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-700 pl-8 pr-3 py-1.5 text-xs text-slate-100"
            />
          </div>
          <button
            type="submit"
            className="px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-medium text-cyan-300 cursor-pointer"
          >
            Search
          </button>
        </form>
      </div>

      {/* Master-Detail Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Alert Table */}
        <div className="lg:col-span-5 rounded-xl bg-slate-900/70 border border-slate-800 overflow-hidden">
          {loading ? (
            <div className="p-6 text-xs text-slate-400">Loading alerts...</div>
          ) : alerts.length === 0 ? (
            <div className="p-6 text-xs text-slate-400">
              No alerts match the current filters.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80 max-h-[750px] overflow-y-auto">
              {alerts.map((a) => {
                const active = a.id === selectedId;
                return (
                  <button
                    key={a.id}
                    type="button"
                    onClick={() => setSelectedId(a.id)}
                    className={`w-full text-left p-4 transition-colors cursor-pointer ${
                      active
                        ? "bg-cyan-500/10 border-l-2 border-l-cyan-400"
                        : "hover:bg-slate-800/50"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-cyan-300">
                          {a.reference}
                        </span>
                        <SeverityBadge severity={a.severity} />
                        <AlertStatusBadge status={a.status} />
                      </div>
                      <span className="font-mono text-[11px] text-indigo-300">
                        {a.mitre_technique_id || a.rule_id}
                      </span>
                    </div>
                    <div className="text-sm font-semibold text-white line-clamp-1">
                      {a.title}
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>
                        src: {a.source_ip || "—"} · {a.event_count} events
                      </span>
                      <span>{formatUtc(a.last_seen)}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: Alert Detail Workbench */}
        <div className="lg:col-span-7 rounded-xl bg-slate-900/70 border border-slate-800 p-6 space-y-6">
          {!detail ? (
            <div className="text-sm text-slate-400">
              Select an alert from the queue to inspect evidence and triage.
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2.5 mb-2">
                    <span className="font-mono text-sm font-bold text-cyan-300">
                      {detail.reference}
                    </span>
                    <SeverityBadge severity={detail.severity} />
                    <AlertStatusBadge status={detail.status} />
                    <span className="px-2 py-0.5 rounded bg-slate-800 font-mono text-xs text-slate-300">
                      {detail.rule_id}
                    </span>
                    {detail.mitre_technique_id && (
                      <span className="px-2 py-0.5 rounded bg-indigo-500/15 border border-indigo-500/30 font-mono text-xs text-indigo-300">
                        MITRE {detail.mitre_technique_id}
                      </span>
                    )}
                  </div>
                  <h2 className="text-lg font-bold text-white">{detail.title}</h2>
                  <p className="text-xs text-slate-300 mt-1">
                    {detail.description}
                  </p>
                </div>

                {detail.incident_id ? (
                  <button
                    type="button"
                    onClick={() =>
                      navigate(`/incidents?selected=${detail.incident_id}`)
                    }
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/20 border border-orange-500/40 text-xs font-semibold text-orange-300 cursor-pointer"
                  >
                    <Flame className="w-3.5 h-3.5" />
                    <span>View Linked Incident</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={handleEscalateToIncident}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-400 text-slate-950 text-xs font-semibold cursor-pointer"
                  >
                    <Flame className="w-3.5 h-3.5" />
                    <span>Escalate to Incident</span>
                  </button>
                )}
              </div>

              {actionError && (
                <div className="rounded-lg bg-rose-500/10 border border-rose-500/40 px-3.5 py-2 text-xs text-rose-300">
                  {actionError}
                </div>
              )}
              {actionStatus && (
                <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/40 px-3.5 py-2 text-xs text-emerald-300 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{actionStatus}</span>
                </div>
              )}

              {/* Triage & Assignment Controls */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 rounded-xl bg-slate-950/70 border border-slate-800 p-4">
                <div>
                  <div className="text-xs font-semibold uppercase text-slate-400 mb-2">
                    Status Workflow Transitions
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {detail.status === "new" && (
                      <button
                        type="button"
                        onClick={() => void handleStatusChange("investigating")}
                        className="px-3 py-1.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-xs font-medium text-purple-200 cursor-pointer"
                      >
                        Start Investigation
                      </button>
                    )}
                    {(detail.status === "new" ||
                      detail.status === "investigating") && (
                      <>
                        <button
                          type="button"
                          onClick={() => void handleStatusChange("resolved")}
                          className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-xs font-medium text-emerald-200 cursor-pointer"
                        >
                          Mark Resolved
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            void handleStatusChange("false_positive")
                          }
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-xs font-medium text-slate-200 cursor-pointer"
                        >
                          False Positive
                        </button>
                      </>
                    )}
                    {(detail.status === "resolved" ||
                      detail.status === "false_positive") && (
                      <button
                        type="button"
                        onClick={() => void handleStatusChange("investigating")}
                        className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-xs font-medium text-amber-200 cursor-pointer"
                      >
                        Re-open Alert
                      </button>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1.5">
                    Note: Closing as Resolved or False Positive requires at least one investigation note.
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-400 mb-2">
                    <UserCheck className="w-3.5 h-3.5 inline mr-1" />
                    Assigned Analyst
                  </label>
                  <select
                    value={detail.assigned_to || ""}
                    onChange={(e) => void handleAssign(e.target.value)}
                    className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-1.5 text-xs text-slate-200"
                  >
                    <option value="">Unassigned</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.display_name} (@{u.username})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Structured Evidence */}
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Structured Detection Evidence
                </h3>
                <pre className="rounded-lg bg-slate-950 border border-slate-800 p-3.5 text-xs font-mono text-cyan-200 overflow-x-auto">
                  {JSON.stringify(detail.evidence, null, 2)}
                </pre>
              </div>

              {/* Playbook Guidance */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3.5">
                  <h4 className="text-xs font-semibold uppercase text-cyan-400 mb-2">
                    Recommended Investigation Steps
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
                    {detail.investigation_steps.map((s, idx) => (
                      <li key={idx}>{s}</li>
                    ))}
                  </ul>
                </div>
                <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3.5">
                  <h4 className="text-xs font-semibold uppercase text-emerald-400 mb-2">
                    Recommended Remediation
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
                    {detail.remediation_steps.map((s, idx) => (
                      <li key={idx}>{s}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Investigation Notes */}
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Analyst Investigation Notes ({detail.notes.length})
                </h3>
                <div className="space-y-2 mb-3">
                  {detail.notes.map((n) => (
                    <div
                      key={n.id}
                      className="rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs"
                    >
                      <div className="flex items-center justify-between text-slate-400 font-mono mb-1">
                        <span className="text-cyan-300">
                          {n.author ? n.author.display_name : "Analyst"}
                        </span>
                        <span>{formatUtc(n.created_at)}</span>
                      </div>
                      <p className="text-slate-200 whitespace-pre-wrap">
                        {n.body}
                      </p>
                    </div>
                  ))}
                </div>
                <form onSubmit={handleAddNote} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Add triage finding or closure rationale..."
                    value={noteInput}
                    onChange={(e) => setNoteInput(e.target.value)}
                    className="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-slate-100"
                  />
                  <button
                    type="submit"
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold cursor-pointer"
                  >
                    <MessageSquarePlus className="w-3.5 h-3.5" />
                    <span>Add Note</span>
                  </button>
                </form>
              </div>

              {/* Supporting Events */}
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Correlated Evidence Events ({relatedEvents.length})
                </h3>
                <div className="max-h-60 overflow-y-auto rounded-lg border border-slate-800 divide-y divide-slate-800 bg-slate-950">
                  {relatedEvents.map((ev) => (
                    <div key={ev.id} className="p-2.5 text-xs space-y-1">
                      <div className="flex items-center justify-between font-mono text-[11px] text-slate-400">
                        <div className="flex items-center gap-2">
                          <span>{formatUtc(ev.timestamp)}</span>
                          <OutcomeBadge outcome={ev.event_outcome} />
                          {ev.is_synthetic && <SyntheticBadge />}
                        </div>
                        <span>
                          {ev.source_ip || "—"} → {ev.destination_ip || ev.hostname || "—"}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-200 break-all">
                        {ev.raw_event}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
