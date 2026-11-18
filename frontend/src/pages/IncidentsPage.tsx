import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Download,
  FileJson,
  MessageSquarePlus,
  PlusCircle,
  Save,
} from "lucide-react";
import { api } from "../api/client";
import type {
  AlertSummary,
  IncidentDetail,
  IncidentStatus,
  IncidentSummary,
  Severity,
} from "../types/soc";
import {
  AlertStatusBadge,
  IncidentStatusBadge,
  SeverityBadge,
  formatUtc,
} from "../components/ui/Badges";

const IR_PHASES: IncidentStatus[] = [
  "open",
  "investigating",
  "containment",
  "eradication",
  "recovery",
  "closed",
];

export function IncidentsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(
    searchParams.get("selected")
  );
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);

  const [findings, setFindings] = useState("");
  const [resolution, setResolution] = useState("");
  const [noteBody, setNoteBody] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Create Incident Modal state
  const [showCreate, setShowCreate] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newSeverity, setNewSeverity] = useState<Severity>("high");
  const [availableAlerts, setAvailableAlerts] = useState<AlertSummary[]>([]);
  const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);

  async function loadIncidents() {
    setLoading(true);
    try {
      const page = await api.listIncidents({ limit: 50 });
      setIncidents(page.items);
      if (!selectedId && page.items.length > 0) {
        setSelectedId(page.items[0].id);
      }
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(id: string) {
    setError(null);
    const d = await api.getIncident(id);
    setDetail(d);
    setFindings(d.findings || "");
    setResolution(d.resolution_summary || "");
  }

  useEffect(() => {
    void loadIncidents();
  }, []);

  useEffect(() => {
    if (selectedId) {
      void loadDetail(selectedId);
      setSearchParams(
        (prev) => {
          prev.set("selected", selectedId);
          return prev;
        },
        { replace: true }
      );
    }
  }, [selectedId]);

  async function handlePhaseChange(phase: IncidentStatus) {
    if (!detail) return;
    setError(null);
    try {
      const updated = await api.updateIncident(detail.id, { status: phase });
      setDetail(updated);
      await loadIncidents();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transition not allowed");
    }
  }

  async function handleSaveFindings(e: FormEvent) {
    e.preventDefault();
    if (!detail) return;
    setError(null);
    try {
      const updated = await api.updateIncident(detail.id, {
        findings,
        resolution_summary: resolution,
      });
      setDetail(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save findings");
    }
  }

  async function handleAddNote(e: FormEvent) {
    e.preventDefault();
    if (!detail || !noteBody.trim()) return;
    setError(null);
    try {
      await api.addIncidentNote(detail.id, noteBody.trim());
      setNoteBody("");
      await loadDetail(detail.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add note");
    }
  }

  async function handleExportJson() {
    if (!detail) return;
    const report = await api.getIncidentReportJson(detail.id);
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-soc-${detail.reference}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function openCreateModal() {
    setShowCreate(true);
    const page = await api.listAlerts({ limit: 50 });
    setAvailableAlerts(page.items);
  }

  async function handleCreateIncident(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const created = await api.createIncident({
        title: newTitle,
        description: newDesc,
        severity: newSeverity,
        alert_ids: selectedAlerts,
      });
      setShowCreate(false);
      setNewTitle("");
      setNewDesc("");
      setSelectedAlerts([]);
      await loadIncidents();
      setSelectedId(created.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create incident");
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Incident Response &amp; Case Management
          </h1>
          <p className="text-sm text-slate-400">
            Group correlated alerts into incidents, track NIST SP 800-61 response phases, and export executive PDF/JSON reports.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void openCreateModal()}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs cursor-pointer"
        >
          <PlusCircle className="w-4 h-4" />
          <span>New Incident</span>
        </button>
      </div>

      {showCreate && (
        <form
          onSubmit={handleCreateIncident}
          className="rounded-xl bg-slate-900 border border-cyan-500/40 p-5 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white">
              Create Security Incident
            </h2>
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Cancel
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <input
              type="text"
              required
              placeholder="Incident title..."
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              className="md:col-span-2 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-white"
            />
            <select
              value={newSeverity}
              onChange={(e) => setNewSeverity(e.target.value as Severity)}
              className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-white"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <textarea
            rows={2}
            placeholder="Initial incident scope and hypothesis..."
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            className="w-full rounded-lg bg-slate-950 border border-slate-700 p-3 text-xs text-white"
          />
          <div>
            <div className="text-xs font-semibold text-slate-300 mb-1.5">
              Attach Alerts (Optional)
            </div>
            <div className="max-h-36 overflow-y-auto rounded-lg bg-slate-950 border border-slate-800 p-2 space-y-1">
              {availableAlerts.map((a) => (
                <label
                  key={a.id}
                  className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={selectedAlerts.includes(a.id)}
                    onChange={(e) =>
                      setSelectedAlerts((prev) =>
                        e.target.checked
                          ? [...prev, a.id]
                          : prev.filter((id) => id !== a.id)
                      )
                    }
                  />
                  <span className="font-mono text-cyan-300">{a.reference}</span>
                  <span>{a.title}</span>
                </label>
              ))}
            </div>
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs cursor-pointer"
          >
            Create Incident
          </button>
        </form>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Incident List */}
        <div className="lg:col-span-4 rounded-xl bg-slate-900/70 border border-slate-800 overflow-hidden">
          {loading ? (
            <div className="p-6 text-xs text-slate-400">Loading incidents...</div>
          ) : incidents.length === 0 ? (
            <div className="p-6 text-xs text-slate-400">No incidents created yet.</div>
          ) : (
            <div className="divide-y divide-slate-800">
              {incidents.map((inc) => (
                <button
                  key={inc.id}
                  type="button"
                  onClick={() => setSelectedId(inc.id)}
                  className={`w-full text-left p-4 transition-colors cursor-pointer ${
                    inc.id === selectedId
                      ? "bg-cyan-500/10 border-l-2 border-l-cyan-400"
                      : "hover:bg-slate-800/50"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="font-mono text-xs font-bold text-cyan-300">
                      {inc.reference}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={inc.severity} />
                      <IncidentStatusBadge status={inc.status} />
                    </div>
                  </div>
                  <div className="text-sm font-semibold text-white">
                    {inc.title}
                  </div>
                  <div className="mt-1.5 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>{inc.alert_count} linked alert(s)</span>
                    <span>{formatUtc(inc.created_at)}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Incident Detail */}
        <div className="lg:col-span-8 rounded-xl bg-slate-900/70 border border-slate-800 p-6 space-y-6">
          {!detail ? (
            <div className="text-sm text-slate-400">
              Select an incident to manage response workflow and generate reports.
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono text-sm font-bold text-cyan-300">
                      {detail.reference}
                    </span>
                    <SeverityBadge severity={detail.severity} />
                    <IncidentStatusBadge status={detail.status} />
                  </div>
                  <h2 className="text-lg font-bold text-white">{detail.title}</h2>
                  <p className="text-xs text-slate-300 mt-1">
                    {detail.description}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => void handleExportJson()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 cursor-pointer"
                  >
                    <FileJson className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Export JSON</span>
                  </button>
                  <a
                    href={api.getIncidentReportPdfUrl(detail.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download PDF Report</span>
                  </a>
                </div>
              </div>

              {error && (
                <div className="rounded-lg bg-rose-500/10 border border-rose-500/40 px-3.5 py-2 text-xs text-rose-300">
                  {error}
                </div>
              )}

              {/* NIST SP 800-61 IR Phase Stepper */}
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Incident Response Phase (NIST SP 800-61 Lifecycle)
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-6 gap-2">
                  {IR_PHASES.map((phase) => {
                    const active = detail.status === phase;
                    return (
                      <button
                        key={phase}
                        type="button"
                        onClick={() => void handlePhaseChange(phase)}
                        className={`py-2 px-2.5 rounded-lg text-xs font-semibold uppercase border transition-colors cursor-pointer ${
                          active
                            ? "bg-cyan-500/20 text-cyan-300 border-cyan-400"
                            : "bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200"
                        }`}
                      >
                        {phase}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Linked Alerts */}
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Correlated Alerts ({detail.alerts.length})
                </h3>
                <div className="space-y-2">
                  {detail.alerts.map((a) => (
                    <div
                      key={a.id}
                      className="flex items-center justify-between rounded-lg bg-slate-950 border border-slate-800 px-3.5 py-2.5 text-xs"
                    >
                      <div className="flex items-center gap-2.5">
                        <span className="font-mono font-bold text-cyan-300">
                          {a.reference}
                        </span>
                        <SeverityBadge severity={a.severity} />
                        <span className="text-slate-100 font-medium">
                          {a.title}
                        </span>
                      </div>
                      <AlertStatusBadge status={a.status} />
                    </div>
                  ))}
                </div>
              </div>

              {/* Findings & Resolution Editor */}
              <form onSubmit={handleSaveFindings} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold uppercase text-slate-400 mb-1.5">
                      Investigation Findings &amp; Root Cause
                    </label>
                    <textarea
                      rows={3}
                      value={findings}
                      onChange={(e) => setFindings(e.target.value)}
                      className="w-full rounded-lg bg-slate-950 border border-slate-700 p-2.5 text-xs text-slate-100"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase text-slate-400 mb-1.5">
                      Containment &amp; Resolution Summary
                    </label>
                    <textarea
                      rows={3}
                      value={resolution}
                      onChange={(e) => setResolution(e.target.value)}
                      className="w-full rounded-lg bg-slate-950 border border-slate-700 p-2.5 text-xs text-slate-100"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-xs font-medium text-slate-100 cursor-pointer"
                >
                  <Save className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Save Case Findings</span>
                </button>
              </form>

              {/* Recommended Actions & Timeline */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg bg-slate-950 border border-slate-800 p-4">
                  <h4 className="text-xs font-semibold uppercase text-emerald-400 mb-2">
                    Recommended Response Actions
                  </h4>
                  <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
                    {detail.recommended_actions.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>

                <div className="rounded-lg bg-slate-950 border border-slate-800 p-4">
                  <h4 className="text-xs font-semibold uppercase text-cyan-400 mb-2">
                    Incident Response Timeline
                  </h4>
                  <div className="max-h-48 overflow-y-auto space-y-2">
                    {detail.timeline.map((entry) => (
                      <div
                        key={entry.id}
                        className="border-l-2 border-cyan-500/40 pl-3 text-xs"
                      >
                        <div className="font-mono text-[10px] text-slate-400">
                          {formatUtc(entry.occurred_at)} · {entry.entry_type}
                        </div>
                        <div className="text-slate-200">{entry.summary}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Analyst Notes */}
              <div>
                <h3 className="text-xs font-semibold uppercase text-slate-400 mb-2">
                  Incident Notes ({detail.notes.length})
                </h3>
                <div className="space-y-2 mb-3">
                  {detail.notes.map((n) => (
                    <div
                      key={n.id}
                      className="rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs"
                    >
                      <div className="flex justify-between font-mono text-slate-400 mb-1">
                        <span className="text-cyan-300">
                          {n.author?.display_name || "Analyst"}
                        </span>
                        <span>{formatUtc(n.created_at)}</span>
                      </div>
                      <p className="text-slate-200">{n.body}</p>
                    </div>
                  ))}
                </div>
                <form onSubmit={handleAddNote} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Log incident response action or handoff note..."
                    value={noteBody}
                    onChange={(e) => setNoteBody(e.target.value)}
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
            </>
          )}
        </div>
      </div>
    </div>
  );
}
