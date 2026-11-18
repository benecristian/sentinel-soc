import { useEffect, useState, type FormEvent } from "react";
import { Upload, Search } from "lucide-react";
import { api } from "../api/client";
import type { IngestionBatch, SecurityEvent } from "../types/soc";
import {
  OutcomeBadge,
  SeverityBadge,
  SyntheticBadge,
  formatUtc,
} from "../components/ui/Badges";

export function EventExplorerPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [loading, setLoading] = useState(true);

  const [eventType, setEventType] = useState("");
  const [outcome, setOutcome] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [cidrFilter, setCidrFilter] = useState("");
  const [usernameFilter, setUsernameFilter] = useState("");
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Upload state
  const [uploadFormat, setUploadFormat] = useState("auto");
  const [lastBatch, setLastBatch] = useState<IngestionBatch | null>(null);

  async function loadEvents() {
    setLoading(true);
    setError(null);
    try {
      const page = await api.listEvents({
        event_type: eventType || undefined,
        event_outcome: outcome || undefined,
        ip: ipFilter.trim() || undefined,
        cidr: cidrFilter.trim() || undefined,
        username: usernameFilter.trim() || undefined,
        q: query.trim() || undefined,
        limit: 100,
      });
      setEvents(page.items);
      setTotal(page.total);
      if (page.items.length > 0 && !selected) {
        setSelected(page.items[0]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Query failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadEvents();
  }, [eventType, outcome]);

  function handleSearch(e: FormEvent) {
    e.preventDefault();
    void loadEvents();
  }

  async function handleFileUpload(file: File | undefined) {
    if (!file) return;
    setError(null);
    try {
      const batch = await api.uploadLogFile(file, uploadFormat);
      setLastBatch(batch);
      await loadEvents();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Normalized Security Event Explorer
          </h1>
          <p className="text-sm text-slate-400">
            Search normalized telemetry across authentication, firewall, DNS, HTTP, and process logs, or upload raw log files.
          </p>
        </div>

        {/* Log Upload Control */}
        <div className="flex items-center gap-2 rounded-xl bg-slate-900 border border-slate-800 p-2">
          <select
            aria-label="Log format"
            value={uploadFormat}
            onChange={(e) => setUploadFormat(e.target.value)}
            className="rounded-lg bg-slate-950 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="auto">Auto-detect format</option>
            <option value="linux_auth">Linux auth.log</option>
            <option value="web_access">Nginx/Apache Combined</option>
            <option value="iptables">iptables / UFW Firewall</option>
            <option value="bind_query">BIND 9 DNS Query</option>
            <option value="json">JSON / JSONL</option>
          </select>
          <label className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold cursor-pointer">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Log File</span>
            <input
              type="file"
              accept=".log,.txt,.json,.jsonl"
              className="hidden"
              onChange={(e) => void handleFileUpload(e.target.files?.[0])}
            />
          </label>
        </div>
      </div>

      {lastBatch && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/30 p-3.5 text-xs text-emerald-200 flex flex-wrap items-center justify-between gap-2">
          <div>
            Uploaded <b>{lastBatch.original_filename}</b> (parser:{" "}
            <code>{lastBatch.parser}</code>):{" "}
            <b>{lastBatch.accepted_count}</b> accepted,{" "}
            <b>{lastBatch.duplicate_count}</b> duplicates,{" "}
            <b>{lastBatch.rejected_count}</b> rejected →{" "}
            <b>{lastBatch.alerts_created}</b> new alert(s) triggered.
          </div>
          <button
            type="button"
            onClick={() => setLastBatch(null)}
            className="text-emerald-300 underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 p-3.5 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Search & Filter Form */}
      <form
        onSubmit={handleSearch}
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 rounded-xl bg-slate-900/70 border border-slate-800 p-4"
      >
        <select
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-slate-200"
        >
          <option value="">All Event Types</option>
          <option value="authentication">authentication</option>
          <option value="firewall">firewall</option>
          <option value="dns_query">dns_query</option>
          <option value="http_request">http_request</option>
          <option value="process_execution">process_execution</option>
          <option value="network_connection">network_connection</option>
        </select>

        <select
          value={outcome}
          onChange={(e) => setOutcome(e.target.value)}
          className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-slate-200"
        >
          <option value="">All Outcomes</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
        </select>

        <input
          type="text"
          placeholder="Exact IP (e.g. 203.0.113.45)"
          value={ipFilter}
          onChange={(e) => setIpFilter(e.target.value)}
          className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs font-mono text-slate-100"
        />

        <input
          type="text"
          placeholder="CIDR (e.g. 203.0.113.0/24)"
          value={cidrFilter}
          onChange={(e) => setCidrFilter(e.target.value)}
          className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs font-mono text-slate-100"
        />

        <input
          type="text"
          placeholder="Username (e.g. deploy)"
          value={usernameFilter}
          onChange={(e) => setUsernameFilter(e.target.value)}
          className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-slate-100"
        />

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Free-text search..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-slate-100"
          />
          <button
            type="submit"
            className="px-3.5 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-medium text-cyan-300 cursor-pointer"
          >
            <Search className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Event Table */}
        <div className="lg:col-span-7 rounded-xl bg-slate-900/70 border border-slate-800 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-slate-800 flex justify-between text-xs text-slate-400">
            <span>Matching Events ({total})</span>
            <span>Click any row to inspect raw &amp; normalized schema</span>
          </div>
          {loading ? (
            <div className="p-6 text-xs text-slate-400">Loading events...</div>
          ) : (
            <div className="max-h-[620px] overflow-y-auto divide-y divide-slate-800/70">
              {events.map((ev) => (
                <button
                  key={ev.id}
                  type="button"
                  onClick={() => setSelected(ev)}
                  className={`w-full text-left px-4 py-3 text-xs transition-colors cursor-pointer ${
                    selected?.id === ev.id
                      ? "bg-cyan-500/10 border-l-2 border-l-cyan-400"
                      : "hover:bg-slate-800/40"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-slate-400">
                        {formatUtc(ev.timestamp)}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 font-mono text-[11px] text-cyan-300">
                        {ev.event_type}
                      </span>
                      <OutcomeBadge outcome={ev.event_outcome} />
                      <SeverityBadge severity={ev.severity} />
                    </div>
                    {ev.is_synthetic && <SyntheticBadge />}
                  </div>
                  <div className="font-mono text-[11px] text-slate-300 flex flex-wrap gap-x-4">
                    <span>src: {ev.source_ip || "—"}</span>
                    <span>dst: {ev.destination_ip || "—"}:{ev.destination_port ?? "—"}</span>
                    <span>user: {ev.username || "—"}</span>
                    <span>host: {ev.hostname || "—"}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Raw vs Normalized Inspector */}
        <div className="lg:col-span-5 rounded-xl bg-slate-900/70 border border-slate-800 p-5 space-y-4">
          {!selected ? (
            <div className="text-xs text-slate-400">
              Select an event to inspect its raw and normalized representations.
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="text-xs font-mono text-cyan-400">
                    EVENT ID: {selected.id}
                  </div>
                  <div className="text-xs text-slate-400">
                    Parser: <code>{selected.log_source}</code> · Action:{" "}
                    <code>{selected.event_action}</code>
                  </div>
                </div>
                {selected.is_synthetic && <SyntheticBadge />}
              </div>

              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Raw Log Record (Text-Only Safe View)
                </h3>
                <pre className="rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs font-mono text-amber-200 whitespace-pre-wrap break-all">
                  {selected.raw_event}
                </pre>
              </div>

              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Normalized Event Document (ECS-style JSONB)
                </h3>
                <pre className="rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs font-mono text-cyan-200 overflow-x-auto max-h-96">
                  {JSON.stringify(selected.normalized_event, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
