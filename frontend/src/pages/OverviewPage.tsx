import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Flame,
  RefreshCw,
  ShieldCheck,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api/client";
import type { DashboardOverview } from "../types/soc";
import {
  AlertStatusBadge,
  SeverityBadge,
  formatUtc,
} from "../components/ui/Badges";

export function OverviewPage() {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [hours, setHours] = useState<number>(24);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load(selectedHours = hours) {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getOverview(selectedHours);
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load(hours);
  }, [hours]);

  if (loading && !data) {
    return (
      <div className="text-sm text-slate-400 animate-pulse">
        Loading SOC telemetry overview...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-xl bg-rose-500/10 border border-rose-500/30 p-4 text-sm text-rose-300">
        {error || "No telemetry available"}
      </div>
    );
  }

  const { kpis } = data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Security Operations Overview
          </h1>
          <p className="text-sm text-slate-400">
            Real-time normalized event ingestion, heuristic detection activity, and incident queue status.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {[6, 24, 72, 168].map((h) => (
            <button
              key={h}
              type="button"
              onClick={() => setHours(h)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium border transition-colors cursor-pointer ${
                hours === h
                  ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/40"
                  : "bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200"
              }`}
            >
              {h}h
            </button>
          ))}
          <button
            type="button"
            onClick={() => void load(hours)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-medium text-slate-200 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
        <KpiCard
          title="Total Events"
          value={kpis.total_events.toLocaleString()}
          sub={`${kpis.synthetic_events.toLocaleString()} synthetic`}
          icon={<Activity className="w-4 h-4 text-cyan-400" />}
        />
        <KpiCard
          title={`Events / Hour (${hours}h)`}
          value={String(kpis.events_per_hour)}
          sub={`${kpis.events_in_window.toLocaleString()} in window`}
          icon={<Zap className="w-4 h-4 text-sky-400" />}
        />
        <KpiCard
          title="Open Alerts"
          value={String(kpis.open_alerts)}
          sub={`${kpis.total_alerts} total alerts`}
          icon={<AlertTriangle className="w-4 h-4 text-amber-400" />}
        />
        <KpiCard
          title="Critical / High Open"
          value={String(kpis.critical_or_high_open_alerts)}
          sub="Requires immediate triage"
          highlight={kpis.critical_or_high_open_alerts > 0}
          icon={<AlertOctagon className="w-4 h-4 text-red-400" />}
        />
        <KpiCard
          title="Open Incidents"
          value={String(kpis.open_incidents)}
          sub="Active IR cases"
          icon={<Flame className="w-4 h-4 text-orange-400" />}
        />
        <KpiCard
          title="Active Rules"
          value={`${kpis.enabled_rules} / 7`}
          sub="Heuristic rules enabled"
          icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl bg-slate-900/70 border border-slate-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Ingestion &amp; Detection Activity Timeline
              </h2>
              <p className="text-xs text-slate-400">
                Normalized security events and triggered alerts over the selected window
              </p>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#334155",
                    fontSize: "12px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Events"
                  stroke="#22d3ee"
                  fill="#22d3ee"
                  fillOpacity={0.18}
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  name="Alerts"
                  stroke="#f97316"
                  fill="#f97316"
                  fillOpacity={0.25}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-5">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-white">
              Alert Severity Distribution
            </h2>
            <p className="text-xs text-slate-400">
              Breakdown of generated alerts by severity level
            </p>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.severity_distribution} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis
                  dataKey="severity"
                  type="category"
                  stroke="#94a3b8"
                  fontSize={11}
                  width={95}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#334155",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="count" name="Alerts" fill="#38bdf8" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Tables: Recent Alerts + Top Source IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl bg-slate-900/70 border border-slate-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white">
              Recent Security Alerts
            </h2>
            <Link
              to="/alerts"
              className="inline-flex items-center gap-1 text-xs font-medium text-cyan-400 hover:text-cyan-300"
            >
              <span>Open Alert Queue</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase">
                  <th className="py-2 pr-3">Ref</th>
                  <th className="py-2 pr-3">Severity</th>
                  <th className="py-2 pr-3">Alert Title</th>
                  <th className="py-2 pr-3">Source IP</th>
                  <th className="py-2 pr-3">MITRE</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.recent_alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 pr-3 font-mono text-cyan-300">
                      <Link to={`/alerts?selected=${alert.id}`} className="hover:underline">
                        {alert.reference}
                      </Link>
                    </td>
                    <td className="py-2.5 pr-3">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="py-2.5 pr-3 text-slate-100 font-medium">
                      {alert.title}
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-slate-300">
                      {alert.source_ip || "—"}
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-indigo-300">
                      {alert.mitre_technique_id || "—"}
                    </td>
                    <td className="py-2.5 pr-3">
                      <AlertStatusBadge status={alert.status} />
                    </td>
                    <td className="py-2.5 font-mono text-slate-400">
                      {formatUtc(alert.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white">
              Top Source IP Addresses
            </h2>
            <Link
              to="/hunting"
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300"
            >
              Entity Pivot →
            </Link>
          </div>
          <div className="space-y-2.5">
            {data.top_source_ips.map((row) => (
              <div
                key={row.source_ip}
                className="flex items-center justify-between rounded-lg bg-slate-950/70 border border-slate-800/80 px-3.5 py-2.5"
              >
                <div>
                  <Link
                    to={`/hunting?pivot_ip=${encodeURIComponent(row.source_ip)}`}
                    className="font-mono text-xs font-semibold text-cyan-300 hover:underline"
                  >
                    {row.source_ip}
                  </Link>
                  <div className="text-[11px] text-slate-400">
                    {row.failure_count} failed / blocked events
                  </div>
                </div>
                <span className="font-mono text-xs font-semibold px-2.5 py-1 rounded bg-slate-800 text-slate-200">
                  {row.event_count} events
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function KpiCard({
  title,
  value,
  sub,
  icon,
  highlight = false,
}: {
  title: string;
  value: string;
  sub: string;
  icon: React.ReactNode;
  highlight?: boolean;
}) {
  return (
    <div
      className={`rounded-xl p-4 border ${
        highlight
          ? "bg-red-500/10 border-red-500/40"
          : "bg-slate-900/70 border-slate-800"
      }`}
    >
      <div className="flex items-center justify-between text-xs font-medium text-slate-400 mb-2">
        <span>{title}</span>
        {icon}
      </div>
      <div className="text-2xl font-bold font-mono text-white">{value}</div>
      <div className="text-[11px] text-slate-400 mt-1">{sub}</div>
    </div>
  );
}
