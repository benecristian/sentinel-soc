import { useEffect, useState } from "react";
import { Play, Save } from "lucide-react";
import { api } from "../api/client";
import type { DetectionRule, Severity, User } from "../types/soc";
import { SeverityBadge } from "../components/ui/Badges";

export function SettingsPage({ user }: { user: User }) {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [sysInfo, setSysInfo] = useState<Record<string, unknown> | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user.role === "admin";

  async function load() {
    const [r, info] = await Promise.all([
      api.listRules(),
      api.getSystemInfo(),
    ]);
    setRules(r);
    setSysInfo(info);
  }

  useEffect(() => {
    void load();
  }, []);

  async function handleSaveRule(rule: DetectionRule) {
    setError(null);
    setStatusMsg(null);
    try {
      await api.updateRule(rule.id, {
        enabled: rule.enabled,
        severity: rule.severity,
        threshold: rule.threshold,
        time_window_seconds: rule.time_window_seconds,
      });
      setStatusMsg(`Saved configuration for ${rule.id}`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update rule");
    }
  }

  async function handleReRunDetections() {
    setError(null);
    setStatusMsg(null);
    try {
      const res = await api.runDetections(24);
      setStatusMsg(
        `Evaluated ${res.rules_evaluated} rules: ${res.alerts_created} created, ${res.alerts_updated} updated.`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Detection run failed");
    }
  }

  function updateLocalRule(id: string, patch: Partial<DetectionRule>) {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, ...patch } : r))
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Detection Rule Tuning &amp; Platform Settings
          </h1>
          <p className="text-sm text-slate-400">
            Configure heuristic thresholds, sliding time windows, and rule activation status. {!isAdmin && "(Admin role required to save changes.)"}
          </p>
        </div>

        <button
          type="button"
          onClick={() => void handleReRunDetections()}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs cursor-pointer"
        >
          <Play className="w-3.5 h-3.5" />
          <span>Re-evaluate Detections (Last 24h)</span>
        </button>
      </div>

      {statusMsg && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/30 p-3.5 text-xs text-emerald-300">
          {statusMsg}
        </div>
      )}
      {error && (
        <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 p-3.5 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Rule Cards */}
      <div className="space-y-4">
        {rules.map((r) => (
          <div
            key={r.id}
            className="rounded-xl bg-slate-900/70 border border-slate-800 p-5 space-y-4"
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="font-mono text-xs font-bold text-cyan-300">
                    {r.id}
                  </span>
                  <h2 className="text-sm font-bold text-white">{r.name}</h2>
                  <SeverityBadge severity={r.severity} />
                  <span className="font-mono text-[11px] text-slate-400">
                    v{r.version}
                  </span>
                </div>
                <p className="text-xs text-slate-400">{r.description}</p>
              </div>

              <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  disabled={!isAdmin}
                  checked={r.enabled}
                  onChange={(e) =>
                    updateLocalRule(r.id, { enabled: e.target.checked })
                  }
                />
                <span>{r.enabled ? "Enabled" : "Disabled"}</span>
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 items-end">
              <div>
                <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                  Severity
                </label>
                <select
                  disabled={!isAdmin}
                  value={r.severity}
                  onChange={(e) =>
                    updateLocalRule(r.id, {
                      severity: e.target.value as Severity,
                    })
                  }
                  className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs text-slate-100"
                >
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                  Threshold Count
                </label>
                <input
                  type="number"
                  min={1}
                  max={100000}
                  disabled={!isAdmin}
                  value={r.threshold}
                  onChange={(e) =>
                    updateLocalRule(r.id, {
                      threshold: Number(e.target.value),
                    })
                  }
                  className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-100"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                  Time Window (Seconds)
                </label>
                <input
                  type="number"
                  min={10}
                  max={86400}
                  disabled={!isAdmin}
                  value={r.time_window_seconds}
                  onChange={(e) =>
                    updateLocalRule(r.id, {
                      time_window_seconds: Number(e.target.value),
                    })
                  }
                  className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-100"
                />
              </div>

              <div>
                <button
                  type="button"
                  disabled={!isAdmin}
                  onClick={() => void handleSaveRule(r)}
                  className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-slate-700 text-xs font-semibold text-cyan-300 cursor-pointer"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>Save Rule</span>
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* System Information */}
      {sysInfo && (
        <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-5">
          <h2 className="text-sm font-bold text-white mb-2">
            System Configuration &amp; Ingestion Guardrails
          </h2>
          <pre className="rounded-lg bg-slate-950 border border-slate-800 p-3.5 text-xs font-mono text-slate-300 overflow-x-auto">
            {JSON.stringify(sysInfo, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
