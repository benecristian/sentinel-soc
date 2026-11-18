import { useEffect, useState } from "react";
import { CheckCircle2, PlayCircle, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import type { SimulationRun, SimulationScenario } from "../types/soc";
import { SyntheticBadge, formatUtc } from "../components/ui/Badges";

export function SimulationCenterPage() {
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [lastRun, setLastRun] = useState<SimulationRun | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const res = await api.getSimulations();
    setScenarios(res.scenarios);
    setRuns(res.recent_runs);
  }

  useEffect(() => {
    void load();
  }, []);

  async function handleRun(scenarioId: string) {
    setRunningId(scenarioId);
    setError(null);
    try {
      const run = await api.runSimulation(scenarioId);
      setLastRun(run);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setRunningId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Synthetic Adversary &amp; Baseline Simulation Center
          </h1>
          <p className="text-sm text-slate-400">
            Safely generate synthetic security logs (RFC 5737 test IPs and <code>.test</code> domains) to exercise ingestion, normalization, and detection rules end-to-end.
          </p>
        </div>
        <SyntheticBadge />
      </div>

      {lastRun && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/30 p-4 text-xs text-emerald-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>
              Scenario <b>{lastRun.scenario_id}</b> completed (seed:{" "}
              <code>{lastRun.seed}</code>): generated{" "}
              <b>{lastRun.events_generated}</b> new synthetic events and{" "}
              <b>{lastRun.alerts_generated}</b> alert(s).
            </span>
          </div>
          <button
            type="button"
            onClick={() => setLastRun(null)}
            className="underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 p-4 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Scenario Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {scenarios.map((s) => {
          const isBenign = s.category === "benign";
          return (
            <div
              key={s.id}
              className="rounded-xl bg-slate-900/70 border border-slate-800 p-5 flex flex-col justify-between space-y-4"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase ${
                      isBenign
                        ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                        : "bg-orange-500/15 text-orange-300 border border-orange-500/30"
                    }`}
                  >
                    {s.category.replace("_", " ")}
                  </span>
                  <span className="font-mono text-[11px] text-slate-400">
                    seed: {s.default_seed}
                  </span>
                </div>
                <h2 className="text-sm font-bold text-white">{s.name}</h2>
                <p className="text-xs text-slate-400">{s.description}</p>
              </div>

              <div className="space-y-3">
                <div className="flex flex-wrap gap-1.5">
                  {s.expected_rules.length === 0 ? (
                    <span className="text-[11px] font-mono text-emerald-400">
                      Expected alerts: 0 (Benign check)
                    </span>
                  ) : (
                    s.expected_rules.map((r) => (
                      <span
                        key={r}
                        className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300"
                      >
                        {r}
                      </span>
                    ))
                  )}
                </div>

                <button
                  type="button"
                  disabled={runningId === s.id}
                  onClick={() => void handleRun(s.id)}
                  className="w-full flex items-center justify-center gap-1.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold text-xs transition-colors cursor-pointer"
                >
                  <PlayCircle className="w-4 h-4" />
                  <span>
                    {runningId === s.id ? "Running..." : "Execute Scenario"}
                  </span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Simulation Execution History */}
      <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-5">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold text-white">
            Simulation Execution History
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase">
                <th className="py-2 pr-3">Scenario ID</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Seed</th>
                <th className="py-2 pr-3">Events Ingested</th>
                <th className="py-2 pr-3">Alerts Triggered</th>
                <th className="py-2">Executed At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {runs.map((r) => (
                <tr key={r.id}>
                  <td className="py-2.5 pr-3 font-mono text-cyan-300">
                    {r.scenario_id}
                  </td>
                  <td className="py-2.5 pr-3 uppercase font-mono text-emerald-400">
                    {r.status}
                  </td>
                  <td className="py-2.5 pr-3 font-mono text-slate-300">
                    {r.seed}
                  </td>
                  <td className="py-2.5 pr-3 font-mono text-slate-200">
                    {r.events_generated}
                  </td>
                  <td className="py-2.5 pr-3 font-mono text-amber-300">
                    {r.alerts_generated}
                  </td>
                  <td className="py-2.5 font-mono text-slate-400">
                    {formatUtc(r.started_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
