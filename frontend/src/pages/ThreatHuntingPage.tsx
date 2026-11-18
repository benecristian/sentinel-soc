import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { Crosshair, Play, Search, User as UserIcon } from "lucide-react";
import { api } from "../api/client";

interface HuntCatalogItem {
  id: string;
  name: string;
  hypothesis: string;
  mitre_techniques: string[];
}

export function ThreatHuntingPage() {
  const [searchParams] = useSearchParams();
  const [queries, setQueries] = useState<HuntCatalogItem[]>([]);
  const [activeHunt, setActiveHunt] = useState<HuntCatalogItem | null>(null);
  const [huntResults, setHuntResults] = useState<Array<Record<string, unknown>>>([]);
  const [huntLoading, setHuntLoading] = useState(false);

  const [ipInput, setIpInput] = useState(
    searchParams.get("pivot_ip") || "203.0.113.45"
  );
  const [userInput, setUserInput] = useState("intern01");
  const [pivotData, setPivotData] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api.listHuntQueries().then((res) => {
      setQueries(res.queries);
      if (res.queries.length > 0) {
        void runHunt(res.queries[0].id);
      }
    });
    const initialIp = searchParams.get("pivot_ip") || "203.0.113.45";
    void api.pivotIp(initialIp).then(setPivotData).catch(() => {});
  }, []);

  async function runHunt(queryId: string) {
    setHuntLoading(true);
    setError(null);
    try {
      const res = await api.runHuntQuery(queryId);
      setActiveHunt(res.query);
      setHuntResults(res.results);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Hunt execution failed");
    } finally {
      setHuntLoading(false);
    }
  }

  async function handleIpPivot(e: FormEvent) {
    e.preventDefault();
    if (!ipInput.trim()) return;
    setError(null);
    try {
      const res = await api.pivotIp(ipInput.trim());
      setPivotData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "IP pivot failed");
    }
  }

  async function handleUserPivot(e: FormEvent) {
    e.preventDefault();
    if (!userInput.trim()) return;
    setError(null);
    try {
      const res = await api.pivotUser(userInput.trim());
      setPivotData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "User pivot failed");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">
          Hypothesis-Driven Threat Hunting &amp; Entity Pivoting
        </h1>
        <p className="text-sm text-slate-400">
          Proactively hunt across normalized telemetry using parameterized queries and pivot on suspicious IP addresses or user accounts.
        </p>
      </div>

      {error && (
        <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 p-3.5 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Predefined Hunts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 space-y-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Predefined Hunt Hypotheses
          </h2>
          {queries.map((q) => {
            const active = activeHunt?.id === q.id;
            return (
              <div
                key={q.id}
                className={`rounded-xl border p-4 transition-colors ${
                  active
                    ? "bg-cyan-500/10 border-cyan-500/40"
                    : "bg-slate-900/70 border-slate-800"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="text-sm font-semibold text-white">
                    {q.name}
                  </div>
                  <button
                    type="button"
                    onClick={() => void runHunt(q.id)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold shrink-0 cursor-pointer"
                  >
                    <Play className="w-3 h-3" />
                    <span>Run</span>
                  </button>
                </div>
                <p className="text-xs text-slate-400 mt-1.5">{q.hypothesis}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {q.mitre_techniques.map((t) => (
                    <span
                      key={t}
                      className="px-2 py-0.5 rounded bg-indigo-500/15 border border-indigo-500/30 font-mono text-[11px] text-indigo-300"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {/* Hunt Results */}
        <div className="lg:col-span-7 rounded-xl bg-slate-900/70 border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-bold text-white">
                {activeHunt ? activeHunt.name : "Hunt Results"}
              </h2>
              <p className="text-xs text-slate-400">
                {huntLoading
                  ? "Executing hunt query..."
                  : `${huntResults.length} matching records`}
              </p>
            </div>
            <Crosshair className="w-4 h-4 text-cyan-400" />
          </div>

          {huntResults.length === 0 ? (
            <div className="text-xs text-slate-400 py-8 text-center">
              No matching records found for this hypothesis.
            </div>
          ) : (
            <div className="max-h-96 overflow-y-auto space-y-2">
              {huntResults.map((row, idx) => (
                <pre
                  key={idx}
                  className="rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs font-mono text-cyan-200 overflow-x-auto"
                >
                  {JSON.stringify(row, null, 2)}
                </pre>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Entity Pivot Analyzer */}
      <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-white">
              Entity Pivot Analyzer (IP Address or Username)
            </h2>
            <p className="text-xs text-slate-400">
              Correlate all events, targeted ports, executed commands, and alerts for a single indicator.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <form onSubmit={handleIpPivot} className="flex gap-2">
              <input
                type="text"
                placeholder="IP (e.g. 203.0.113.45)"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-white"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-medium text-cyan-300 cursor-pointer"
              >
                <Search className="w-3.5 h-3.5" />
                <span>Pivot IP</span>
              </button>
            </form>

            <form onSubmit={handleUserPivot} className="flex gap-2">
              <input
                type="text"
                placeholder="Username (e.g. intern01)"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                className="rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-white"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 border border-indigo-500/40 text-xs font-medium text-indigo-300 cursor-pointer"
              >
                <UserIcon className="w-3.5 h-3.5" />
                <span>Pivot User</span>
              </button>
            </form>
          </div>
        </div>

        {pivotData && (
          <pre className="rounded-lg bg-slate-950 border border-slate-800 p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-96">
            {JSON.stringify(pivotData, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
