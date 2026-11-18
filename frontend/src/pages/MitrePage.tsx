import { useEffect, useState } from "react";
import { ExternalLink, ShieldCheck } from "lucide-react";
import { api } from "../api/client";
import type { MitreCoverageMatrix, MitreTechniqueItem } from "../types/soc";
import { SeverityBadge } from "../components/ui/Badges";

export function MitrePage() {
  const [matrix, setMatrix] = useState<MitreCoverageMatrix | null>(null);
  const [selected, setSelected] = useState<MitreTechniqueItem | null>(null);
  const [filter, setFilter] = useState<"all" | "implemented" | "documented">("all");

  useEffect(() => {
    void api.getMitreCoverage().then((res) => {
      setMatrix(res);
      const firstTech = res.tactics.flatMap((t) => t.techniques)[0];
      if (firstTech) setSelected(firstTech);
    });
  }, []);

  if (!matrix) {
    return (
      <div className="text-sm text-slate-400">
        Loading MITRE ATT&amp;CK® coverage matrix...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            MITRE ATT&amp;CK® Enterprise Coverage Matrix (v{matrix.attack_version})
          </h1>
          <p className="text-sm text-slate-400">
            Distinguishes active heuristic rule coverage (<b className="text-emerald-300">Implemented</b>) from techniques included as reference context (<b className="text-slate-300">Documented Only</b>).
          </p>
        </div>

        <div className="flex items-center gap-2">
          {(["all", "implemented", "documented"] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase border cursor-pointer ${
                filter === f
                  ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                  : "bg-slate-900 text-slate-400 border-slate-800"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Summary Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/30 p-4">
          <div className="text-xs font-semibold uppercase text-emerald-300">
            Implemented Detection Coverage
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {matrix.summary.implemented_count} Techniques
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Mapped to at least one enabled SENTINEL detection rule
          </div>
        </div>

        <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-4">
          <div className="text-xs font-semibold uppercase text-slate-400">
            Documented Reference Techniques
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {matrix.summary.documented_count} Techniques
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Catalogued for analyst context and future detection roadmap
          </div>
        </div>

        <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-4">
          <div className="text-xs font-semibold uppercase text-cyan-300">
            Total Catalogued Techniques
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {matrix.summary.total_techniques} Techniques
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {matrix.attribution}
          </div>
        </div>
      </div>

      {/* Selected Technique Inspector */}
      {selected && (
        <div className="rounded-xl bg-slate-900/90 border border-cyan-500/40 p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-sm font-bold text-cyan-300">
                {selected.id}
              </span>
              <h2 className="text-base font-bold text-white">{selected.name}</h2>
              <span
                className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${
                  selected.coverage === "implemented"
                    ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                    : "bg-slate-800 text-slate-300 border border-slate-700"
                }`}
              >
                {selected.coverage}
              </span>
            </div>
            <a
              href={selected.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs font-mono text-cyan-400 hover:underline"
            >
              <span>attack.mitre.org</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
          <p className="text-xs text-slate-300">{selected.description}</p>
          {selected.rules.length > 0 && (
            <div className="pt-2 flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold text-slate-400 flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                Mapped Rules:
              </span>
              {selected.rules.map((r) => (
                <span
                  key={r.id}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-xs"
                >
                  <span className="font-mono text-cyan-300">{r.id}</span>
                  <span className="text-slate-200">{r.name}</span>
                  <SeverityBadge severity={r.severity} />
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tactic Columns */}
      <div className="overflow-x-auto pb-4">
        <div className="grid grid-flow-col auto-cols-[230px] gap-3">
          {matrix.tactics.map((tactic) => {
            const visibleTechs = tactic.techniques.filter((t) =>
              filter === "all" ? true : t.coverage === filter
            );
            return (
              <div
                key={tactic.id}
                className="rounded-xl bg-slate-900/70 border border-slate-800 flex flex-col"
              >
                <div className="p-3 border-b border-slate-800 bg-slate-950/60">
                  <div className="font-mono text-[11px] text-cyan-400">
                    {tactic.id}
                  </div>
                  <div className="text-xs font-bold text-white">
                    {tactic.name}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    {tactic.implemented_count}/{tactic.total_count} implemented
                  </div>
                </div>
                <div className="p-2.5 space-y-2">
                  {visibleTechs.map((tech) => {
                    const isImpl = tech.coverage === "implemented";
                    return (
                      <button
                        key={tech.id}
                        type="button"
                        onClick={() => setSelected(tech)}
                        className={`w-full text-left p-2.5 rounded-lg border text-xs transition-colors cursor-pointer ${
                          isImpl
                            ? "bg-emerald-500/10 border-emerald-500/35 hover:border-emerald-400"
                            : "bg-slate-950/70 border-slate-800/90 hover:border-slate-700 text-slate-400"
                        }`}
                      >
                        <div className="flex items-center justify-between font-mono text-[11px]">
                          <span
                            className={
                              isImpl ? "text-emerald-300 font-bold" : "text-slate-400"
                            }
                          >
                            {tech.id}
                          </span>
                          {tech.alert_count > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300">
                              {tech.alert_count} alerts
                            </span>
                          )}
                        </div>
                        <div className="font-medium text-slate-100 mt-1 line-clamp-2">
                          {tech.name}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
