import { useState, type FormEvent } from "react";
import { Lock, Shield, Terminal } from "lucide-react";
import { api } from "../api/client";
import type { User } from "../types/soc";

interface LoginPageProps {
  onAuthenticated: (user: User) => void;
}

export function LoginPage({ onAuthenticated }: LoginPageProps) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("SentinelAdmin!2026");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const user = await api.login(username, password);
      onAuthenticated(user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#060911] text-slate-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl p-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-11 h-11 rounded-xl bg-cyan-500/15 border border-cyan-400/40 flex items-center justify-center text-cyan-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wide text-white">
              SENTINEL SOC
            </h1>
            <p className="text-xs font-mono text-cyan-400">
              SECURITY OPERATIONS &amp; INCIDENT RESPONSE
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="username"
              className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5"
            >
              Analyst Username
            </label>
            <input
              id="username"
              type="text"
              required
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5"
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-400"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg bg-rose-500/10 border border-rose-500/40 px-3.5 py-2.5 text-xs text-rose-300"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold py-2.5 text-sm transition-colors cursor-pointer"
          >
            <Lock className="w-4 h-4" />
            <span>{loading ? "Authenticating..." : "Sign In to SOC Console"}</span>
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-slate-800 text-xs text-slate-400 space-y-2">
          <div className="flex items-center gap-1.5 font-mono text-slate-300">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Local Demo Accounts (Pre-seeded):</span>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => {
                setUsername("admin");
                setPassword("SentinelAdmin!2026");
              }}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs cursor-pointer"
            >
              admin (Admin)
            </button>
            <button
              type="button"
              onClick={() => {
                setUsername("analyst");
                setPassword("SentinelAdmin!2026");
              }}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs cursor-pointer"
            >
              analyst (SOC Analyst)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
