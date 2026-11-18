import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Crosshair,
  Database,
  Flame,
  Grid,
  LogOut,
  PlayCircle,
  Settings,
  Shield,
} from "lucide-react";
import type { User } from "../../types/soc";

interface AppShellProps {
  user: User;
  onLogout: () => void;
  children: ReactNode;
}

const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: Activity, end: true },
  { to: "/alerts", label: "Alerts Queue", icon: AlertTriangle, end: false },
  { to: "/incidents", label: "Incidents (IR)", icon: Flame, end: false },
  { to: "/events", label: "Event Explorer", icon: Database, end: false },
  { to: "/hunting", label: "Threat Hunting", icon: Crosshair, end: false },
  { to: "/mitre", label: "MITRE ATT&CK", icon: Grid, end: false },
  { to: "/simulations", label: "Simulation Center", icon: PlayCircle, end: false },
  { to: "/settings", label: "Rules & Settings", icon: Settings, end: false },
];

export function AppShell({ user, onLogout, children }: AppShellProps) {
  return (
    <div className="min-h-screen flex bg-[#060911] text-slate-100">
      {/* Left Navigation Sidebar */}
      <aside className="w-64 shrink-0 border-r border-slate-800/80 bg-slate-950/90 flex flex-col justify-between">
        <div>
          <div className="h-16 px-5 flex items-center gap-3 border-b border-slate-800/80">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-400/40 flex items-center justify-center text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold tracking-wider text-sm text-white">
                SENTINEL SOC
              </div>
              <div className="text-[11px] font-mono text-cyan-400/90">
                SIEM &amp; IR PLATFORM
              </div>
            </div>
          </div>

          <nav className="p-3 space-y-1" aria-label="Main Navigation">
            {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30"
                      : "text-slate-400 hover:text-slate-100 hover:bg-slate-900/80 border border-transparent"
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>
        </div>

        {/* User Footer */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-900/40">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="text-xs font-semibold text-slate-200 truncate">
                {user.display_name}
              </div>
              <div className="text-[11px] font-mono text-slate-400 uppercase">
                @{user.username} · {user.role}
              </div>
            </div>
            <button
              type="button"
              onClick={onLogout}
              title="Sign out"
              className="p-2 rounded-lg text-slate-400 hover:text-rose-300 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/30 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 px-6 border-b border-slate-800/80 bg-slate-950/60 backdrop-blur flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 rounded-full">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              DETECTION ENGINE ONLINE
            </span>
            <span className="text-xs text-slate-400 hidden md:inline">
              Isolated Local Environment · All simulated telemetry is labeled{" "}
              <code className="text-indigo-300">SYNTHETIC</code>
            </span>
          </div>
          <div className="text-xs font-mono text-slate-400">
            MITRE ATT&amp;CK® v16.1
          </div>
        </header>

        <main className="flex-1 p-6 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
