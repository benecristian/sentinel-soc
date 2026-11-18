import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { api } from "./api/client";
import { AppShell } from "./components/layout/AppShell";
import { AlertsPage } from "./pages/AlertsPage";
import { EventExplorerPage } from "./pages/EventExplorerPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { LoginPage } from "./pages/LoginPage";
import { MitrePage } from "./pages/MitrePage";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";
import { SimulationCenterPage } from "./pages/SimulationCenterPage";
import { ThreatHuntingPage } from "./pages/ThreatHuntingPage";
import type { User } from "./types/soc";

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);

  useEffect(() => {
    api
      .me()
      .then((u) => setUser(u))
      .catch(() => setUser(null))
      .finally(() => setCheckingSession(false));
  }, []);

  async function handleLogout() {
    try {
      await api.logout();
    } finally {
      setUser(null);
    }
  }

  if (checkingSession) {
    return (
      <div className="min-h-screen bg-[#060911] text-slate-400 flex items-center justify-center text-sm font-mono">
        INITIALIZING SENTINEL SOC CONSOLE...
      </div>
    );
  }

  if (!user) {
    return <LoginPage onAuthenticated={setUser} />;
  }

  return (
    <BrowserRouter>
      <AppShell user={user} onLogout={() => void handleLogout()}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/events" element={<EventExplorerPage />} />
          <Route path="/hunting" element={<ThreatHuntingPage />} />
          <Route path="/mitre" element={<MitrePage />} />
          <Route path="/simulations" element={<SimulationCenterPage />} />
          <Route path="/settings" element={<SettingsPage user={user} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}
