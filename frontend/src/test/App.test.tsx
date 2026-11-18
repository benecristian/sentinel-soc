import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "../components/layout/AppShell";
import {
  AlertStatusBadge,
  IncidentStatusBadge,
  SeverityBadge,
  SyntheticBadge,
  formatUtc,
} from "../components/ui/Badges";
import { LoginPage } from "../pages/LoginPage";

describe("SENTINEL SOC UI Badges & Formatting", () => {
  it("renders severity, alert status, incident status, and synthetic badges", () => {
    render(
      <div>
        <SeverityBadge severity="critical" />
        <AlertStatusBadge status="investigating" />
        <IncidentStatusBadge status="containment" />
        <SyntheticBadge />
      </div>
    );
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("investigating")).toBeInTheDocument();
    expect(screen.getByText("containment")).toBeInTheDocument();
    expect(screen.getByText("SYNTHETIC")).toBeInTheDocument();
  });

  it("formats ISO timestamps in UTC", () => {
    expect(formatUtc("2026-11-16T10:15:32Z")).toBe("2026-11-16 10:15:32 UTC");
    expect(formatUtc(null)).toBe("—");
  });
});

describe("LoginPage workflow", () => {
  it("submits credentials and invokes onAuthenticated callback", async () => {
    const mockUser = {
      id: "11111111-1111-1111-1111-111111111111",
      username: "admin",
      display_name: "Alice Admin",
      role: "admin" as const,
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify(mockUser), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    const onAuthenticated = vi.fn();
    render(<LoginPage onAuthenticated={onAuthenticated} />);

    const submitBtn = screen.getByRole("button", {
      name: /Sign In to SOC Console/i,
    });
    await userEvent.click(submitBtn);

    await waitFor(() => {
      expect(onAuthenticated).toHaveBeenCalledWith(mockUser);
    });

    fetchSpy.mockRestore();
  });
});

describe("AppShell Navigation", () => {
  it("renders all 8 SOC navigation sections and user profile", () => {
    render(
      <MemoryRouter>
        <AppShell
          user={{
            id: "1",
            username: "analyst",
            display_name: "Marcus Chen",
            role: "analyst",
          }}
          onLogout={() => {}}
        >
          <div>Dashboard Content</div>
        </AppShell>
      </MemoryRouter>
    );

    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("Alerts Queue")).toBeInTheDocument();
    expect(screen.getByText("Incidents (IR)")).toBeInTheDocument();
    expect(screen.getByText("Event Explorer")).toBeInTheDocument();
    expect(screen.getByText("Threat Hunting")).toBeInTheDocument();
    expect(screen.getByText("MITRE ATT&CK")).toBeInTheDocument();
    expect(screen.getByText("Simulation Center")).toBeInTheDocument();
    expect(screen.getByText("Rules & Settings")).toBeInTheDocument();
    expect(screen.getByText("Marcus Chen")).toBeInTheDocument();
  });
});
