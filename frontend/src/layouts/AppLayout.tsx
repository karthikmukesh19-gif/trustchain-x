import { useEffect, useState } from "react";
import { FiFolder, FiGrid, FiLogOut, FiSettings } from "react-icons/fi";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { Brand } from "../components/Brand";
import { useAuth } from "../context/AuthContext";
import { getReadiness } from "../services/health";
import type { Readiness } from "../utils/types";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: FiGrid },
  { to: "/projects", label: "Projects", icon: FiFolder },
  { to: "/settings", label: "Settings", icon: FiSettings },
];

const HEALTH_POLL_MS = 30_000;

function SystemStatus() {
  const [state, setState] = useState<Readiness["status"] | "unknown">("unknown");

  useEffect(() => {
    let cancelled = false;
    const check = () => {
      getReadiness()
        .then((result) => {
          if (!cancelled) setState(result.status);
        })
        .catch(() => {
          if (!cancelled) setState("unavailable");
        });
    };
    check();
    const timer = window.setInterval(check, HEALTH_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const view = {
    ok: { dot: "bg-signal", text: "All services running" },
    degraded: { dot: "bg-amber-400", text: "Background worker offline" },
    unavailable: { dot: "bg-red-400", text: "Backend unavailable" },
    unknown: { dot: "bg-white/30", text: "Checking services" },
  }[state];

  return (
    <NavLink to="/settings" className="flex items-center gap-2 text-xs text-white/60 hover:text-white">
      <span className={`h-2 w-2 shrink-0 rounded-full ${view.dot}`} aria-hidden />
      {view.text}
    </NavLink>
  );
}

export function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  // Go to the login page directly so a deliberate sign-out does not carry a
  // "return to where you were" target into the next session.
  function signOut() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="min-h-screen md:grid md:grid-cols-[232px_minmax(0,1fr)]">
      <aside className="flex flex-col bg-ink text-white md:sticky md:top-0 md:h-screen">
        <div className="flex items-center justify-between px-5 py-4 md:py-5">
          <Brand />
        </div>

        <nav className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-1 md:flex-col md:overflow-visible md:pb-0" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-2.5 whitespace-nowrap rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive ? "bg-white/10 text-white" : "text-white/60 hover:bg-white/5 hover:text-white"
                }`
              }
            >
              <Icon aria-hidden className="shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="hidden space-y-3 border-t border-white/10 px-5 py-4 md:block">
          <SystemStatus />
          <div className="min-w-0">
            <div className="truncate text-sm font-medium">{user?.full_name}</div>
            <div className="truncate font-mono text-xs text-white/50">{user?.email}</div>
          </div>
          <button
            type="button"
            onClick={signOut}
            className="flex items-center gap-2 text-sm text-white/60 hover:text-white"
          >
            <FiLogOut aria-hidden /> Sign out
          </button>
        </div>
      </aside>

      <div className="min-w-0">
        <div className="flex items-center justify-between border-b border-line bg-surface px-4 py-2 text-sm md:hidden">
          <span className="truncate text-muted">{user?.email}</span>
          <button type="button" onClick={signOut} className="flex items-center gap-1.5 font-medium">
            <FiLogOut aria-hidden /> Sign out
          </button>
        </div>
        <main className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-8 sm:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
