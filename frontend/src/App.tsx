import { Navigate, Route, Routes } from "react-router-dom";

import { ProtectedRoute, PublicOnlyRoute } from "./components/ProtectedRoute";
import { AppLayout } from "./layouts/AppLayout";
import { DashboardPage } from "./pages/DashboardPage";
import { DependenciesPage } from "./pages/DependenciesPage";
import { FragilityPage } from "./pages/FragilityPage";
import { GraphPage } from "./pages/GraphPage";
import { LoginPage } from "./pages/LoginPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { ReachabilityPage } from "./pages/ReachabilityPage";
import { RegisterPage } from "./pages/RegisterPage";
import { SbomPage } from "./pages/SbomPage";
import { SettingsPage } from "./pages/SettingsPage";
import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";

export default function App() {
  return (
    <Routes>
      <Route element={<PublicOnlyRoute />}>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
      </Route>

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/projects/:id" element={<ProjectDetailPage />} />
          <Route path="/projects/:id/dependencies" element={<DependenciesPage />} />
          <Route path="/projects/:id/graph" element={<GraphPage />} />
          <Route path="/projects/:id/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/projects/:id/reachability" element={<ReachabilityPage />} />
          <Route path="/projects/:id/fragility" element={<FragilityPage />} />
          <Route path="/projects/:id/sbom" element={<SbomPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Route>

      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
