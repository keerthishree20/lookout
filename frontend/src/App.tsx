import { Navigate, Route, Routes } from "react-router-dom";

import { SocLayout } from "./layouts/SocLayout";
import { loadSession } from "./lib/session";
import { EmployeePortal } from "./pages/EmployeePortal";
import { Login } from "./pages/Login";
import { AccessControl } from "./pages/soc/AccessControl";
import { Activity } from "./pages/soc/Activity";
import { Alerts } from "./pages/soc/Alerts";
import { AuditLogs } from "./pages/soc/AuditLogs";
import { Dashboard } from "./pages/soc/Dashboard";
import { Honeypot } from "./pages/soc/Honeypot";
import { Incidents } from "./pages/soc/Incidents";
import { MessageScanner } from "./pages/soc/MessageScanner";
import { Messages } from "./pages/soc/Messages";
import { MlInsights } from "./pages/soc/MlInsights";
import { PrivilegedAccess } from "./pages/soc/PrivilegedAccess";
import { Quarantine } from "./pages/soc/Quarantine";
import { SecurityPolicies } from "./pages/soc/SecurityPolicies";
import { Sessions } from "./pages/soc/Sessions";
import { Settings } from "./pages/soc/Settings";
import { Simulation } from "./pages/soc/Simulation";
import { UserDetail } from "./pages/soc/UserDetail";
import { Users } from "./pages/soc/Users";

function Home() {
  const s = loadSession();
  if (!s) return <Navigate to="/login" replace />;
  return <Navigate to={s.kind === "employee" ? "/employee" : "/dashboard"} replace />;
}

export function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/employee" element={<EmployeePortal />} />
      <Route path="/soc" element={<Navigate to="/dashboard" replace />} />
      <Route element={<SocLayout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/simulation" element={<Simulation />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="/users" element={<Users />} />
        <Route path="/users/:id" element={<UserDetail />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/messages" element={<Messages />} />
        <Route path="/message-scanner" element={<MessageScanner />} />
        <Route path="/quarantine" element={<Quarantine />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<Incidents />} />
        <Route path="/honeypot" element={<Honeypot />} />
        <Route path="/access-control" element={<AccessControl />} />
        <Route path="/privileged-access" element={<PrivilegedAccess />} />
        <Route path="/audit-logs" element={<AuditLogs />} />
        <Route path="/ml-insights" element={<MlInsights />} />
        <Route path="/security-policies" element={<SecurityPolicies />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Home />} />
    </Routes>
  );
}
