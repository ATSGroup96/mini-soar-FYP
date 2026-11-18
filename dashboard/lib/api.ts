// Calls to the FastAPI gateway for ACTIONS (scans, what-if, approvals, reports).
// "auto" (or empty) = the API runs on the same machine as the dashboard, port 8000.
// Then nothing needs rebuilding when the engine gets a new IP on a new network.
const ENV_API = process.env.NEXT_PUBLIC_API_URL || "auto";
const API =
  ENV_API !== "auto"
    ? ENV_API
    : typeof window !== "undefined"
      ? `${window.location.protocol}//${window.location.hostname}:8000`
      : "http://localhost:8000";

async function call(path: string, opts: RequestInit = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`${res.status}: ${txt || res.statusText}`);
  }
  return res.json();
}

export const api = {
  health: () => call("/health"),
  getScope: () => call("/scope"),
  checkTarget: (ip: string) => call(`/targets/${encodeURIComponent(ip)}/check`),
  setScope: (payload: {
    admin_user_id: string; totp_code: string; allowed_ranges: string[];
    deny_hosts: string[]; authorized: boolean; authorization_note: string;
  }) => call("/scope", { method: "POST", body: JSON.stringify(payload) }),
  runScan: (targets?: string[], full_ports = false) =>
    call("/scan", { method: "POST", body: JSON.stringify({ targets, full_ports }) }),
  attackGraph: () => call("/attack-graph"),
  whatIf: (target_ip: string, fix: Record<string, unknown>) =>
    call("/whatif", { method: "POST", body: JSON.stringify({ target_ip, fix }) }),
  requestRemediation: (payload: Record<string, unknown>) =>
    call("/remediation/request", { method: "POST", body: JSON.stringify(payload) }),
  approveRemediation: (remediation_id: string, admin_user_id: string, totp_code: string) =>
    call("/remediation/approve", {
      method: "POST",
      body: JSON.stringify({ remediation_id, admin_user_id, totp_code }),
    }),
  rollbackRemediation: (remediation_id: string, admin_user_id: string, totp_code: string) =>
    call("/remediation/rollback", {
      method: "POST",
      body: JSON.stringify({ remediation_id, admin_user_id, totp_code }),
    }),
  whatIfMany: (target_ip: string, fixes: Record<string, unknown>[]) =>
    call("/whatif", { method: "POST", body: JSON.stringify({ target_ip, fixes }) }),
  rejectRemediation: (remediation_id: string, admin_user_id: string, reason: string) =>
    call("/remediation/reject", {
      method: "POST",
      body: JSON.stringify({ remediation_id, admin_user_id, reason }),
    }),
  // current_code is needed only when the user already has 2FA and replaces it
  enrollTotp: (user_id: string, current_code = "") =>
    call("/totp/enroll", { method: "POST", body: JSON.stringify({ user_id, current_code }) }),
  verifyAudit: () => call("/audit/verify"),
  // dependency-based digital twin (Jiang et al. 2024, adapted)
  twin: () => call("/twin"),
  setCriticality: (admin_user_id: string, asset_ip: string, criticality: string) =>
    call("/twin/criticality", {
      method: "POST",
      body: JSON.stringify({ admin_user_id, asset_ip, criticality }),
    }),
  setDependency: (payload: {
    admin_user_id: string; from_component: string; to_component: string;
    rule: string; enabled?: boolean; note?: string;
  }) => call("/twin/dependency", { method: "POST", body: JSON.stringify(payload) }),
  removeDependency: (admin_user_id: string, id: string) =>
    call("/twin/dependency/remove", { method: "POST", body: JSON.stringify({ admin_user_id, id }) }),
  reportUrl: () => `${API}/report/latest.pdf`,
};
