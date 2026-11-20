// Calls to the FastAPI gateway for ACTIONS (scans, prioritization, approvals, reports).
// "auto" (or empty) = the API runs on the same machine as the dashboard, port 8000.
// Then nothing needs rebuilding when the engine gets a new IP on a new network.
//
// Every call carries the signed-in user's Supabase access token
// ("Authorization: Bearer ..."). The API takes the user's identity and role from
// that token, never from the request body.
import { getSupabase } from "./supabaseClient";

const ENV_API = process.env.NEXT_PUBLIC_API_URL || "auto";
const API =
  ENV_API !== "auto"
    ? ENV_API
    : typeof window !== "undefined"
      ? `${window.location.protocol}//${window.location.hostname}:8000`
      : "http://localhost:8000";

async function authHeader(): Promise<Record<string, string>> {
  const sb = getSupabase();
  if (!sb) return {};
  const { data } = await sb.auth.getSession();
  const token = data.session?.access_token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function send(path: string, opts: RequestInit = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(await authHeader()),
      ...((opts.headers as Record<string, string>) || {}),
    },
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    let detail = txt;
    try { detail = JSON.parse(txt).detail ?? txt; } catch { /* plain text */ }
    throw new Error(`${res.status}: ${detail || res.statusText}`);
  }
  return res;
}

async function call(path: string, opts: RequestInit = {}) {
  return (await send(path, opts)).json();
}

const post = (path: string, body: unknown) =>
  call(path, { method: "POST", body: JSON.stringify(body) });

export type Fix = { type: string; params?: Record<string, unknown>; [k: string]: unknown };

export const api = {
  health: () => call("/health"),
  getScope: () => call("/scope"),
  checkTarget: (ip: string) => call(`/targets/${encodeURIComponent(ip)}/check`),
  setScope: (payload: {
    totp_code: string; allowed_ranges: string[];
    deny_hosts: string[]; authorized: boolean; authorization_note: string;
  }) => post("/scope", payload),
  runScan: (targets?: string[], full_ports = false) => post("/scan", { targets, full_ports }),

  // topology + dependency-based patch prioritization (Jiang et al. 2024, adapted)
  topology: () => call("/topology"),
  prioritization: () => call("/prioritization"),
  fixPreview: (target_ip: string, fixes: Fix[]) =>
    post("/fix-preview", fixes.length === 1 ? { target_ip, fix: fixes[0] } : { target_ip, fixes }),
  setImportance: (asset_ip: string, importance: string) =>
    post("/prioritization/importance", { asset_ip, importance }),
  setDependency: (payload: {
    from_component: string; to_component: string; rule: string; enabled?: boolean; note?: string;
  }) => post("/prioritization/dependency", payload),
  removeDependency: (id: string) => post("/prioritization/dependency/remove", { id }),

  // remediation pipeline
  requestRemediation: (payload: {
    ticket_id: string; asset_ip: string; action_type: string; params: Record<string, unknown>;
  }) => post("/remediation/request", payload),
  approveRemediation: (remediation_id: string, totp_code: string) =>
    post("/remediation/approve", { remediation_id, totp_code }),
  rollbackRemediation: (remediation_id: string, totp_code: string) =>
    post("/remediation/rollback", { remediation_id, totp_code }),
  rejectRemediation: (remediation_id: string, reason: string) =>
    post("/remediation/reject", { remediation_id, reason }),

  // current_code is needed only when the user already has 2FA and replaces it
  enrollTotp: (current_code = "") => post("/totp/enroll", { current_code }),
  verifyAudit: () => call("/audit/verify"),

  // the report needs the login too, so it is fetched and saved as a file
  downloadReport: async () => {
    const res = await send("/report/latest.pdf");
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "mini-soar-report.pdf";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  },
};
