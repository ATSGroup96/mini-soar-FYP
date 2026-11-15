"use client";
import { useEffect, useState } from "react";
import { useSession } from "@/components/AuthGate";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { api } from "@/lib/api";
import { enablePush } from "@/lib/push";
import { Empty } from "@/lib/ui";
import { QrCode, Bell, Network, Activity } from "lucide-react";

// What the scores and CVE matches rest on right now (from the API /health).
function EngineCard() {
  const [h, setH] = useState<any>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.health().then(setH).catch((e: any) => setErr(e.message));
  }, []);
  const ok = "text-low";
  const warn = "text-high";
  return (
    <div className="card">
      <div className="text-sm font-semibold mb-2 flex items-center gap-2"><Activity size={16} /> Engine status</div>
      {err && <div className="text-xs text-critical">API not reachable: {err}</div>}
      {h && (
        <ul className="text-sm space-y-1">
          <li>
            Risk scoring:{" "}
            {h.model?.trained
              ? <span className={ok}>trained PyTorch model{h.model.metrics?.val_mae != null && ` (validation error ${h.model.metrics.val_mae} points)`}</span>
              : <span className={warn}>expert formula (model not trained yet: run.bat train)</span>}
          </li>
          <li>
            CVE database:{" "}
            <span className={h.intel?.cves ? ok : warn}>
              {h.intel?.cves ?? 0} CVEs, {h.intel?.kev ?? 0} KEV, {h.intel?.epss ?? 0} EPSS scores
            </span>
            {!(h.intel?.cves && h.intel?.kev && h.intel?.epss) && <span className="text-muted"> (run.bat update downloads them)</span>}
          </li>
          <li>
            Push notifications:{" "}
            {h.push?.configured
              ? <span className={ok}>ready</span>
              : <span className="text-muted">not set up (optional: VAPID keys in .env)</span>}
          </li>
          <li>
            Cloud database: <span className={h.cloud ? ok : warn}>{h.cloud ? "connected" : "not connected"}</span>
          </li>
        </ul>
      )}
    </div>
  );
}

function ScopeCard({ userId }: { userId: string }) {
  const [cur, setCur] = useState<any>(null);
  const [ranges, setRanges] = useState("");
  const [deny, setDeny] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [note, setNote] = useState("");
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const r = await api.getScope();
      setCur(r);
      setRanges(r.allowed_ranges.join(", "));
      setDeny(r.deny_hosts.filter((d: string) => !r.engine_ips.includes(d)).join(", "));
      setAuthorized(r.authorized);
      setNote(r.note || "");
    } catch (e: any) {
      setMsg(`Engine not reachable: ${e.message}`);
    }
  }
  useEffect(() => { load(); }, []);

  function pickNetwork(n: any) {
    // suggest: scan the network, never the gateway (.1) or the engine itself
    setRanges(n.network);
    const gw = n.network.split("/")[0].replace(/\.\d+$/, ".1");
    setDeny(gw);
    setAuthorized(false);
    setMsg(`Selected ${n.network}. Confirm authorization, enter your 2FA code and save.`);
  }

  async function save() {
    setBusy(true); setMsg("");
    try {
      const split = (t: string) => t.split(",").map((x) => x.trim()).filter(Boolean);
      const r = await api.setScope({
        admin_user_id: userId, totp_code: code, allowed_ranges: split(ranges),
        deny_hosts: split(deny), authorized, authorization_note: note,
      });
      setMsg(`Saved. Scope: ${r.allowed_ranges.join(", ")} · ${r.authorized ? "authorized" : "NOT authorized (scans blocked)"}`);
      setCode("");
      load();
    } catch (e: any) {
      setMsg(`Refused: ${e.message}`);
    } finally { setBusy(false); }
  }

  return (
    <div className="card">
      <div className="text-sm font-semibold mb-1 flex items-center gap-2"><Network size={16} /> Network scope</div>
      <p className="text-xs text-muted mb-3">
        Scans and fixes only touch these ranges. Use only your own lab or a network you have
        <b> written permission</b> to test. Admin + 2FA required; every change goes to the audit log.
      </p>
      {cur && (
        <div className="text-xs mb-3 p-2 rounded-lg bg-panel2 border border-edge space-y-1">
          <div>Now: <span className="font-mono">{cur.allowed_ranges.join(", ") || "none"}</span>{" "}
            <span className={cur.authorized ? "text-low" : "text-critical"}>
              {cur.authorized ? "· authorized" : "· not authorized (scans blocked)"}</span>{" "}
            <span className="text-muted">(from {cur.source})</span></div>
          <div>Always denied: <span className="font-mono">{cur.deny_hosts.join(", ") || "-"}</span></div>
          {cur.note && <div className="text-muted">Authorization: {cur.note}</div>}
          {!cur.env_master_switch && <div className="text-critical">AUTHORIZED_LAB_ONLY is not true in .env, so nothing can run.</div>}
          {!cur.editable && <div className="text-high">SCOPE_SOURCE=env: change the scope in .env on the engine.</div>}
        </div>
      )}
      {cur?.detected?.length > 0 && (
        <div className="mb-3">
          <div className="text-xs text-muted mb-1">Networks the engine is connected to:</div>
          <div className="flex flex-wrap gap-2">
            {cur.detected.filter((n: any) => n.private).map((n: any) => (
              <button key={n.iface + n.network} className="btn text-xs" onClick={() => pickNetwork(n)}>
                {n.iface}: {n.network} (engine {n.ip})
              </button>
            ))}
          </div>
        </div>
      )}
      <label className="text-xs text-muted">Allowed ranges (comma separated, /{cur?.max_prefix ?? 22} or smaller)</label>
      <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full mb-2 font-mono"
        placeholder="192.168.110.0/24" value={ranges} onChange={(e) => setRanges(e.target.value)} />
      <label className="text-xs text-muted">Never touch these IPs (gateway, your PC; the engine is added automatically)</label>
      <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full mb-2 font-mono"
        placeholder="192.168.110.1" value={deny} onChange={(e) => setDeny(e.target.value)} />
      <label className="flex items-start gap-2 text-sm mb-2">
        <input type="checkbox" className="mt-1" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
        <span>I own this network or have written permission to scan and fix it.</span>
      </label>
      <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full mb-2"
        placeholder="Who authorized it, e.g. 'Own VirtualBox lab' or 'Written permission from <name>, <date>'"
        value={note} onChange={(e) => setNote(e.target.value)} />
      <div className="flex gap-2">
        <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-40 font-mono"
          placeholder="2FA code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
        <button className="btn btn-primary flex-1" onClick={save}
          disabled={busy || !userId || code.length < 6 || !ranges.trim() || cur?.editable === false}>
          {busy ? "Saving…" : "Save scope"}
        </button>
      </div>
      {msg && <div className="text-xs text-muted mt-2">{msg}</div>}
    </div>
  );
}

export default function SettingsPage() {
  const profiles = useTable<any>("profiles", { realtime: false });
  const [userId, setUserId] = useState("");
  const session = useSession();
  useEffect(() => { if (session) setUserId(session.user.id); }, [session]);
  const [qr, setQr] = useState("");
  const [currentCode, setCurrentCode] = useState("");
  const [totpMsg, setTotpMsg] = useState("");
  const [pushMsg, setPushMsg] = useState("");

  async function enroll() {
    setTotpMsg("");
    try {
      const r = await api.enrollTotp(userId, currentCode);
      setQr(r.qr);
      setCurrentCode("");
      setTotpMsg("Scan this QR now. Any older entry for Mini-SOAR in your authenticator app no longer works: delete it.");
    } catch (e: any) {
      setQr("");
      setTotpMsg(e.message);
    }
  }

  async function subscribePush() {
    setPushMsg("Requesting permission…");
    try {
      const ok = await enablePush();
      setPushMsg(ok ? "Push enabled on this device." : "Push not available / denied.");
    } catch (e: any) {
      setPushMsg(e.message);
    }
  }

  return (
    <div>
      <Topbar title="Settings" />
      <div className="p-6 space-y-4 max-w-3xl">
        <ConfigNotice />

        <EngineCard />

        <ScopeCard userId={userId} />

        <div className="card">
          <div className="text-sm font-semibold mb-2">Users &amp; roles (RBAC)</div>
          {profiles.rows.length ? (
            <table className="w-full">
              <thead><tr><th className="th">Email</th><th className="th">Role</th><th className="th">2FA</th></tr></thead>
              <tbody>
                {profiles.rows.map((p) => (
                  <tr key={p.id}>
                    <td className="td text-sm">{p.email}</td>
                    <td className="td"><span className="badge bg-accent/20 text-accent border border-accent/40">{p.role}</span></td>
                    <td className="td text-xs">{p.totp_enrolled ? "enrolled" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty msg="No profiles visible (viewer role sees only itself)." />
          )}
        </div>

        <div className="card">
          <div className="text-sm font-semibold mb-2 flex items-center gap-2"><QrCode size={16} /> Enroll TOTP 2FA</div>
          <p className="text-xs text-muted mb-3">Required to approve remediations. Scan the QR in Google Authenticator.</p>
          <div className="flex gap-2">
            <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm flex-1"
              placeholder="your Supabase user id" value={userId} onChange={(e) => setUserId(e.target.value)} />
            <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-44 font-mono"
              placeholder="current code (replace)" maxLength={6} value={currentCode}
              onChange={(e) => setCurrentCode(e.target.value.replace(/\D/g, ""))} />
            <button className="btn btn-primary" onClick={enroll} disabled={!userId}>Generate QR</button>
          </div>
          <p className="text-xs text-muted mt-2">
            First time: leave the code empty. To replace an existing 2FA setup, enter a current 6-digit code.
            Lost the phone? On the engine PC run <span className="font-mono">run.bat totp-reset your@email</span>.
          </p>
          {totpMsg && <div className="text-xs text-muted mt-2">{totpMsg}</div>}
          {qr && <img src={qr} alt="TOTP QR" className="mt-3 w-40 h-40 rounded-lg bg-white p-2" />}
        </div>

        <div className="card">
          <div className="text-sm font-semibold mb-2 flex items-center gap-2"><Bell size={16} /> PWA push notifications</div>
          <button className="btn" onClick={subscribePush}>Enable push on this device</button>
          {pushMsg && <div className="text-xs text-muted mt-2">{pushMsg}</div>}
        </div>
      </div>
    </div>
  );
}
