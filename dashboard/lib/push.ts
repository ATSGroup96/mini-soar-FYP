"use client";
import { getSupabase } from "./supabaseClient";

const VAPID = process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY || "";

function urlBase64ToUint8Array(base64: string) {
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const b64 = (base64 + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

export async function enablePush(): Promise<boolean> {
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) return false;
  const perm = await Notification.requestPermission();
  if (perm !== "granted") return false;

  const reg = await navigator.serviceWorker.register("/sw.js");
  if (!VAPID) {
    // Without VAPID keys we can still show local notifications from realtime.
    return true;
  }
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(VAPID),
  });

  const sb = getSupabase();
  const json = sub.toJSON() as any;
  const { data: auth } = (await sb?.auth.getUser()) || { data: { user: null } };
  if (sb && json.keys) {
    await sb.from("push_subscriptions").upsert({
      user_id: auth?.user?.id ?? null,
      endpoint: json.endpoint,
      p256dh: json.keys.p256dh,
      auth: json.keys.auth,
    });
  }
  return true;
}
