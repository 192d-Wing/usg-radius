// Thin client for the BFF JSON API.
export async function get<T = any>(
  path: string,
  params?: Record<string, string | number | undefined>
): Promise<T> {
  const url = new URL(path, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export async function post<T = any>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export interface Me {
  user?: string;
  email?: string;
  groups?: string[];
}

export interface ServerHealth {
  ready: boolean;
  detail?: string;
}

// A single Prometheus-style gauge/counter scraped from the radius /metrics endpoint.
export interface Metric {
  name: string;
  value: number;
  labels?: Record<string, string>;
  help?: string;
}

export interface Overview {
  backend: string; // e.g. "memory"
  backend_up: boolean;
  uptime_seconds: number;
  cache_entries: number;
  metrics: Metric[];
}

export interface Client {
  address: string;
  name?: string | null;
  enabled: boolean;
  nas_identifier?: string | null;
}

export interface User {
  username: string;
  attributes: Record<string, string>;
}

export interface Session {
  session_id?: string;
  username?: string;
  nas_ip?: string;
  framed_ip?: string;
  [k: string]: any;
}

export const fmtDuration = (s: number) => {
  if (!Number.isFinite(s)) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return [d && `${d}d`, h && `${h}h`, `${m}m`].filter(Boolean).join(" ");
};
