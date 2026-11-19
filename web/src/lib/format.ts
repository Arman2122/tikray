import { ApiError, type Server } from './api';

export function friendlyError(err: unknown, fallback: string): string {
  const raw = err instanceof ApiError ? err.detail || err.message : err instanceof Error ? err.message : '';
  if (!raw) return fallback;
  const lower = raw.toLowerCase();
  if (lower.includes('waiting for the runner token') || lower.includes("runner can't be reached")) {
    return 'Data-plane runner (tikray-runner) is offline or still starting up.';
  }
  if (lower.includes('cannot verify installed image state')) {
    return 'Managed RouterOS installation required — container image updates run via the native RouterOS watchdog.';
  }
  return raw.replace(/^(service|artifacts|runnerapi|routeros|auth|backup):\s*/i, '');
}

export function formatBrandVersion(v?: string, fallback = 'v1.0.0'): string {
  const s = v?.trim();
  if (!s || /^[0-9a-f]{12,40}$/i.test(s)) return fallback;
  return s;
}

export function formatBuildVersion(v?: string, fallback = 'v1.0.0'): string {
  const s = v?.trim();
  if (!s) return fallback;
  if (/^[0-9a-f]{12,40}$/i.test(s)) return `${fallback} · ${s.slice(0, 7)}`;
  return s;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${Math.round(v)} B` : `${v.toFixed(1)} ${units[i]}`;
}

export function formatMs(ns?: number): string {
  if (!ns || ns <= 0) return '—';
  const ms = Math.round(ns / 1_000_000);
  if (ms >= 10000) return 'timeout';
  return `${ms} ms`;
}

export function delayClass(ns?: number): 'ok' | 'warn' | 'danger' {
  if (!ns || ns <= 0) return 'danger';
  const ms = ns / 1_000_000;
  if (ms < 250) return 'ok';
  if (ms < 600) return 'warn';
  return 'danger';
}

export function delayPercent(ns?: number): number {
  if (!ns || ns <= 0) return 0;
  const ms = ns / 1_000_000;
  return Math.max(8, Math.min(100, Math.round((ms / 800) * 100)));
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function formatTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 2000) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

export function serverEndpoint(srv: Server): { protocol: string; endpoint: string } {
  const proto = srv.outbound?.protocol ? srv.outbound.protocol.toUpperCase() : '—';
  const addr = srv.outbound?.settings?.address;
  const port = srv.outbound?.settings?.port;
  const endpoint = addr ? (port ? `${addr}:${port}` : addr) : '—';
  return { protocol: proto, endpoint };
}

export function splitLines(text: string): string[] {
  return text
    .split(/[\r\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function downloadJSON(filename: string, obj: unknown): void {
  const blob = new Blob([JSON.stringify(obj, null, 2) + '\n'], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
