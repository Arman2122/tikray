// Typed HTTPS API client for tikray control plane (/v1/*).
// Uses session cookies (same-origin), automatic X-Tikray-CSRF headers,
// optimistic concurrency via ETag / If-Match, and X-Tikray-Boot-ID tracking.

export interface AuthState {
  setup_required: boolean;
  signed_in: boolean;
}

export interface SessionInfo {
  username?: string;
  csrf_token: string;
  expires: string;
}

export interface TokenInfo {
  id: string;
  name: string;
  created: string;
  expires?: string;
  last_used?: string;
}

export interface CreatedToken {
  token: string;
  info: TokenInfo;
}

export type PolicyMode = 'direct' | 'smart' | 'full';

export interface Policy {
  mode: PolicyMode;
  kill_switch?: boolean;
}

export const KEEP_SECRET_SENTINEL = '__tikray_saved__';

export interface ServerConfigView {
  id: string;
  name: string;
  disabled?: boolean;
  subscription?: string;
  outbound: Record<string, unknown>;
}

export interface Server {
  id: string;
  name: string;
  disabled?: boolean;
  untested?: boolean;
  invalid?: string;
  subscription?: string;
  outbound?: {
    protocol?: string;
    settings?: {
      address?: string;
      port?: number;
    };
  };
}

export interface Subscription {
  id: string;
  name: string;
  disabled?: boolean;
  interval: string;
  last_fetch?: string;
  last_error?: string;
}

export interface RefreshResult {
  added: number;
  updated: number;
  removed: number;
  kept: number;
  skipped: { line: string; reason: string }[];
  via: string;
}

export interface Device {
  address: string;
  name?: string;
  mac?: string;
  policy: Policy;
}

export type RuleAction = 'direct' | 'proxy' | 'block' | 'server';

export interface Rule {
  domains?: string[];
  ips?: string[];
  action: RuleAction;
  server?: string;
}

export interface Routing {
  pinned?: string;
  block_list?: string[];
  domestic: {
    domains?: string[];
    ips?: string[];
  };
  rules?: Rule[];
}

export interface DNSConfig {
  domestic?: string;
  remote: string;
}

export interface HealthConfig {
  probe_url: string;
}

export interface NetworkConfig {
  subnet: string;
  require_local_bridge?: boolean;
}

export interface State {
  version: number;
  servers: Server[];
  subscriptions: Subscription[];
  devices: Device[];
  default_policy: Policy;
  routing: Routing;
  dns: DNSConfig;
  network: NetworkConfig;
  health: HealthConfig;
}

export interface ArtifactResult {
  from?: string;
  to: string;
  outcome: string;
  kind?: string;
  source?: string;
  verified?: string;
  detail?: string;
  hot?: boolean;
  at: string;
}

export interface ServerHealth {
  id: string;
  alive: boolean;
  delay?: number; // nanoseconds from Go time.Duration
  last_error?: string;
  last_seen?: string;
  last_try?: string;
}

export interface HealthSnapshot {
  at?: string;
  level: 'ok' | 'idle' | 'degraded' | 'outage' | 'down' | 'unknown';
  selected?: string;
  pinned?: string;
  runner: {
    reachable: boolean;
    state?: string;
    xray_version?: string;
    routes_ok?: boolean;
    gateway_up?: boolean;
    error?: string;
  };
  servers: ServerHealth[];
  probe: {
    ran?: boolean;
    ok?: boolean;
    delay?: number;
    error?: string;
    at?: string;
  };
}

export interface RouterStatus {
  version?: string;
  untested?: boolean;
  revision: number;
  pending: boolean;
  degraded?: string;
  last_verified?: string;
}

export interface PingResult {
  id: string;
  tcp_ms?: number;
  http_ms?: number;
  obs_ms?: number;
  alive: boolean;
  error?: string;
  tested_at: string;
}

export interface CoreRelease {
  version: string;
  tested: boolean;
  installed: boolean;
  active: boolean;
}

export interface CoreReleasesInfo {
  latest?: string;
  releases: CoreRelease[];
  online: boolean;
}

export interface ServiceStatus {
  boot_id?: string;
  version?: string;
  revision: number;
  applied: boolean;
  routeros?: RouterStatus;
  pending: boolean;
  last_apply?: ArtifactResult;
  core?: string;
  core_tested: boolean;
  health: HealthSnapshot;
  degraded: string[];
  geo_degraded?: boolean;
  pings?: Record<string, PingResult>;
}

export interface TrafficCounter {
  tag: string;
  server_id?: string;
  uplink: number;
  downlink: number;
}

export interface ServiceStats {
  available: boolean;
  sys?: {
    uptime: number;
    num_goroutine: number;
    alloc: number;
  };
  outbounds: TrafficCounter[];
  inbounds: TrafficCounter[];
}

export interface ServiceEvent {
  seq: number;
  at: string;
  kind: string;
  message: string;
}

export interface LeaseInfo {
  address: string;
  mac: string;
  name?: string;
  static?: boolean;
}

export interface CoreSlot {
  version: string;
  verified: string;
  source: string;
  installed_at: string;
}

export interface CoreInfo {
  active: string;
  slots: CoreSlot[];
  history: ArtifactResult[];
}

export interface GeoSlotInfo {
  slot: string;
  profile?: string;
  release_id?: string;
  site: string[];
  ip: string[];
  prefix_count: number;
}

export interface GeoInfo {
  active?: string;
  profile?: string;
  degraded?: boolean;
  pending?: boolean;
  slots: GeoSlotInfo[];
  history: ArtifactResult[];
}

export interface ImageStatus {
  component: string;
  active?: string;
  previous?: string;
  target?: string;
  state?: string;
  error?: string;
  updated_at?: string;
}

export interface ImageOperation {
  component: string;
  action: string;
  target?: string;
  state: string;
  warning?: string;
}

export interface BackupBundle {
  format: string;
  created_at: string;
  kdf: string;
  kdf_params: {
    memory_kib: number;
    iterations: number;
    parallelism: number;
  };
  salt: string;
  nonce: string;
  ciphertext: string;
}

export class ApiError extends Error {
  status: number;
  code: string;
  detail: string;
  result?: ArtifactResult;
  retryAfter?: number;

  constructor(status: number, code: string, detail: string, result?: ArtifactResult, retryAfter?: number) {
    super(detail || code || `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.result = result;
    this.retryAfter = retryAfter;
  }
}

let csrfToken = '';
let currentEtag = '';
let unauthorizedHandler: (() => void) | null = null;

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export function clearSessionState(): void {
  csrfToken = '';
  currentEtag = '';
}

export function onUnauthorized(fn: () => void): void {
  unauthorizedHandler = fn;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  rawBody?: BodyInit;
  contentType?: string;
  useIfMatch?: boolean;
  publicRoute?: boolean;
}

async function request<T>(
  path: string,
  opts: RequestOptions = {}
): Promise<{ data: T; headers: Headers; etag: string }> {
  const method = opts.method ?? 'GET';
  const headers = new Headers();
  if (opts.rawBody !== undefined) {
    if (opts.contentType) {
      headers.set('Content-Type', opts.contentType);
    }
  } else if (opts.body !== undefined) {
    headers.set('Content-Type', 'application/json');
  }
  if (method !== 'GET' && method !== 'HEAD' && csrfToken && !opts.publicRoute) {
    headers.set('X-Tikray-CSRF', csrfToken);
  }
  if (opts.useIfMatch && currentEtag) {
    headers.set('If-Match', currentEtag);
  }

  const resp = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: opts.rawBody !== undefined ? opts.rawBody : opts.body !== undefined ? JSON.stringify(opts.body) : undefined
  });

  const etag = resp.headers.get('ETag') ?? '';
  if (etag) {
    currentEtag = etag;
  }

  if (resp.status === 204) {
    return { data: undefined as T, headers: resp.headers, etag };
  }

  const text = await resp.text();
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }

  if (!resp.ok) {
    const errObj = (parsed ?? {}) as { error?: string; detail?: string; result?: ArtifactResult };
    const retryHeader = resp.headers.get('Retry-After');
    const retryAfter = retryHeader ? Number.parseInt(retryHeader, 10) : undefined;
    if (resp.status === 401 && !opts.publicRoute) {
      clearSessionState();
      unauthorizedHandler?.();
    }
    throw new ApiError(
      resp.status,
      errObj.error ?? 'http_error',
      errObj.detail ?? (text || resp.statusText),
      errObj.result,
      Number.isFinite(retryAfter) ? retryAfter : undefined
    );
  }

  return { data: parsed as T, headers: resp.headers, etag };
}

export const api = {
  // Auth
  async getAuthState(): Promise<AuthState> {
    return (await request<AuthState>('/v1/auth/state', { publicRoute: true })).data;
  },
  async setup(code: string, username: string, password: string): Promise<SessionInfo> {
    const { data } = await request<SessionInfo>('/v1/auth/setup', {
      method: 'POST',
      body: { code, username, password },
      publicRoute: true
    });
    setCsrfToken(data.csrf_token);
    return data;
  },
  async login(username: string, password: string): Promise<SessionInfo> {
    const { data } = await request<SessionInfo>('/v1/auth/login', {
      method: 'POST',
      body: { username, password },
      publicRoute: true
    });
    setCsrfToken(data.csrf_token);
    return data;
  },
  async getSession(): Promise<SessionInfo> {
    const { data } = await request<SessionInfo>('/v1/auth/session');
    setCsrfToken(data.csrf_token);
    return data;
  },
  async logout(): Promise<void> {
    await request<void>('/v1/auth/logout', { method: 'POST' });
    clearSessionState();
  },
  async changePassword(current: string, next: string): Promise<void> {
    await request<void>('/v1/auth/password', { method: 'PUT', body: { current, new: next } });
  },

  // Tokens
  async listTokens(): Promise<TokenInfo[]> {
    return (await request<TokenInfo[]>('/v1/tokens')).data;
  },
  async createToken(name: string, expiresIn?: string): Promise<CreatedToken> {
    return (
      await request<CreatedToken>('/v1/tokens', {
        method: 'POST',
        body: { name, expires_in: expiresIn || undefined }
      })
    ).data;
  },
  async revokeToken(id: string): Promise<void> {
    await request<void>(`/v1/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },

  // Status, State, Stats, Events
  async getStatus(): Promise<ServiceStatus> {
    return (await request<ServiceStatus>('/v1/status')).data;
  },
  async getStats(): Promise<ServiceStats> {
    return (await request<ServiceStats>('/v1/stats')).data;
  },
  async getState(): Promise<State> {
    return (await request<State>('/v1/state')).data;
  },
  async getEvents(after = 0): Promise<{ events: ServiceEvent[]; bootId: string }> {
    const q = after > 0 ? `?after=${after}` : '';
    const { data, headers } = await request<ServiceEvent[]>(`/v1/events${q}`);
    return { events: data, bootId: headers.get('X-Tikray-Boot-ID') ?? '' };
  },
  async applyNow(): Promise<ArtifactResult> {
    return (await request<ArtifactResult>('/v1/apply', { method: 'POST' })).data;
  },

  // Servers
  async getServerConfig(id: string): Promise<ServerConfigView> {
    return (await request<ServerConfigView>(`/v1/servers/${encodeURIComponent(id)}/config`)).data;
  },
  async addServer(payload: { link?: string; name?: string; outbound?: unknown }): Promise<Server> {
    return (
      await request<Server>('/v1/servers', {
        method: 'POST',
        body: payload,
        useIfMatch: true
      })
    ).data;
  },
  async patchServer(
    id: string,
    patch: { name?: string; disabled?: boolean; link?: string; outbound?: unknown }
  ): Promise<Server> {
    return (
      await request<Server>(`/v1/servers/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: patch,
        useIfMatch: true
      })
    ).data;
  },
  async deleteServer(id: string): Promise<void> {
    await request<void>(`/v1/servers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      useIfMatch: true
    });
  },
  async pingServer(id: string): Promise<PingResult> {
    return (await request<PingResult>(`/v1/servers/${encodeURIComponent(id)}/ping`, { method: 'POST' })).data;
  },
  async pingAllServers(): Promise<PingResult[]> {
    return (await request<PingResult[]>('/v1/servers/ping', { method: 'POST' })).data;
  },

  // Subscriptions
  async addSubscription(name: string, url: string, interval: string): Promise<Subscription> {
    return (
      await request<Subscription>('/v1/subscriptions', {
        method: 'POST',
        body: { name, url, interval },
        useIfMatch: true
      })
    ).data;
  },
  async patchSubscription(
    id: string,
    patch: { name?: string; url?: string; disabled?: boolean; interval?: string }
  ): Promise<Subscription> {
    return (
      await request<Subscription>(`/v1/subscriptions/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: patch,
        useIfMatch: true
      })
    ).data;
  },
  async deleteSubscription(id: string): Promise<void> {
    await request<void>(`/v1/subscriptions/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      useIfMatch: true
    });
  },
  async refreshSubscription(id: string): Promise<RefreshResult> {
    return (
      await request<RefreshResult>(`/v1/subscriptions/${encodeURIComponent(id)}/refresh`, {
        method: 'POST'
      })
    ).data;
  },

  // Devices, Policy & RouterOS
  async setDefaultPolicy(policy: Policy): Promise<void> {
    await request<void>('/v1/policy', { method: 'PUT', body: policy, useIfMatch: true });
  },
  async setDevice(address: string, device: Device): Promise<void> {
    await request<void>(`/v1/devices/${encodeURIComponent(address)}`, {
      method: 'PUT',
      body: device,
      useIfMatch: true
    });
  },
  async deleteDevice(address: string): Promise<void> {
    await request<void>(`/v1/devices/${encodeURIComponent(address)}`, {
      method: 'DELETE',
      useIfMatch: true
    });
  },
  async getLeases(): Promise<LeaseInfo[]> {
    return (await request<LeaseInfo[]>('/v1/routeros/leases')).data;
  },
  async makeStaticLease(address: string): Promise<LeaseInfo> {
    return (
      await request<LeaseInfo>('/v1/routeros/leases/static', {
        method: 'POST',
        body: { address }
      })
    ).data;
  },
  async repairNetwork(fix: {
    subnet?: string;
    remove_devices?: string[];
    remote_dns?: string;
  }): Promise<{ restart_required: boolean }> {
    return (
      await request<{ restart_required: boolean }>('/v1/network', {
        method: 'PUT',
        body: fix,
        useIfMatch: true
      })
    ).data;
  },

  // Routing, DNS, Health
  async setRouting(routing: Routing): Promise<void> {
    await request<void>('/v1/routing', { method: 'PUT', body: routing, useIfMatch: true });
  },
  async setDNS(dns: DNSConfig): Promise<void> {
    await request<void>('/v1/dns', { method: 'PUT', body: dns, useIfMatch: true });
  },
  async setHealth(health: HealthConfig): Promise<void> {
    await request<void>('/v1/health', { method: 'PUT', body: health, useIfMatch: true });
  },

  // Core, Geo, Images, Offline Inbox
  async getCore(): Promise<CoreInfo> {
    return (await request<CoreInfo>('/v1/core')).data;
  },
  async getCoreReleases(): Promise<CoreReleasesInfo> {
    return (await request<CoreReleasesInfo>('/v1/core/releases')).data;
  },
  async updateCore(version: string, allowUnverified = false): Promise<ArtifactResult> {
    return (
      await request<ArtifactResult>('/v1/core/update', {
        method: 'POST',
        body: { version, allow_unverified: allowUnverified }
      })
    ).data;
  },
  async rollbackCore(): Promise<ArtifactResult> {
    return (await request<ArtifactResult>('/v1/core/rollback', { method: 'POST' })).data;
  },
  async getGeo(): Promise<GeoInfo> {
    return (await request<GeoInfo>('/v1/geo')).data;
  },
  async updateGeo(profile: string, version: string): Promise<ArtifactResult> {
    return (
      await request<ArtifactResult>('/v1/geo/update', {
        method: 'POST',
        body: { profile, version }
      })
    ).data;
  },
  async rollbackGeo(): Promise<ArtifactResult> {
    return (await request<ArtifactResult>('/v1/geo/rollback', { method: 'POST' })).data;
  },
  async getImageStatus(component: 'tikray' | 'runner'): Promise<ImageStatus> {
    return (await request<ImageStatus>(`/v1/images/${component}`)).data;
  },
  async updateImage(component: 'tikray' | 'runner', version: string): Promise<ImageOperation> {
    return (
      await request<ImageOperation>(`/v1/images/${component}/update`, {
        method: 'POST',
        body: { version }
      })
    ).data;
  },
  async rollbackImage(component: 'tikray' | 'runner'): Promise<ImageOperation> {
    return (await request<ImageOperation>(`/v1/images/${component}/rollback`, { method: 'POST' })).data;
  },
  async uploadCoreInbox(filename: string, file: File): Promise<{ name: string; bytes: number }> {
    return (
      await request<{ name: string; bytes: number }>(`/v1/inbox/core/${encodeURIComponent(filename)}`, {
        method: 'POST',
        rawBody: file,
        contentType: 'application/octet-stream'
      })
    ).data;
  },
  async uploadGeoInbox(
    profile: string,
    version: string,
    filename: string,
    file: File
  ): Promise<{ name: string; bytes: number }> {
    return (
      await request<{ name: string; bytes: number }>(
        `/v1/inbox/geo/${encodeURIComponent(profile)}/${encodeURIComponent(version)}/${encodeURIComponent(filename)}`,
        {
          method: 'POST',
          rawBody: file,
          contentType: 'application/octet-stream'
        }
      )
    ).data;
  },

  // Encrypted Backup
  async exportBackup(passphrase: string): Promise<BackupBundle> {
    return (
      await request<BackupBundle>('/v1/backup/export', {
        method: 'POST',
        body: { passphrase }
      })
    ).data;
  },
  async restoreBackup(bundle: BackupBundle, passphrase: string): Promise<{ revision: number }> {
    return (
      await request<{ revision: number }>('/v1/backup/restore', {
        method: 'POST',
        body: { bundle, passphrase },
        useIfMatch: true
      })
    ).data;
  }
};
