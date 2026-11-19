<script lang="ts">
  import { api, type PingResult, type ServiceEvent, type ServiceStats, type ServiceStatus, type State } from '../lib/api';
  import { formatBytes, formatTime, formatUptime, friendlyError } from '../lib/format';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import TopologyFlow from '../components/TopologyFlow.svelte';
  import TrafficChart, { type RateSample } from '../components/TrafficChart.svelte';

  interface Props {
    username: string;
    status: ServiceStatus | null;
    stateData: State | null;
    stats: ServiceStats | null;
    rateHistory: RateSample[];
    events: ServiceEvent[];
    onRefresh: () => Promise<void>;
    onNavigate: (view: string) => void;
  }

  let { username, status, stateData, stats, rateHistory, events, onRefresh, onNavigate }: Props = $props();

  let applying = $state(false);
  let pingingAll = $state(false);
  let localPings = $state<Record<string, PingResult>>({});

  const greeting = $derived.by(() => {
    const now = new Date();
    const h = now.getHours();
    const part = h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
    const dateStr = now.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' });
    return `${part}, ${username || 'admin'} · ${dateStr}`;
  });

  const healthLevel = $derived(status?.health.level ?? 'unknown');
  const healthTone = $derived(
    healthLevel === 'ok'
      ? 'ok'
      : healthLevel === 'degraded'
        ? 'warn'
        : healthLevel === 'down' || healthLevel === 'outage'
          ? 'danger'
          : 'accent'
  );

  const selectedServer = $derived(
    stateData?.servers.find((s) => s.id === status?.health.selected) ?? null
  );

  const selectedHealth = $derived(
    status?.health.servers.find((h) => h.id === status?.health.selected) ?? null
  );

  const pingMap = $derived({ ...(status?.pings ?? {}), ...localPings });

  function bestLatencyMs(id: string, obsNs?: number): { ms: number; label: string; detail: string } | null {
    const p = pingMap[id];
    const parts: string[] = [];
    if (p?.tcp_ms) parts.push(`TCP ${p.tcp_ms} ms`);
    if (p?.http_ms) parts.push(`HTTP 204 ${p.http_ms} ms`);
    const obsMs = obsNs && obsNs > 0 ? Math.round(obsNs / 1_000_000) : p?.obs_ms;
    if (obsMs && obsMs > 0) parts.push(`Cold E2E ${obsMs} ms`);

    if (p?.http_ms && p.http_ms > 0) {
      return { ms: p.http_ms, label: 'HTTP', detail: parts.join(' · ') };
    }
    if (p?.tcp_ms && p.tcp_ms > 0) {
      return { ms: p.tcp_ms, label: 'TCP', detail: parts.join(' · ') };
    }
    if (obsMs && obsMs > 0) {
      return { ms: obsMs, label: 'E2E', detail: parts.join(' · ') };
    }
    return null;
  }

  function latencyTone(ms: number): 'ok' | 'warn' | 'danger' {
    if (ms <= 180) return 'ok';
    if (ms <= 450) return 'warn';
    return 'danger';
  }

  const totalTraffic = $derived.by(() => {
    if (!stats?.outbounds) return { up: 0, down: 0 };
    let up = 0;
    let down = 0;
    for (const o of stats.outbounds) {
      if (o.tag === 'direct' || o.server_id) {
        up += o.uplink;
        down += o.downlink;
      }
    }
    return { up, down };
  });

  const trafficSplit = $derived.by(() => {
    if (!stats?.outbounds) return { proxied: 0, direct: 0, proxyPct: 0, directPct: 0 };
    let proxied = 0;
    let direct = 0;
    for (const o of stats.outbounds) {
      const sum = o.uplink + o.downlink;
      if (o.server_id) proxied += sum;
      else if (o.tag === 'direct') direct += sum;
    }
    const total = proxied + direct;
    if (total === 0) return { proxied: 0, direct: 0, proxyPct: 0, directPct: 0 };
    const proxyPct = Math.round((proxied / total) * 100);
    return { proxied, direct, proxyPct, directPct: 100 - proxyPct };
  });

  const serverRows = $derived.by(() => {
    const srvs = stateData?.servers ?? [];
    const healthMap = new Map((status?.health.servers ?? []).map((h) => [h.id, h]));
    const statMap = new Map((stats?.outbounds ?? []).filter((o) => o.server_id).map((o) => [o.server_id!, o]));
    return srvs.map((srv) => {
      const h = healthMap.get(srv.id);
      const lat = bestLatencyMs(srv.id, h?.delay);
      return {
        srv,
        h,
        lat,
        ping: pingMap[srv.id],
        traffic: statMap.get(srv.id),
        selected: status?.health.selected === srv.id,
        pinned: stateData?.routing.pinned === srv.id
      };
    });
  });

  const serverCounts = $derived.by(() => {
    let alive = 0;
    let disabled = 0;
    let down = 0;
    const runnerOnline = Boolean(status?.health.runner.reachable);
    for (const row of serverRows) {
      if (row.srv.disabled) {
        disabled++;
      } else if (row.h?.alive || row.ping?.alive) {
        alive++;
      } else if (runnerOnline && !row.srv.untested && (row.h?.last_error || row.ping?.error)) {
        down++;
      }
    }
    const total = serverRows.length;
    const alivePct = total > 0 ? Math.round((alive / total) * 100) : 0;
    return { total, alive, disabled, down, alivePct };
  });

  const fastestMetric = $derived.by(() => {
    let best: { ms: number; label: string; name: string; detail: string } | null = null;
    for (const r of serverRows) {
      if (r.srv.disabled || !r.lat) continue;
      if (!best || r.lat.ms < best.ms) {
        best = { ms: r.lat.ms, label: r.lat.label, name: r.srv.name, detail: r.lat.detail };
      }
    }
    return best;
  });

  const heapPct = $derived.by(() => {
    const alloc = stats?.sys?.alloc ?? 0;
    const budget = 128 * 1024 * 1024;
    if (alloc <= 0) return 0;
    return Math.min(100, Math.max(2, Math.round((alloc / budget) * 100)));
  });

  const attentionItems = $derived.by(() => {
    const items: { tone: 'danger' | 'warn'; title: string; sub: string; view: string }[] = [];
    if (status?.routeros?.degraded === 'bridge_repair') {
      items.push({
        tone: 'danger',
        title: 'Container bridge overlap detected',
        sub: 'Repair bridge subnet before RouterOS policy writes resume',
        view: 'settings'
      });
    }
    if (status && !status.health.runner.reachable) {
      items.push({
        tone: 'danger',
        title: 'Data-plane runner offline',
        sub: status.health.runner.error || 'Waiting for tikray-runner heartbeat',
        view: 'updates'
      });
    }
    if (status?.geo_degraded) {
      items.push({
        tone: 'warn',
        title: !status.health.runner.reachable ? 'Geo update deferred (runner offline)' : 'Geo bundle needs attention',
        sub: 'Review geo slots and domestic bypass bundle in Updates',
        view: 'updates'
      });
    }
    if (status?.routeros?.untested) {
      items.push({
        tone: 'warn',
        title: `RouterOS ${status.routeros.version} running in forward-compat mode`,
        sub: 'Verify reconciliation events after major RouterOS upgrades',
        view: 'events'
      });
    }
    if (serverCounts.down > 0) {
      items.push({
        tone: 'danger',
        title: `${serverCounts.down} proxy server${serverCounts.down === 1 ? '' : 's'} unreachable`,
        sub: 'Run latency test or inspect credentials in Servers',
        view: 'servers'
      });
    }
    if (serverCounts.total === 0) {
      items.push({
        tone: 'warn',
        title: 'No proxy servers configured',
        sub: 'Add a VLESS, REALITY, XHTTP, Trojan, or VMess share link',
        view: 'servers'
      });
    }
    return items;
  });

  async function applyNow(): Promise<void> {
    applying = true;
    try {
      const res = await api.applyNow();
      if (res.outcome === 'committed' || res.outcome === 'noop') {
        toast.ok(res.hot ? 'Applied live via xray hot-reload.' : `Applied (${res.outcome}).`);
      } else {
        toast.warn(`Apply ended with ${res.outcome}: ${res.detail ?? ''}`);
      }
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Apply failed'));
    } finally {
      applying = false;
    }
  }

  async function runPingAll(): Promise<void> {
    if (serverRows.length === 0) return;
    pingingAll = true;
    try {
      const results = await api.pingAllServers();
      const next = { ...localPings };
      for (const r of results) next[r.id] = r;
      localPings = next;
      const aliveCount = results.filter((r) => r.alive).length;
      toast.ok(`Tested ${results.length} server${results.length === 1 ? '' : 's'}: ${aliveCount} reachable.`);
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Latency test failed'));
    } finally {
      pingingAll = false;
    }
  }
</script>

<div class="stack-lg">
  <!-- Obsidian SaaS Greeting Header -->
  <div class="page-header" style="margin-bottom: 2px">
    <div>
      <h1 class="page-title">Dashboard</h1>
      <p class="page-sub">{greeting}</p>
    </div>
    <div class="row" style="gap: 8px">
      <button
        type="button"
        class="btn btn-sm"
        disabled={pingingAll || serverCounts.total === 0}
        onclick={runPingAll}
      >
        <Icon name="zap" size={13} />
        {pingingAll ? 'Testing…' : 'Test Latency'}
      </button>
      <button type="button" class="btn btn-primary btn-sm" disabled={applying} onclick={applyNow}>
        <Icon name="refresh" size={13} />
        {applying ? 'Applying…' : 'Apply Now'}
      </button>
    </div>
  </div>

  <!-- 4-Column Unified Top Telemetry Strip -->
  <div class="telemetry-strip">
    <button type="button" class="telemetry-cell" onclick={() => onNavigate('settings')}>
      <span class="telemetry-kicker">
        <Icon name="shield" size={11} />
        RouterOS
      </span>
      <span class="telemetry-val">
        <span
          class="dot {!status?.routeros
            ? 'accent'
            : status.routeros.degraded
              ? 'danger'
              : status.routeros.pending || status.routeros.untested
                ? 'warn'
                : 'ok'}"
        ></span>
        {#if status?.routeros}
          v{status.routeros.version || '7.x'} · {status.routeros.degraded || (status.routeros.pending ? 'Syncing' : 'In sync')}
        {:else}
          Standalone · Local bridge
        {/if}
      </span>
    </button>

    <button type="button" class="telemetry-cell" onclick={() => onNavigate('servers')}>
      <span class="telemetry-kicker">
        <Icon name="activity" size={11} />
        Proxy Tunnel
      </span>
      <span class="telemetry-val">
        <span class="dot {healthTone}"></span>
        {healthLevel === 'ok' ? 'Connected' : healthLevel === 'idle' ? 'Idle' : healthLevel} · rev {status?.revision ?? 0}
      </span>
    </button>

    <button type="button" class="telemetry-cell" onclick={() => onNavigate('updates')}>
      <span class="telemetry-kicker">
        <Icon name="cpu" size={11} />
        xray-core
      </span>
      <span class="telemetry-val mono">
        <span class="dot {status?.health.runner.reachable && status?.core ? 'ok' : 'warn'}"></span>
        {status?.core ? `v${status.core}` : 'None'}{stats?.sys ? ` · ${formatBytes(stats.sys.alloc)}` : ''}
      </span>
    </button>

    <button type="button" class="telemetry-cell" onclick={() => onNavigate('events')}>
      <span class="telemetry-kicker">
        <Icon name="events" size={11} />
        Audit Trail
      </span>
      <span class="telemetry-val tabular">
        <span class="dot ok"></span>
        Intact · {events.length} {events.length === 1 ? 'entry' : 'entries'}
      </span>
    </button>
  </div>

  <!-- 4-Column KPI Metric Row with Razor-Thin Micro Meters -->
  <div class="grid-4">
    <div class="kpi">
      <div class="kpi-top">
        <span class="kpi-label">Proxy Servers</span>
        <Icon name="servers" size={14} />
      </div>
      <div class="kpi-value tabular">{serverCounts.total}</div>
      <div class="meter-track">
        <div
          class="meter-fill {serverCounts.down > 0 ? 'warn' : 'ok'}"
          style="width: {serverCounts.total > 0 ? Math.max(6, serverCounts.alivePct) : 0}%"
        ></div>
      </div>
      <span class="kpi-meta tabular">
        {serverCounts.alive} alive · {serverCounts.down} down · {serverCounts.disabled} disabled
      </span>
    </div>

    <div class="kpi">
      <div class="kpi-top">
        <span class="kpi-label">Active Latency</span>
        <Icon name="zap" size={14} />
      </div>
      <div class="kpi-value tabular" title={fastestMetric?.detail}>
        {fastestMetric ? `${fastestMetric.ms} ms` : '—'}
      </div>
      <div class="meter-track">
        {#if fastestMetric}
          <div
            class="meter-fill {latencyTone(fastestMetric.ms)}"
            style="width: {Math.min(100, Math.max(10, Math.round((fastestMetric.ms / 500) * 100)))}%"
          ></div>
        {/if}
      </div>
      <span class="kpi-meta" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis">
        {#if fastestMetric}
          {fastestMetric.label} · {selectedServer?.name || fastestMetric.name}
        {:else if serverCounts.total > 0}
          Click Test Latency to measure
        {:else}
          No active exit server
        {/if}
      </span>
    </div>

    <div class="kpi">
      <div class="kpi-top">
        <span class="kpi-label">Data Plane RAM</span>
        <Icon name="cpu" size={14} />
      </div>
      <div class="kpi-value tabular">
        {stats?.sys ? formatBytes(stats.sys.alloc) : '—'}
      </div>
      <div class="meter-track">
        <div class="meter-fill accent" style="width: {heapPct}%"></div>
      </div>
      <span class="kpi-meta tabular">
        {#if stats?.sys}
          {heapPct}% of 128 MiB · {stats.sys.num_goroutine} goroutines · up {formatUptime(stats.sys.uptime)}
        {:else}
          Waiting for xray stats API
        {/if}
      </span>
    </div>

    <div class="kpi">
      <div class="kpi-top">
        <span class="kpi-label">Session Traffic</span>
        <Icon name="globe" size={14} />
      </div>
      <div class="kpi-value tabular">
        {stats?.available ? formatBytes(totalTraffic.down + totalTraffic.up) : '—'}
      </div>
      <div class="meter-track">
        <div class="meter-fill accent" style="width: {trafficSplit.proxyPct}%"></div>
        <div class="meter-fill ok" style="width: {trafficSplit.directPct}%"></div>
      </div>
      <span class="kpi-meta tabular">
        {#if stats?.available}
          ↓ {formatBytes(totalTraffic.down)} · ↑ {formatBytes(totalTraffic.up)}
        {:else}
          No traffic sampled yet
        {/if}
      </span>
    </div>
  </div>

  <!-- Bento Row 1: Needs Attention + Live Data-Path Topology -->
  <div class="bento-asym">
    <div class="card stack" style="gap: 12px">
      <div class="row-between">
        <div>
          <h2 class="card-title">Needs Attention</h2>
          <p class="card-sub">
            {attentionItems.length === 0 ? 'All checks passing' : `${attentionItems.length} item${attentionItems.length === 1 ? '' : 's'} to review`}
          </p>
        </div>
        <span class="badge {attentionItems.length === 0 ? 'ok' : attentionItems.some((a) => a.tone === 'danger') ? 'danger' : 'warn'} tabular">
          {attentionItems.length}
        </span>
      </div>

      {#if attentionItems.length === 0}
        <div class="attention-item" style="cursor: default">
          <span class="dot ok" style="margin-top: 5px"></span>
          <div>
            <span class="attention-title">All systems operational</span>
            <span class="attention-sub">
              {status?.health.probe.ran && status.health.probe.ok
                ? 'End-to-end SOCKS probe passed · zero drift alerts'
                : 'Control plane and data-plane runner healthy'}
            </span>
          </div>
        </div>
      {:else}
        <div class="attention-list">
          {#each attentionItems as item}
            <button type="button" class="attention-item" onclick={() => onNavigate(item.view)}>
              <span class="dot {item.tone}" style="margin-top: 5px"></span>
              <div style="min-width: 0">
                <span class="attention-title">{item.title}</span>
                <span class="attention-sub">{item.sub}</span>
              </div>
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <TopologyFlow
      {status}
      {stateData}
      {stats}
      {selectedServer}
      selectedDelay={selectedHealth?.delay}
      {onNavigate}
    />
  </div>

  <!-- Bento Row 2: High-Design Interactive Throughput Chart + Proportional Servers & Latency Card -->
  <div class="bento-chart">
    <TrafficChart samples={rateHistory} available={stats?.available ?? false} />

    <div class="card stack" style="gap: 10px">
      <div class="row-between">
        <div>
          <h2 class="card-title">Servers &amp; Latency</h2>
          <p class="card-sub">v2rayN-style TCP/HTTP real delay &amp; outbound volume</p>
        </div>
        <div class="row" style="gap: 10px">
          <button type="button" class="card-link" onclick={() => onNavigate('servers')}>All servers →</button>
        </div>
      </div>

      {#if serverRows.length === 0}
        <div class="empty-state" style="padding: 32px 16px">
          <div class="stack" style="align-items: center; gap: 10px">
            <span>No proxy servers configured yet.</span>
            <button type="button" class="btn btn-primary btn-sm" onclick={() => onNavigate('servers')}>
              <Icon name="plus" size={13} /> Add First Server
            </button>
          </div>
        </div>
      {:else}
        <div class="stack" style="gap: 2px">
          {#each serverRows.slice(0, 6) as item (item.srv.id)}
            {@const pct = item.lat ? Math.min(100, Math.max(8, Math.round((item.lat.ms / 500) * 100))) : 0}
            <div class="metric-row">
              <div class="metric-row-top">
                <div class="row" style="gap: 7px; min-width: 0">
                  <span
                    class="dot {item.srv.disabled
                      ? ''
                      : item.h?.alive || item.ping?.alive
                        ? 'ok'
                        : item.h?.last_error || item.ping?.error
                          ? 'danger'
                          : 'warn'}"
                  ></span>
                  <span style="font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis">
                    {item.srv.name}
                  </span>
                  {#if item.selected}
                    <span class="badge ok" style="padding: 0 6px; font-size: 10px">Active</span>
                  {/if}
                  {#if item.pinned}
                    <span class="badge accent" style="padding: 0 6px; font-size: 10px">Pinned</span>
                  {/if}
                </div>
                <div class="row tabular mono" style="gap: 10px; font-size: 11.5px; color: var(--text-muted)">
                  {#if item.lat}
                    <span
                      style="color: var(--{latencyTone(item.lat.ms)}); font-weight: 600"
                      title={item.lat.detail}
                    >
                      {item.lat.ms} ms <span style="opacity: 0.65; font-weight: 400">{item.lat.label}</span>
                    </span>
                  {:else if item.srv.disabled}
                    <span class="hint">disabled</span>
                  {:else}
                    <span class="hint">{item.ping?.error || item.h?.last_error || 'pending'}</span>
                  {/if}
                  {#if item.traffic}
                    <span class="hint">{formatBytes(item.traffic.downlink + item.traffic.uplink)}</span>
                  {/if}
                </div>
              </div>
              <div class="meter-track">
                {#if item.lat}
                  <div class="meter-fill {item.selected ? 'ok' : 'accent'}" style="width: {pct}%"></div>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  </div>

  <!-- Bento Row 3: Traffic Split & Policy + Recent Activity -->
  <div class="grid-2">
    <div class="card stack" style="gap: 12px">
      <div class="row-between">
        <div>
          <h2 class="card-title">Traffic Split &amp; Policy</h2>
          <p class="card-sub">Domestic LAN/ISP traffic bypasses xray at native RouterOS FastTrack speed</p>
        </div>
        <button type="button" class="card-link" onclick={() => onNavigate('devices')}>Configure →</button>
      </div>

      <div class="split-bar" aria-label="Traffic split">
        <div class="split-proxy" style="width: {trafficSplit.proxyPct}%"></div>
        <div class="split-direct" style="width: {trafficSplit.directPct}%"></div>
      </div>

      <div class="grid-2">
        <div class="editor-section" style="padding: 10px 12px; gap: 3px">
          <div class="row" style="gap: 6px">
            <span class="dot accent"></span>
            <span class="hint">Proxied Tunnels</span>
          </div>
          <strong class="tabular" style="font-size: 15px">{formatBytes(trafficSplit.proxied)}</strong>
          <span class="hint tabular">{trafficSplit.proxyPct}% of xray volume</span>
        </div>
        <div class="editor-section" style="padding: 10px 12px; gap: 3px">
          <div class="row" style="gap: 6px">
            <span class="dot ok"></span>
            <span class="hint">Direct Inside xray</span>
          </div>
          <strong class="tabular" style="font-size: 15px">{formatBytes(trafficSplit.direct)}</strong>
          <span class="hint tabular">{trafficSplit.directPct}% of xray volume</span>
        </div>
      </div>

      <div class="row-between hint" style="padding-top: 6px; border-top: 1px solid var(--border)">
        <span>
          Default policy: <strong style="color: var(--text); text-transform: capitalize">{stateData?.default_policy.mode ?? 'direct'}</strong>
          {stateData?.default_policy.kill_switch ? ' · Kill Switch ON' : ''}
        </span>
        <span class="mono">RAM: 128M / 48M / 24M</span>
      </div>
    </div>

    <div class="card stack" style="gap: 10px">
      <div class="row-between">
        <div>
          <h2 class="card-title">Recent Activity</h2>
          <p class="card-sub">Redacted control-plane and RouterOS audit stream</p>
        </div>
        <button type="button" class="card-link" onclick={() => onNavigate('events')}>All events →</button>
      </div>

      {#if events.length === 0}
        <div class="empty-state">No events recorded yet in this process lifetime.</div>
      {:else}
        <div class="stack" style="gap: 6px">
          {#each events.slice(-6).reverse() as ev (ev.seq)}
            <div class="row-between" style="padding: 6px 0; border-bottom: 1px solid var(--border); gap: 10px">
              <div class="row" style="gap: 8px; min-width: 0; flex: 1">
                <span
                  class="dot {ev.kind === 'error' || ev.kind === 'degraded'
                    ? 'danger'
                    : ev.kind === 'warning'
                      ? 'warn'
                      : ev.kind === 'apply' || ev.kind === 'routeros' || ev.kind === 'core' || ev.kind === 'geo'
                        ? 'ok'
                        : 'accent'}"
                ></span>
                <span
                  class="mono"
                  style="font-size: 12px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis"
                  title={ev.message}
                >
                  {ev.message}
                </span>
              </div>
              <span class="hint tabular" style="white-space: nowrap; font-size: 11px">{formatTime(ev.at)}</span>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</div>
