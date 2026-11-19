<script lang="ts">
  import { api, ApiError, type ServiceEvent, type ServiceStats, type ServiceStatus, type State } from '../lib/api';
  import { delayClass, delayPercent, formatBytes, formatMs, formatTime, formatUptime, serverEndpoint } from '../lib/format';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import TopologyFlow from '../components/TopologyFlow.svelte';
  import TrafficChart, { type RateSample } from '../components/TrafficChart.svelte';

  interface Props {
    status: ServiceStatus | null;
    stateData: State | null;
    stats: ServiceStats | null;
    rateHistory: RateSample[];
    events: ServiceEvent[];
    onRefresh: () => Promise<void>;
    onNavigate: (view: string) => void;
  }

  let { status, stateData, stats, rateHistory, events, onRefresh, onNavigate }: Props = $props();

  let applying = $state(false);

  const healthLevel = $derived(status?.health.level ?? 'unknown');
  const healthTone = $derived(
    healthLevel === 'healthy' ? 'ok' : healthLevel === 'degraded' ? 'warn' : healthLevel === 'down' ? 'danger' : ''
  );

  const selectedServer = $derived.by(() => {
    const id = status?.health.selected || status?.health.pinned;
    if (!id || !stateData) return null;
    return stateData.servers.find((s) => s.id === id) ?? null;
  });

  const selectedHealth = $derived.by(() => {
    const id = status?.health.selected || status?.health.pinned;
    if (!id || !status) return null;
    return status.health.servers.find((s) => s.id === id) ?? null;
  });

  const totalTraffic = $derived.by(() => {
    if (!stats?.available) return { up: 0, down: 0 };
    const tun = stats.inbounds.find((i) => i.tag === 'tun-in');
    if (tun && (tun.uplink > 0 || tun.downlink > 0)) {
      return { up: tun.uplink, down: tun.downlink };
    }
    return stats.outbounds.reduce(
      (acc, cur) => ({ up: acc.up + cur.uplink, down: acc.down + cur.downlink }),
      { up: 0, down: 0 }
    );
  });

  const trafficSplit = $derived.by(() => {
    if (!stats?.available) return { proxied: 0, direct: 0, proxyPct: 0, directPct: 0 };
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
    return srvs.map((srv) => ({
      srv,
      h: healthMap.get(srv.id),
      traffic: statMap.get(srv.id),
      selected: status?.health.selected === srv.id,
      pinned: stateData?.routing.pinned === srv.id
    }));
  });

  async function applyNow(): Promise<void> {
    applying = true;
    try {
      const res = await api.applyNow();
      if (res.outcome === 'committed' || res.outcome === 'noop') {
        toast.ok(res.hot ? 'Applied live via xray hot-reload.' : `Applied successfully (${res.outcome}).`);
      } else {
        toast.warn(`Apply ended with ${res.outcome}: ${res.detail ?? ''}`);
      }
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Apply failed');
    } finally {
      applying = false;
    }
  }
</script>

<div class="stack-lg">
  <!-- Health & Reconciler Hero Banner -->
  <div class="banner {healthTone}">
    <div class="stack" style="gap: 6px">
      <div class="row" style="gap: 10px">
        <span class="dot {healthTone}"></span>
        <span style="font-size: 16px; font-weight: 700; text-transform: capitalize">
          Proxy {healthLevel}
        </span>
        {#if status}
          <span class="badge {status.applied ? 'ok' : 'warn'} tabular">
            {status.applied ? `Applied · rev ${status.revision}` : `Pending · rev ${status.revision}`}
          </span>
          {#if status.core}
            <span class="badge {status.core_tested ? 'accent' : 'warn'} mono">
              xray {status.core}{status.core_tested ? '' : ' (untested)'}
            </span>
          {/if}
          {#if status.routeros}
            <span
              class="badge {status.routeros.degraded
                ? 'danger'
                : status.routeros.pending || status.routeros.untested
                  ? 'warn'
                  : 'ok'}"
            >
              RouterOS{status.routeros.version ? ` ${status.routeros.version}` : ''}:
              {status.routeros.degraded ||
                (status.routeros.pending
                  ? 'reconciling'
                  : status.routeros.untested
                    ? 'untested'
                    : 'verified')}
            </span>
          {:else}
            <span class="badge">Standalone Mode</span>
          {/if}
        {/if}
      </div>
      <div class="hint">
        {#if status?.routeros?.degraded === 'bridge_repair'}
          Bridge network needs repair before policy writes resume.
        {:else if status?.health.runner.err}
          Runner: {status.health.runner.err}
        {:else if status?.health.probe.ran && !status.health.probe.ok && status.health.probe.err}
          Probe failed: {status.health.probe.err}
        {:else if status?.health.runner.reachable}
          Runner {status.health.runner.state ?? 'running'} · Routes {status.health.runner.routes_ok ? 'OK' : 'pending'} · Gateway {status.health.runner.gateway_up ? 'UP' : 'down'}
          {#if status.health.probe.ran && status.health.probe.ok}
            · E2E probe {formatMs(status.health.probe.delay)}
          {/if}
        {:else}
          Waiting for runner heartbeat…
        {/if}
      </div>
    </div>

    <div class="row">
      {#if status?.routeros?.degraded === 'bridge_repair'}
        <button class="btn btn-danger" onclick={() => onNavigate('settings')}>Repair Bridge</button>
      {/if}
      <button class="btn btn-primary" disabled={applying} onclick={applyNow}>
        <Icon name="refresh" size={14} />
        {applying ? 'Applying…' : 'Apply Now'}
      </button>
    </div>
  </div>

  {#if status?.geo_degraded}
    <div class="alert warn row-between">
      <span>Geo bundle is degraded or has a pending recovery transaction.</span>
      <button class="btn btn-sm" onclick={() => onNavigate('updates')}>Open Updates</button>
    </div>
  {/if}

  <!-- KPI Grid -->
  <div class="grid-4">
    <div class="kpi">
      <span class="kpi-label">Active Exit Server</span>
      <span class="kpi-value" style="font-size: 18px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">
        {selectedServer ? selectedServer.name : 'None'}
      </span>
      <span class="kpi-meta tabular">
        {#if selectedHealth?.alive}
          Latency {formatMs(selectedHealth.delay)}
          {#if stateData?.routing.pinned}
            · Pinned
          {:else}
            · Auto leastPing
          {/if}
        {:else if (stateData?.servers.length ?? 0) === 0}
          Add a server to enable proxy
        {:else}
          No alive proxy server
        {/if}
      </span>
    </div>

    <div class="kpi">
      <span class="kpi-label">Live Traffic</span>
      <span class="kpi-value tabular">
        {stats?.available ? formatBytes(totalTraffic.down + totalTraffic.up) : '—'}
      </span>
      <span class="kpi-meta tabular">
        {#if stats?.available}
          ↓ {formatBytes(totalTraffic.down)} · ↑ {formatBytes(totalTraffic.up)}
        {:else}
          xray stats API unavailable
        {/if}
      </span>
    </div>

    <div class="kpi">
      <span class="kpi-label">Routing Policy</span>
      <span class="kpi-value" style="text-transform: capitalize">
        {stateData?.default_policy.mode ?? 'direct'}
      </span>
      <span class="kpi-meta tabular">
        {stateData?.devices.length ?? 0} device overrides
        {#if stateData?.default_policy.kill_switch}
          · Kill switch ON
        {/if}
      </span>
    </div>

    <div class="kpi">
      <span class="kpi-label">xray-core Runtime</span>
      <span class="kpi-value tabular">
        {stats?.available && stats.sys ? formatUptime(stats.sys.uptime) : '—'}
      </span>
      <span class="kpi-meta tabular">
        {#if stats?.available && stats.sys}
          RAM {formatBytes(stats.sys.alloc)} · {stats.sys.num_goroutine} goroutines
        {:else}
          Waiting for xray runtime
        {/if}
      </span>
    </div>
  </div>

  <!-- Live Interactive Data-Path Topology -->
  <TopologyFlow
    {status}
    {stateData}
    {stats}
    {selectedServer}
    selectedDelay={selectedHealth?.delay}
    {onNavigate}
  />

  <!-- Real-time Throughput & Traffic Split -->
  <div class="grid-2">
    <TrafficChart samples={rateHistory} available={Boolean(stats?.available)} />

    <div class="card stack" style="justify-content: space-between">
      <div class="stack" style="gap: 10px">
        <div>
          <h2 class="card-title">Proxy vs Direct Traffic Split</h2>
          <p class="card-sub">
            Cumulative xray-core outbound ratio (RouterOS FastTrack domestic bypass runs outside xray at wire speed)
          </p>
        </div>

        <div class="split-bar" aria-label="Traffic split bar">
          <div class="split-proxy" style="width: {trafficSplit.proxyPct}%"></div>
          <div class="split-direct" style="width: {trafficSplit.directPct}%"></div>
        </div>

        <div class="grid-2" style="gap: 10px">
          <div style="padding: 10px 12px; border-radius: 8px; background: var(--bg-subtle); border: 1px solid var(--border)">
            <div class="row" style="gap: 6px; margin-bottom: 4px">
              <span class="dot" style="background: var(--accent)"></span>
              <span class="hint" style="font-weight: 600">Proxied Tunnels</span>
            </div>
            <div class="mono tabular" style="font-size: 16px; font-weight: 700">
              {formatBytes(trafficSplit.proxied)}
            </div>
            <div class="hint tabular">{trafficSplit.proxyPct}% of xray volume</div>
          </div>
          <div style="padding: 10px 12px; border-radius: 8px; background: var(--bg-subtle); border: 1px solid var(--border)">
            <div class="row" style="gap: 6px; margin-bottom: 4px">
              <span class="dot ok"></span>
              <span class="hint" style="font-weight: 600">Direct Inside xray</span>
            </div>
            <div class="mono tabular" style="font-size: 16px; font-weight: 700">
              {formatBytes(trafficSplit.direct)}
            </div>
            <div class="hint tabular">{trafficSplit.directPct}% of xray volume</div>
          </div>
        </div>
      </div>

      <div class="row-between hint tabular" style="font-size: 12px; padding-top: 8px; border-top: 1px solid var(--border)">
        <span>Memory limit: xray 128 MiB · ctl 48 MiB · runner 24 MiB</span>
        <span>Hot-reload: active</span>
      </div>
    </div>
  </div>

  <!-- Server Health Table -->
  <div class="card">
    <div class="card-header">
      <div>
        <h2 class="card-title">Servers &amp; Observatory Health</h2>
        <p class="card-sub">Live latency, selection status, and per-outbound traffic counters</p>
      </div>
      <button class="btn btn-sm" onclick={() => onNavigate('servers')}>Manage Servers</button>
    </div>

    {#if serverRows.length === 0}
      <div class="empty-state stack" style="align-items: center">
        <p>No proxy servers configured yet.</p>
        <button class="btn btn-primary btn-sm" onclick={() => onNavigate('servers')}>
          <Icon name="plus" size={14} /> Add First Server
        </button>
      </div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Server</th>
              <th>Protocol / Endpoint</th>
              <th>Health</th>
              <th>Latency</th>
              <th>Traffic</th>
            </tr>
          </thead>
          <tbody>
            {#each serverRows as item (item.srv.id)}
              {@const ep = serverEndpoint(item.srv)}
              <tr>
                <td>
                  <div class="row" style="gap: 8px">
                    <span
                      class="dot {item.srv.disabled
                        ? ''
                        : item.h?.alive
                          ? 'ok'
                          : item.h
                            ? 'danger'
                            : 'warn'}"
                    ></span>
                    <span style="font-weight: 600">{item.srv.name}</span>
                    {#if item.selected}
                      <span class="badge ok">Active</span>
                    {/if}
                    {#if item.pinned}
                      <span class="badge accent">Pinned</span>
                    {/if}
                    {#if item.srv.disabled}
                      <span class="badge">Disabled</span>
                    {/if}
                    {#if item.srv.invalid}
                      <span class="badge danger" title={item.srv.invalid}>Invalid</span>
                    {/if}
                  </div>
                </td>
                <td class="mono" style="font-size: 12.5px; color: var(--text-muted)">
                  {ep.protocol} · {ep.endpoint}
                </td>
                <td>
                  {#if item.srv.disabled}
                    <span class="hint">disabled</span>
                  {:else if item.h?.alive}
                    <span class="badge ok">Alive</span>
                  {:else if item.h}
                    <span class="badge danger" title={item.h.last_error}>Down</span>
                  {:else}
                    <span class="badge">Probing</span>
                  {/if}
                </td>
                <td class="tabular">
                  {#if item.h?.alive}
                    <div class="row" style="gap: 8px">
                      <div class="latency-bar">
                        <div
                          class="latency-fill {delayClass(item.h.delay)}"
                          style="width: {delayPercent(item.h.delay)}%"
                        ></div>
                      </div>
                      <span style="font-size: 12.5px">{formatMs(item.h.delay)}</span>
                    </div>
                  {:else}
                    <span class="hint">—</span>
                  {/if}
                </td>
                <td class="tabular mono" style="font-size: 12px; color: var(--text-muted)">
                  {#if item.traffic}
                    ↓ {formatBytes(item.traffic.downlink)} / ↑ {formatBytes(item.traffic.uplink)}
                  {:else}
                    —
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  <!-- Recent Events -->
  <div class="card">
    <div class="card-header">
      <div>
        <h2 class="card-title">Recent Activity</h2>
        <p class="card-sub">Redacted control-plane and RouterOS reconciliation events</p>
      </div>
      <button class="btn btn-sm" onclick={() => onNavigate('events')}>View All Events</button>
    </div>

    {#if events.length === 0}
      <div class="empty-state">No events recorded yet in this process lifetime.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Kind</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {#each events.slice(-8).reverse() as ev (ev.seq)}
              <tr>
                <td class="mono tabular" style="color: var(--text-dim); width: 52px">{ev.seq}</td>
                <td class="tabular" style="white-space: nowrap; color: var(--text-muted); font-size: 12.5px">
                  {formatTime(ev.at)}
                </td>
                <td>
                  <span
                    class="badge {ev.kind === 'error' || ev.kind === 'degraded'
                      ? 'danger'
                      : ev.kind === 'warning'
                        ? 'warn'
                        : ev.kind === 'apply' || ev.kind === 'routeros'
                          ? 'ok'
                          : 'accent'}"
                  >
                    {ev.kind}
                  </span>
                </td>
                <td class="mono" style="font-size: 12.5px">{ev.message}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</div>
