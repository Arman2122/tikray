<script lang="ts">
  import type { Server, ServiceStats, ServiceStatus, State } from '../lib/api';
  import { formatBytes, formatMs } from '../lib/format';

  interface Props {
    status: ServiceStatus | null;
    stateData: State | null;
    stats: ServiceStats | null;
    selectedServer: Server | null;
    selectedDelay?: number;
    onNavigate: (view: string) => void;
  }

  let { status, stateData, stats, selectedServer, selectedDelay, onNavigate }: Props = $props();

  const routerTone = $derived(
    !status?.routeros
      ? ''
      : status.routeros.degraded
        ? 'danger'
        : status.routeros.pending || status.routeros.untested
          ? 'warn'
          : 'ok'
  );

  const runnerTone = $derived(
    status?.health.runner.reachable
      ? status.health.runner.routes_ok && status.health.runner.gateway_up
        ? 'ok'
        : 'warn'
      : 'danger'
  );

  const exitTone = $derived(
    status?.health.level === 'healthy'
      ? 'ok'
      : status?.health.level === 'degraded'
        ? 'warn'
        : selectedServer
          ? 'danger'
          : ''
  );

  const flowActive = $derived(status?.health.level === 'healthy' || status?.health.level === 'degraded');
</script>

<div class="card stack" style="gap: 12px">
  <div class="row-between">
    <div>
      <h2 class="card-title">Live Data-Path Topology</h2>
      <p class="card-sub">Click any stage to inspect or configure its policy, container, or exit node</p>
    </div>
    {#if stateData?.network.subnet}
      <span class="badge mono">Bridge {stateData.network.subnet}</span>
    {/if}
  </div>

  <div class="topo-grid">
    <button type="button" class="topo-node" onclick={() => onNavigate('devices')}>
      <div class="row-between" style="width: 100%">
        <span class="topo-kicker">1 · LAN</span>
        <span class="dot ok"></span>
      </div>
      <strong class="topo-title" style="text-transform: capitalize">
        {stateData?.default_policy.mode ?? 'direct'} default
      </strong>
      <span class="hint tabular">
        {stateData?.devices.length ?? 0} device rule{(stateData?.devices.length ?? 0) === 1 ? '' : 's'}
        {stateData?.default_policy.kill_switch ? ' · Kill switch' : ''}
      </span>
    </button>

    <div class="topo-link {flowActive ? 'live' : ''}" aria-hidden="true"></div>

    <button type="button" class="topo-node" onclick={() => onNavigate('settings')}>
      <div class="row-between" style="width: 100%">
        <span class="topo-kicker">2 · RouterOS</span>
        <span class="dot {routerTone}"></span>
      </div>
      <strong class="topo-title mono">
        {#if status?.routeros?.version}
          v{status.routeros.version}
        {:else if status?.routeros}
          Managed
        {:else}
          Standalone
        {/if}
      </strong>
      <span class="hint">
        {#if status?.routeros?.degraded}
          {status.routeros.degraded}
        {:else if status?.routeros?.untested}
          Forward-compat (untested)
        {:else if status?.routeros}
          FastTrack + policy verified
        {:else}
          Local daemon mode
        {/if}
      </span>
    </button>

    <div class="topo-link {flowActive ? 'live' : ''}" aria-hidden="true"></div>

    <button type="button" class="topo-node" onclick={() => onNavigate('updates')}>
      <div class="row-between" style="width: 100%">
        <span class="topo-kicker">3 · xray-core</span>
        <span class="dot {runnerTone}"></span>
      </div>
      <strong class="topo-title mono">
        {status?.core ? `v${status.core}` : 'Offline'}
      </strong>
      <span class="hint tabular">
        {#if stats?.available && stats.sys}
          {formatBytes(stats.sys.alloc)} RAM · TUN up
        {:else}
          {status?.health.runner.reachable ? 'Runner reachable' : 'Runner unreachable'}
        {/if}
      </span>
    </button>

    <div class="topo-link {exitTone === 'ok' ? 'live' : ''}" aria-hidden="true"></div>

    <button type="button" class="topo-node" onclick={() => onNavigate('servers')}>
      <div class="row-between" style="width: 100%">
        <span class="topo-kicker">4 · Active Exit</span>
        <span class="dot {exitTone}"></span>
      </div>
      <strong class="topo-title" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%">
        {selectedServer ? selectedServer.name : 'Direct / None'}
      </strong>
      <span class="hint tabular">
        {#if selectedDelay && selectedDelay > 0}
          {formatMs(selectedDelay)} · {stateData?.routing.pinned ? 'Pinned' : 'leastPing'}
        {:else if selectedServer}
          Probing exit…
        {:else}
          Add a server to proxy
        {/if}
      </span>
    </button>
  </div>
</div>
