<script lang="ts">
  import {
    api,
    ApiError,
    type PingResult,
    type RefreshResult,
    type Server,
    type ServerConfigView,
    type ServiceStatus,
    type State,
    type Subscription
  } from '../lib/api';
  import { formatTime, friendlyError, serverEndpoint } from '../lib/format';
  import { inspectShareLink } from '../lib/linkPreview';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';
  import ServerConfigEditor, { type ServerEditorResult } from '../components/ServerConfigEditor.svelte';

  interface Props {
    status: ServiceStatus | null;
    stateData: State | null;
    onRefresh: () => Promise<void>;
  }

  let { status, stateData, onRefresh }: Props = $props();

  let tab = $state<'servers' | 'subscriptions'>('servers');
  let search = $state('');
  let filter = $state<'all' | 'enabled' | 'disabled' | 'degraded'>('all');

  // Add Server modal
  let showAddServer = $state(false);
  let addMode = $state<'editor' | 'bulk'>('editor');
  let linkInput = $state('');
  let serverName = $state('');
  let saving = $state(false);

  // Edit Server modal (v2rayN-style Visual + JSON editor)
  let editingServer = $state<Server | null>(null);
  let editConfig = $state<ServerConfigView | null>(null);
  let loadingEditConfig = $state(false);
  let editLoadError = $state('');

  // Add Subscription modal
  let showAddSub = $state(false);
  let subName = $state('');
  let subURL = $state('');
  let subInterval = $state('24h');

  // Refresh, connect & latency test state
  let refreshingId = $state('');
  let lastRefresh = $state<{ id: string; result: RefreshResult } | null>(null);
  let pingingId = $state('');
  let pinningId = $state('');
  let pingingAll = $state(false);
  let localPings = $state<Record<string, PingResult>>({});

  const healthMap = $derived(new Map((status?.health.servers ?? []).map((h) => [h.id, h])));
  const subMap = $derived(new Map((stateData?.subscriptions ?? []).map((s) => [s.id, s])));
  const pingMap = $derived({ ...(status?.pings ?? {}), ...localPings });

  function serverLatency(srvId: string, obsNs?: number): { ms: number; kind: string; detail: string } | null {
    const p = pingMap[srvId];
    const parts: string[] = [];
    if (p?.http_ms && p.http_ms > 0) parts.push(`HTTP 204 ${p.http_ms} ms`);
    if (p?.tcp_ms && p.tcp_ms > 0) parts.push(`TCP ${p.tcp_ms} ms`);
    const obsMs = obsNs && obsNs > 0 ? Math.round(obsNs / 1_000_000) : p?.obs_ms;
    if (obsMs && obsMs > 0) parts.push(`Cold E2E ${obsMs} ms`);

    if (p?.http_ms && p.http_ms > 0) return { ms: p.http_ms, kind: 'HTTP', detail: parts.join(' · ') };
    if (p?.tcp_ms && p.tcp_ms > 0) return { ms: p.tcp_ms, kind: 'TCP', detail: parts.join(' · ') };
    return null;
  }

  function latencyBadgeTone(ms: number): 'ok' | 'warn' | 'danger' {
    if (ms <= 180) return 'ok';
    if (ms <= 450) return 'warn';
    return 'danger';
  }

  async function pingOne(srv: Server): Promise<void> {
    pingingId = srv.id;
    try {
      const res = await api.pingServer(srv.id);
      localPings = { ...localPings, [srv.id]: res };
      if (res.alive) {
        const msg = res.http_ms
          ? `${srv.name}: HTTP ${res.http_ms} ms (TCP ${res.tcp_ms} ms)`
          : `${srv.name}: TCP ${res.tcp_ms} ms`;
        toast.ok(msg);
      } else {
        toast.warn(`${srv.name}: ${res.error || 'unreachable'}`);
      }
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Latency test failed'));
    } finally {
      pingingId = '';
    }
  }

  async function pingAll(): Promise<void> {
    pingingAll = true;
    try {
      const list = await api.pingAllServers();
      const next = { ...localPings };
      for (const r of list) next[r.id] = r;
      localPings = next;
      const alive = list.filter((r) => r.alive);
      if (alive.length > 0) {
        const best = alive.reduce((a, b) =>
          (a.http_ms || a.tcp_ms || 99999) <= (b.http_ms || b.tcp_ms || 99999) ? a : b
        );
        toast.ok(`Tested ${list.length} server${list.length === 1 ? '' : 's'} · fastest ${best.http_ms || best.tcp_ms} ms.`);
      } else {
        toast.warn(`Tested ${list.length} server${list.length === 1 ? '' : 's'} · none reachable.`);
      }
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Latency test failed'));
    } finally {
      pingingAll = false;
    }
  }

  const linkPreviews = $derived.by(() => {
    return linkInput
      .split(/\r?\n/)
      .map((l) => inspectShareLink(l))
      .filter((p): p is NonNullable<typeof p> => p !== null);
  });

  const filteredServers = $derived.by(() => {
    const q = search.trim().toLowerCase();
    return (stateData?.servers ?? []).filter((srv) => {
      if (filter === 'enabled' && srv.disabled) return false;
      if (filter === 'disabled' && !srv.disabled) return false;
      if (filter === 'degraded' && !srv.invalid && !srv.untested) return false;
      if (!q) return true;
      const ep = serverEndpoint(srv);
      return (
        srv.name.toLowerCase().includes(q) ||
        srv.id.toLowerCase().includes(q) ||
        ep.protocol.toLowerCase().includes(q) ||
        ep.endpoint.toLowerCase().includes(q)
      );
    });
  });

  function autoPingCreated(ids: string[]): void {
    if (ids.length === 0) return;
    Promise.allSettled(
      ids.slice(0, 6).map((cid) =>
        api.pingServer(cid).then((res) => {
          localPings = { ...localPings, [cid]: res };
        })
      )
    ).then(() => {
      onRefresh();
    });
  }

  async function addFromEditor(res: ServerEditorResult): Promise<void> {
    saving = true;
    try {
      const payload: { name?: string; link?: string; outbound?: unknown } = {};
      if (res.name) payload.name = res.name;
      if (res.link) {
        payload.link = res.link;
      } else if (res.outbound) {
        payload.outbound = res.outbound;
      }
      const srv = await api.addServer(payload);
      toast.ok(`Added ${srv.name} — measuring latency…`);
      showAddServer = false;
      await onRefresh();
      autoPingCreated([srv.id]);
    } catch (err) {
      toast.err(friendlyError(err, 'Could not add server'));
    } finally {
      saving = false;
    }
  }

  async function addBulkSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    saving = true;
    try {
      const lines = linkInput
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      if (lines.length === 0) {
        toast.warn('Paste at least one share link (vless://, vmess://, trojan://, ss://).');
        return;
      }
      const createdIds: string[] = [];
      let added = 0;
      let failed = 0;
      let firstErr = '';
      for (const line of lines) {
        try {
          const srv = await api.addServer({
            link: line,
            name: lines.length === 1 && serverName.trim() ? serverName.trim() : undefined
          });
          createdIds.push(srv.id);
          added++;
        } catch (err) {
          failed++;
          if (!firstErr) {
            firstErr = friendlyError(err, 'Failed to add server');
          }
        }
      }
      if (added > 0) {
        toast.ok(`Added ${added} server${added === 1 ? '' : 's'}${failed > 0 ? ` (${failed} failed)` : ''} — measuring latency…`);
      }
      if (failed > 0 && added === 0) {
        toast.err(firstErr);
        return;
      }
      showAddServer = false;
      linkInput = '';
      serverName = '';
      await onRefresh();
      autoPingCreated(createdIds);
    } catch (err) {
      toast.err(friendlyError(err, 'Could not add servers'));
    } finally {
      saving = false;
    }
  }

  async function toggleServer(srv: Server): Promise<void> {
    try {
      await api.patchServer(srv.id, { disabled: !srv.disabled });
      toast.ok(`${srv.disabled ? 'Enabled' : 'Disabled'} ${srv.name}.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Update failed');
    }
  }

  async function togglePin(srv: Server): Promise<void> {
    if (!stateData) return;
    const pinned = stateData.routing.pinned === srv.id ? '' : srv.id;
    pinningId = srv.id;
    try {
      await api.setRouting({ ...stateData.routing, pinned: pinned || undefined });
      // Apply immediately via hot-reload so xray connects to the selected server right away.
      try {
        await api.applyNow();
      } catch {
        // Reconciler loop will still apply if runner was temporarily busy.
      }
      await onRefresh();
      if (pinned) {
        // Measure live HTTP 204 latency on connect.
        pingingId = srv.id;
        try {
          const res = await api.pingServer(srv.id);
          localPings = { ...localPings, [srv.id]: res };
          if (res.alive) {
            const msg = res.http_ms
              ? `Connected to ${srv.name} · HTTP ${res.http_ms} ms (TCP ${res.tcp_ms} ms)`
              : `Connected to ${srv.name} · TCP ${res.tcp_ms} ms`;
            toast.ok(msg);
          } else {
            toast.warn(`Pinned ${srv.name}, but latency probe failed: ${res.error || 'unreachable'}`);
          }
          await onRefresh();
        } finally {
          pingingId = '';
        }
      } else {
        toast.ok('Cleared server pin (auto leastPing).');
      }
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not update pin');
    } finally {
      pinningId = '';
    }
  }

  async function openEditServer(srv: Server): Promise<void> {
    editingServer = srv;
    editConfig = null;
    editLoadError = '';
    loadingEditConfig = true;
    try {
      editConfig = await api.getServerConfig(srv.id);
    } catch (err) {
      editLoadError = friendlyError(err, 'Could not load server configuration');
    } finally {
      loadingEditConfig = false;
    }
  }

  async function saveEditedConfig(res: ServerEditorResult): Promise<void> {
    if (!editingServer) return;
    saving = true;
    try {
      const patch: { name?: string; disabled?: boolean; link?: string; outbound?: unknown } = {};
      if (res.name && res.name !== editingServer.name) {
        patch.name = res.name;
      }
      if (res.disabled !== Boolean(editingServer.disabled)) {
        patch.disabled = res.disabled;
      }
      if (res.link) {
        patch.link = res.link;
      } else if (res.outbound) {
        patch.outbound = res.outbound;
      }
      const targetId = editingServer.id;
      const targetName = res.name || editingServer.name;
      await api.patchServer(targetId, patch);
      toast.ok(`Updated ${targetName}.`);
      editingServer = null;
      editConfig = null;
      await onRefresh();
      if (!res.disabled) {
        api
          .pingServer(targetId)
          .then((pr) => {
            localPings = { ...localPings, [targetId]: pr };
            onRefresh();
          })
          .catch(() => {});
      }
    } catch (err) {
      toast.err(friendlyError(err, 'Could not update server'));
    } finally {
      saving = false;
    }
  }

  async function removeServer(srv: Server): Promise<void> {
    if (!confirm(`Delete server "${srv.name}" (${srv.id})?`)) return;
    try {
      await api.deleteServer(srv.id);
      toast.ok(`Removed server ${srv.name}.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Delete failed');
    }
  }

  async function addSubscriptionSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    saving = true;
    try {
      await api.addSubscription(subName.trim(), subURL.trim(), subInterval);
      toast.ok('Subscription added.');
      showAddSub = false;
      subName = '';
      subURL = '';
      subInterval = '24h';
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not add subscription');
    } finally {
      saving = false;
    }
  }

  async function toggleSub(sub: Subscription): Promise<void> {
    try {
      await api.patchSubscription(sub.id, { disabled: !sub.disabled });
      toast.ok(`${sub.disabled ? 'Enabled' : 'Disabled'} subscription ${sub.name}.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not update subscription');
    }
  }

  async function refreshSub(sub: Subscription): Promise<void> {
    refreshingId = sub.id;
    try {
      const res = await api.refreshSubscription(sub.id);
      lastRefresh = { id: sub.id, result: res };
      toast.ok(`Refreshed ${sub.name}: +${res.added} added, ${res.updated} updated, -${res.removed} removed.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Subscription refresh failed');
    } finally {
      refreshingId = '';
    }
  }

  async function removeSub(sub: Subscription): Promise<void> {
    if (!confirm(`Delete subscription "${sub.name}" and its imported servers?`)) return;
    try {
      await api.deleteSubscription(sub.id);
      toast.ok(`Removed subscription ${sub.name}.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Delete failed');
    }
  }
</script>

<div class="stack-lg">
  <div class="row-between">
    <div class="tabs" role="tablist">
      <button class="tab {tab === 'servers' ? 'active' : ''}" role="tab" onclick={() => (tab = 'servers')}>
        Servers ({stateData?.servers.length ?? 0})
      </button>
      <button
        class="tab {tab === 'subscriptions' ? 'active' : ''}"
        role="tab"
        onclick={() => (tab = 'subscriptions')}
      >
        Subscriptions ({stateData?.subscriptions.length ?? 0})
      </button>
    </div>

    {#if tab === 'servers'}
      <div class="row" style="gap: 8px">
        <button
          type="button"
          class="btn"
          disabled={pingingAll || (stateData?.servers.length ?? 0) === 0}
          onclick={pingAll}
        >
          <Icon name="zap" size={14} />
          {pingingAll ? 'Testing Latency…' : 'Test All Latency'}
        </button>
        <button type="button" class="btn btn-primary" onclick={() => (showAddServer = true)}>
          <Icon name="plus" size={14} /> Add Server
        </button>
      </div>
    {:else}
      <button type="button" class="btn btn-primary" onclick={() => (showAddSub = true)}>
        <Icon name="plus" size={14} /> Add Subscription
      </button>
    {/if}
  </div>

  {#if tab === 'servers'}
    <div class="card stack">
      <div class="row-between">
        <div class="row">
          {#each ['all', 'enabled', 'disabled', 'degraded'] as const as f}
            <button class="chip {filter === f ? 'active' : ''}" onclick={() => (filter = f)}>
              {f}
            </button>
          {/each}
        </div>
        <input
          class="input search-input"
          type="search"
          placeholder="Search name, ID, host…"
          bind:value={search}
        />
      </div>

      {#if filteredServers.length === 0}
        <div class="empty-state">
          No servers match this filter. Paste a <code>vless://</code>, <code>vmess://</code>, <code>trojan://</code>,
          or <code>ss://</code> share link to get started.
        </div>
      {:else}
        <div class="table-wrap">
          <table class="responsive-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Protocol / Host</th>
                <th>Status</th>
                <th>Origin</th>
                <th style="text-align: right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredServers as srv (srv.id)}
                {@const h = healthMap.get(srv.id)}
                {@const p = pingMap[srv.id]}
                {@const lat = serverLatency(srv.id, h?.delay)}
                {@const ep = serverEndpoint(srv)}
                {@const isPinned = stateData?.routing.pinned === srv.id}
                {@const isSelected = status?.health.selected === srv.id}
                {@const runnerOnline = Boolean(status?.health.runner.reachable)}
                {@const isReachable = Boolean(h?.alive || p?.alive)}
                {@const hasFailedProbe = Boolean(
                  !isReachable && ((h && runnerOnline && !srv.untested && (h.last_error || h.last_seen)) || (p && !p.alive && p.error))
                )}
                <tr>
                  <td data-label="Server" class="cell-primary">
                    <div class="stack" style="gap: 3px">
                      <div class="row" style="gap: 7px">
                        <span class="dot {srv.disabled ? '' : isReachable ? 'ok' : hasFailedProbe ? 'danger' : 'warn'}"></span>
                        <span style="font-weight: 600">{srv.name}</span>
                        <span class="mono hint" style="font-size: 11px">{srv.id}</span>
                        {#if isSelected}
                          <span class="badge ok">Active</span>
                        {/if}
                        {#if isPinned}
                          <span class="badge accent">Pinned</span>
                        {/if}
                      </div>
                      {#if srv.invalid}
                        <span style="font-size: 12px; color: var(--danger)">{srv.invalid}</span>
                      {:else if srv.untested && !p}
                        <span style="font-size: 12px; color: var(--warn)">Untested (click Test Latency or wait for core)</span>
                      {:else if hasFailedProbe && (p?.error || h?.last_error)}
                        <span style="font-size: 12px; color: var(--danger)">{p?.error || h?.last_error}</span>
                      {/if}
                    </div>
                  </td>
                  <td data-label="Endpoint" class="mono" style="font-size: 12.5px; color: var(--text-muted); word-break: break-all">
                    {ep.protocol} · {ep.endpoint}
                  </td>
                  <td data-label="Latency" class="tabular">
                    {#if srv.disabled}
                      <span class="badge">Disabled</span>
                    {:else if pingingId === srv.id}
                      <span class="badge accent">Testing…</span>
                    {:else if lat}
                      <span class="badge {latencyBadgeTone(lat.ms)} mono" title={lat.detail}>
                        {lat.ms} ms <span style="opacity: 0.7; font-weight: 500">{lat.kind}</span>
                      </span>
                    {:else if isReachable}
                      <span class="badge ok" title="Alive via observatory · click Ping for TCP/HTTP latency">Online</span>
                    {:else if hasFailedProbe}
                      <span class="badge danger" title={p?.error || h?.last_error}>Unreachable</span>
                    {:else if srv.untested}
                      <span class="badge warn">Untested</span>
                    {:else}
                      <span class="badge warn">Pending</span>
                    {/if}
                  </td>
                  <td data-label="Origin">
                    {#if srv.subscription}
                      <span class="badge purple">
                        {subMap.get(srv.subscription)?.name ?? srv.subscription}
                      </span>
                    {:else}
                      <span class="hint">Manual</span>
                    {/if}
                  </td>
                  <td data-label="Actions" class="cell-actions" style="text-align: right">
                    <div class="row action-row" style="justify-content: flex-end; gap: 5px">
                      <button
                        type="button"
                        class="btn btn-sm"
                        title="Test TCP & HTTP latency (v2rayN-style)"
                        disabled={srv.disabled || Boolean(srv.invalid) || pingingId === srv.id}
                        onclick={() => pingOne(srv)}
                      >
                        <Icon name="zap" size={13} />
                        Ping
                      </button>
                      <button
                        type="button"
                        class="btn btn-sm {isPinned ? 'btn-primary' : ''}"
                        title={isPinned ? 'Unpin server (return to auto)' : 'Connect & pin as active exit'}
                        disabled={srv.disabled || pinningId === srv.id}
                        onclick={() => togglePin(srv)}
                      >
                        <Icon name="pin" size={13} />
                        {pinningId === srv.id ? 'Connecting…' : isPinned ? 'Unpin' : 'Pin'}
                      </button>
                      <button type="button" class="btn btn-sm" onclick={() => toggleServer(srv)}>
                        {srv.disabled ? 'Enable' : 'Disable'}
                      </button>
                      <button type="button" class="btn btn-sm" onclick={() => openEditServer(srv)}>Edit</button>
                      <button type="button" class="btn btn-sm btn-danger" onclick={() => removeServer(srv)} aria-label="Delete server">
                        <Icon name="trash" size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {:else}
    <div class="card stack">
      {#if (stateData?.subscriptions.length ?? 0) === 0}
        <div class="empty-state">
          No subscriptions configured. Add an HTTPS subscription feed to auto-sync servers on a schedule.
        </div>
      {:else}
        <div class="table-wrap">
          <table class="responsive-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Interval</th>
                <th>Last Fetch</th>
                <th>Status</th>
                <th style="text-align: right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each stateData?.subscriptions ?? [] as sub (sub.id)}
                <tr>
                  <td data-label="Subscription" class="cell-primary">
                    <div style="font-weight: 600">{sub.name}</div>
                    <div class="hint mono" style="font-size: 11px">
                      {sub.id} · URL hidden for security
                    </div>
                  </td>
                  <td data-label="Interval" class="mono">{sub.interval}</td>
                  <td data-label="Last Fetch" class="tabular" style="font-size: 12.5px; color: var(--text-muted)">
                    {formatTime(sub.last_fetch)}
                  </td>
                  <td data-label="Status">
                    {#if sub.disabled}
                      <span class="badge">Paused</span>
                    {:else if sub.last_error}
                      <span class="badge danger" title={sub.last_error}>Error</span>
                    {:else}
                      <span class="badge ok">Active</span>
                    {/if}
                    {#if sub.last_error}
                      <div class="hint" style="color: var(--danger); margin-top: 3px; max-width: 280px">
                        {sub.last_error}
                      </div>
                    {/if}
                  </td>
                  <td data-label="Actions" class="cell-actions" style="text-align: right">
                    <div class="row action-row" style="justify-content: flex-end; gap: 6px">
                      <button
                        class="btn btn-sm btn-primary"
                        disabled={refreshingId === sub.id}
                        onclick={() => refreshSub(sub)}
                      >
                        <Icon name="refresh" size={13} />
                        {refreshingId === sub.id ? 'Refreshing…' : 'Refresh'}
                      </button>
                      <button class="btn btn-sm" onclick={() => toggleSub(sub)}>
                        {sub.disabled ? 'Resume' : 'Pause'}
                      </button>
                      <button class="btn btn-sm btn-danger" onclick={() => removeSub(sub)} aria-label="Delete subscription">
                        <Icon name="trash" size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}

      {#if lastRefresh}
        <div class="alert ok stack" style="gap: 6px">
          <div class="row-between">
            <strong>
              Last Refresh Summary (via {lastRefresh.result.via || 'direct'}): +{lastRefresh.result.added} added,
              {lastRefresh.result.updated} updated, -{lastRefresh.result.removed} removed, {lastRefresh.result.kept} kept
            </strong>
            <button class="btn btn-ghost btn-sm" onclick={() => (lastRefresh = null)}>Dismiss</button>
          </div>
          {#if lastRefresh.result.skipped.length > 0}
            <div class="hint">Skipped {lastRefresh.result.skipped.length} line(s):</div>
            <ul style="margin: 0; padding-left: 18px; font-size: 12px">
              {#each lastRefresh.result.skipped.slice(0, 8) as sk}
                <li class="mono">{sk.line}: {sk.reason}</li>
              {/each}
            </ul>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</div>

<!-- Add Server Modal -->
{#if showAddServer}
  <Modal title="Add Proxy Server" wide={true} onClose={() => (showAddServer = false)}>
    <div class="row-between" style="padding-bottom: 6px; border-bottom: 1px solid var(--border)">
      <div class="tabs">
        <button type="button" class="tab {addMode === 'editor' ? 'active' : ''}" onclick={() => (addMode = 'editor')}>
          Server Editor (Visual / JSON / Link)
        </button>
        <button type="button" class="tab {addMode === 'bulk' ? 'active' : ''}" onclick={() => (addMode = 'bulk')}>
          Bulk Share Links
        </button>
      </div>
    </div>

    {#if addMode === 'editor'}
      <ServerConfigEditor
        mode="add"
        {saving}
        onCancel={() => (showAddServer = false)}
        onSubmit={addFromEditor}
      />
    {:else}
      <form class="stack" onsubmit={addBulkSubmit}>
        <div class="field">
          <label for="srv-links">Share Link(s) — One Per Line</label>
          <textarea
            id="srv-links"
            class="textarea"
            style="min-height: 130px"
            placeholder="vless://...&#10;trojan://...&#10;(Paste one or multiple lines for bulk import)"
            bind:value={linkInput}
            required
          ></textarea>
          <span class="hint">
            Supports VLESS (TLS / REALITY / Vision / XHTTP + Extra / PQ ML-DSA-65 / PQ Encryption / TLS ECH / WS /
            gRPC / HTTPUpgrade), VMess, Trojan, and Shadowsocks.
          </span>
        </div>
        {#if linkPreviews.length > 0}
          <div class="preview-box">
            <div class="row-between">
              <span class="label">Live Link Preview ({linkPreviews.length})</span>
              <span class="hint">Parsed locally in browser</span>
            </div>
            {#each linkPreviews.slice(0, 4) as pv}
              <div class="stack" style="gap: 4px; padding-top: 4px; border-top: 1px solid var(--border)">
                <div class="row-between">
                  <div class="row" style="gap: 6px">
                    <span class="dot {pv.valid ? 'ok' : 'danger'}"></span>
                    <strong style="font-size: 12.5px">{pv.name || pv.scheme}</strong>
                    {#if pv.endpoint}
                      <span class="mono hint" style="font-size: 11.5px">{pv.endpoint}</span>
                    {/if}
                  </div>
                  <div class="row" style="gap: 4px">
                    {#each pv.badges as b}
                      <span class="badge {b.tone}" style="font-size: 10.5px; padding: 1px 7px">{b.label}</span>
                    {/each}
                  </div>
                </div>
                {#if pv.warning}
                  <span style="font-size: 11.5px; color: var(--warn)">{pv.warning}</span>
                {/if}
              </div>
            {/each}
            {#if linkPreviews.length > 4}
              <span class="hint">+{linkPreviews.length - 4} more link(s) queued for bulk import</span>
            {/if}
          </div>
        {/if}
        <div class="field">
          <label for="srv-name">Custom Alias (optional, single link only)</label>
          <input id="srv-name" class="input" placeholder="Auto from #fragment" bind:value={serverName} />
        </div>
        <div class="row" style="justify-content: flex-end">
          <button type="button" class="btn" onclick={() => (showAddServer = false)}>Cancel</button>
          <button type="submit" class="btn btn-primary" disabled={saving}>
            {saving ? 'Validating & Importing…' : 'Import Links'}
          </button>
        </div>
      </form>
    {/if}
  </Modal>
{/if}

<!-- Edit Server Modal (v2rayN-style Visual Config + Live JSON Editor) -->
{#if editingServer}
  {@const editEp = serverEndpoint(editingServer)}
  {@const editHealth = healthMap.get(editingServer.id)}
  {@const editLat = serverLatency(editingServer.id, editHealth?.delay)}
  {@const editPinned = stateData?.routing.pinned === editingServer.id}
  <Modal title="{editEp.protocol.toUpperCase()} · {editingServer.name}" wide={true} onClose={() => ((editingServer = null), (editConfig = null))}>
    <!-- Live Server Summary Strip -->
    <div class="editor-section" style="padding: 10px 14px; gap: 6px">
      <div class="row-between" style="flex-wrap: wrap; gap: 8px">
        <div class="row" style="gap: 8px; flex-wrap: wrap">
          <span class="badge accent mono">{editEp.protocol}</span>
          <span class="mono" style="font-size: 12.5px; font-weight: 600; word-break: break-all">{editEp.endpoint}</span>
          <span class="mono hint" style="font-size: 11px">ID: {editingServer.id}</span>
        </div>
        <div class="row" style="gap: 6px; flex-wrap: wrap">
          {#if editLat}
            <span class="badge {latencyBadgeTone(editLat.ms)} tabular mono" title={editLat.detail}>
              {editLat.ms} ms {editLat.kind}
            </span>
          {:else if editHealth?.alive}
            <span class="badge ok">Online</span>
          {:else if editHealth?.last_error}
            <span class="badge danger">{editHealth.last_error}</span>
          {:else}
            <span class="badge warn">Pending</span>
          {/if}
          {#if editPinned}
            <span class="badge accent">Pinned</span>
          {/if}
          <span class="badge">
            {editingServer.subscription ? subMap.get(editingServer.subscription)?.name ?? 'Subscription' : 'Manual'}
          </span>
        </div>
      </div>
    </div>

    {#if loadingEditConfig}
      <div class="empty-state" style="padding: 36px 16px">Loading server configuration…</div>
    {:else if editLoadError}
      <div class="alert danger">{editLoadError}</div>
    {:else if editConfig}
      <ServerConfigEditor
        mode="edit"
        initialName={editConfig.name}
        initialDisabled={Boolean(editConfig.disabled)}
        initialOutbound={editConfig.outbound}
        {saving}
        onCancel={() => ((editingServer = null), (editConfig = null))}
        onSubmit={saveEditedConfig}
      />
    {/if}
  </Modal>
{/if}

<!-- Add Subscription Modal -->
{#if showAddSub}
  <Modal title="Add Subscription Feed" onClose={() => (showAddSub = false)}>
    <form class="stack" onsubmit={addSubscriptionSubmit}>
      <div class="field">
        <label for="sub-name">Name (optional)</label>
        <input id="sub-name" class="input" placeholder="e.g. Primary Provider" bind:value={subName} />
      </div>
      <div class="field">
        <label for="sub-url">Subscription HTTPS URL</label>
        <input
          id="sub-url"
          class="input mono"
          type="url"
          placeholder="https://provider.example/sub/..."
          bind:value={subURL}
          required
        />
        <span class="hint">Stored securely on disk; the URL is never echoed back in API responses or logs.</span>
      </div>
      <div class="field">
        <label for="sub-interval">Auto-Refresh Interval</label>
        <select id="sub-interval" class="select" bind:value={subInterval}>
          <option value="6h">Every 6 hours</option>
          <option value="12h">Every 12 hours</option>
          <option value="24h">Every 24 hours</option>
          <option value="72h">Every 3 days</option>
        </select>
      </div>
      <div class="row" style="justify-content: flex-end">
        <button type="button" class="btn" onclick={() => (showAddSub = false)}>Cancel</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>
          {saving ? 'Saving…' : 'Add Subscription'}
        </button>
      </div>
    </form>
  </Modal>
{/if}
