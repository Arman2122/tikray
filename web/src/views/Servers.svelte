<script lang="ts">
  import { api, ApiError, type RefreshResult, type Server, type ServiceStatus, type State, type Subscription } from '../lib/api';
  import { formatMs, formatTime, serverEndpoint } from '../lib/format';
  import { inspectShareLink } from '../lib/linkPreview';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';

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
  let addMode = $state<'link' | 'json'>('link');
  let linkInput = $state('');
  let serverName = $state('');
  let outboundJSON = $state('');
  let saving = $state(false);

  // Edit Server modal
  let editingServer = $state<Server | null>(null);
  let editName = $state('');
  let editLink = $state('');

  // Add Subscription modal
  let showAddSub = $state(false);
  let subName = $state('');
  let subURL = $state('');
  let subInterval = $state('24h');

  // Refresh summary
  let refreshingId = $state('');
  let lastRefresh = $state<{ id: string; result: RefreshResult } | null>(null);

  const healthMap = $derived(new Map((status?.health.servers ?? []).map((h) => [h.id, h])));
  const subMap = $derived(new Map((stateData?.subscriptions ?? []).map((s) => [s.id, s])));

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

  async function addServerSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    saving = true;
    try {
      if (addMode === 'link') {
        const lines = linkInput
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
        if (lines.length === 0) {
          toast.warn('Paste at least one share link (vless://, vmess://, trojan://, ss://).');
          return;
        }
        let added = 0;
        let failed = 0;
        let firstErr = '';
        for (const line of lines) {
          try {
            await api.addServer({
              link: line,
              name: lines.length === 1 && serverName.trim() ? serverName.trim() : undefined
            });
            added++;
          } catch (err) {
            failed++;
            if (!firstErr) {
              firstErr = err instanceof ApiError ? err.detail || err.message : 'Failed to add server';
            }
          }
        }
        if (added > 0) {
          toast.ok(`Added ${added} server${added === 1 ? '' : 's'}${failed > 0 ? ` (${failed} failed)` : ''}.`);
        }
        if (failed > 0 && added === 0) {
          toast.err(firstErr);
          return;
        }
      } else {
        let parsed: unknown;
        try {
          parsed = JSON.parse(outboundJSON);
        } catch {
          toast.err('Outbound must be valid JSON.');
          return;
        }
        if (!serverName.trim()) {
          toast.err('A server name is required for raw outbound JSON.');
          return;
        }
        await api.addServer({ name: serverName.trim(), outbound: parsed });
        toast.ok(`Added server "${serverName.trim()}".`);
      }
      showAddServer = false;
      linkInput = '';
      serverName = '';
      outboundJSON = '';
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not add server');
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
    try {
      await api.setRouting({ ...stateData.routing, pinned: pinned || undefined });
      toast.ok(pinned ? `Pinned exit to ${srv.name}.` : 'Cleared server pin (auto leastPing).');
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not update pin');
    }
  }

  function openEditServer(srv: Server): void {
    editingServer = srv;
    editName = srv.name;
    editLink = '';
  }

  async function saveEditServer(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (!editingServer) return;
    saving = true;
    try {
      const patch: { name?: string; link?: string } = {};
      if (editName.trim() && editName.trim() !== editingServer.name) {
        patch.name = editName.trim();
      }
      if (editLink.trim()) {
        patch.link = editLink.trim();
      }
      if (Object.keys(patch).length === 0) {
        editingServer = null;
        return;
      }
      await api.patchServer(editingServer.id, patch);
      toast.ok(`Updated ${editName.trim() || editingServer.name}.`);
      editingServer = null;
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not update server');
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
      <button class="btn btn-primary" onclick={() => (showAddServer = true)}>
        <Icon name="plus" size={14} /> Add Server
      </button>
    {:else}
      <button class="btn btn-primary" onclick={() => (showAddSub = true)}>
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
          class="input"
          style="max-width: 260px"
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
          <table>
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
                {@const ep = serverEndpoint(srv)}
                {@const isPinned = stateData?.routing.pinned === srv.id}
                {@const isSelected = status?.health.selected === srv.id}
                {@const runnerOnline = Boolean(status?.health.runner.reachable)}
                {@const hasFailedProbe = Boolean(h && !h.alive && runnerOnline && !srv.untested && (h.last_error || h.last_seen))}
                <tr>
                  <td>
                    <div class="stack" style="gap: 3px">
                      <div class="row" style="gap: 7px">
                        <span class="dot {srv.disabled ? '' : h?.alive ? 'ok' : hasFailedProbe ? 'danger' : 'warn'}"></span>
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
                      {:else if srv.untested}
                        <span style="font-size: 12px; color: var(--warn)">Untested (will verify when core runs)</span>
                      {/if}
                    </div>
                  </td>
                  <td class="mono" style="font-size: 12.5px; color: var(--text-muted)">
                    {ep.protocol} · {ep.endpoint}
                  </td>
                  <td class="tabular">
                    {#if srv.disabled}
                      <span class="badge">Disabled</span>
                    {:else if h?.alive}
                      <span class="badge ok">{formatMs(h.delay)}</span>
                    {:else if hasFailedProbe}
                      <span class="badge danger" title={h?.last_error}>Unreachable</span>
                    {:else if srv.untested}
                      <span class="badge warn">Untested</span>
                    {:else}
                      <span class="badge warn">Pending</span>
                    {/if}
                  </td>
                  <td>
                    {#if srv.subscription}
                      <span class="badge purple">
                        {subMap.get(srv.subscription)?.name ?? srv.subscription}
                      </span>
                    {:else}
                      <span class="hint">Manual</span>
                    {/if}
                  </td>
                  <td style="text-align: right">
                    <div class="row" style="justify-content: flex-end; gap: 6px">
                      <button
                        class="btn btn-sm {isPinned ? 'btn-primary' : ''}"
                        title={isPinned ? 'Unpin server' : 'Pin as active exit'}
                        disabled={srv.disabled}
                        onclick={() => togglePin(srv)}
                      >
                        <Icon name="pin" size={13} />
                        {isPinned ? 'Unpin' : 'Pin'}
                      </button>
                      <button class="btn btn-sm" onclick={() => toggleServer(srv)}>
                        {srv.disabled ? 'Enable' : 'Disable'}
                      </button>
                      <button class="btn btn-sm" onclick={() => openEditServer(srv)}>Edit</button>
                      <button class="btn btn-sm btn-danger" onclick={() => removeServer(srv)} aria-label="Delete server">
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
          <table>
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
                  <td>
                    <div style="font-weight: 600">{sub.name}</div>
                    <div class="hint mono" style="font-size: 11px">
                      {sub.id} · URL hidden for security
                    </div>
                  </td>
                  <td class="mono">{sub.interval}</td>
                  <td class="tabular" style="font-size: 12.5px; color: var(--text-muted)">
                    {formatTime(sub.last_fetch)}
                  </td>
                  <td>
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
                  <td style="text-align: right">
                    <div class="row" style="justify-content: flex-end; gap: 6px">
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
  <Modal title="Add Proxy Server" onClose={() => (showAddServer = false)}>
    <div class="tabs">
      <button class="tab {addMode === 'link' ? 'active' : ''}" onclick={() => (addMode = 'link')}>
        Share Link(s)
      </button>
      <button class="tab {addMode === 'json' ? 'active' : ''}" onclick={() => (addMode = 'json')}>
        Raw Xray Outbound JSON
      </button>
    </div>

    <form class="stack" onsubmit={addServerSubmit}>
      {#if addMode === 'link'}
        <div class="field">
          <label for="srv-links">Share Link(s)</label>
          <textarea
            id="srv-links"
            class="textarea"
            placeholder="vless://...&#10;trojan://...&#10;(Paste one or multiple lines for bulk import)"
            bind:value={linkInput}
            required
          ></textarea>
          <span class="hint">
            Supports VLESS (TLS / REALITY / Vision / XHTTP + Extra / PQ ML-DSA-65 / PQ Encryption / TLS ECH / WS /
            gRPC / HTTPUpgrade), VMess, Trojan, and Shadowsocks. Credentials are never echoed back in API views.
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
          <label for="srv-name">Custom Name (optional, single link only)</label>
          <input id="srv-name" class="input" placeholder="Auto from #fragment" bind:value={serverName} />
        </div>
      {:else}
        <div class="field">
          <label for="json-name">Server Name</label>
          <input id="json-name" class="input" placeholder="e.g. wireguard-eu" bind:value={serverName} required />
        </div>
        <div class="field">
          <label for="json-body">Xray Outbound JSON Object</label>
          <textarea
            id="json-body"
            class="textarea"
            style="min-height: 160px"
            placeholder={'{"protocol":"vless","settings":{...},"streamSettings":{...}}'}
            bind:value={outboundJSON}
            required
          ></textarea>
        </div>
      {/if}

      <div class="row" style="justify-content: flex-end">
        <button type="button" class="btn" onclick={() => (showAddServer = false)}>Cancel</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>
          {saving ? 'Validating & Saving…' : 'Save Server'}
        </button>
      </div>
    </form>
  </Modal>
{/if}

<!-- Edit Server Modal -->
{#if editingServer}
  <Modal title="Edit Server ({editingServer.id})" onClose={() => (editingServer = null)}>
    <form class="stack" onsubmit={saveEditServer}>
      <div class="field">
        <label for="edit-name">Display Name</label>
        <input id="edit-name" class="input" bind:value={editName} required />
      </div>
      <div class="field">
        <label for="edit-link">Replace Share Link (optional)</label>
        <input
          id="edit-link"
          class="input mono"
          placeholder="Leave empty to keep existing credentials"
          bind:value={editLink}
        />
      </div>
      <div class="row" style="justify-content: flex-end">
        <button type="button" class="btn" onclick={() => (editingServer = null)}>Cancel</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>
          {saving ? 'Saving…' : 'Save Changes'}
        </button>
      </div>
    </form>
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
