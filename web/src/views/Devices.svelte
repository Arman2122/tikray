<script lang="ts">
  import { api, ApiError, type Device, type LeaseInfo, type PolicyMode, type ServiceStatus, type State } from '../lib/api';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';

  interface Props {
    status: ServiceStatus | null;
    stateData: State | null;
    onRefresh: () => Promise<void>;
  }

  let { status, stateData, onRefresh }: Props = $props();

  let defaultMode = $state<PolicyMode>('direct');
  let defaultKill = $state(false);
  let savingPolicy = $state(false);

  // Device modal
  let showDeviceModal = $state(false);
  let devAddr = $state('');
  let devName = $state('');
  let devMAC = $state('');
  let devMode = $state<PolicyMode>('smart');
  let devKill = $state(false);
  let savingDevice = $state(false);

  // RouterOS DHCP leases
  let leases = $state<LeaseInfo[]>([]);
  let loadingLeases = $state(false);
  let leasesError = $state('');
  let staticBusy = $state('');

  $effect(() => {
    if (stateData) {
      defaultMode = stateData.default_policy.mode;
      defaultKill = Boolean(stateData.default_policy.kill_switch);
    }
  });

  $effect(() => {
    if (status?.routeros) {
      loadLeases();
    }
  });

  async function loadLeases(): Promise<void> {
    loadingLeases = true;
    leasesError = '';
    try {
      leases = await api.getLeases();
    } catch (err) {
      leasesError = err instanceof ApiError ? err.detail || err.message : 'Unable to read RouterOS DHCP leases';
    } finally {
      loadingLeases = false;
    }
  }

  async function saveDefaultPolicy(): Promise<void> {
    savingPolicy = true;
    try {
      await api.setDefaultPolicy({
        mode: defaultMode,
        kill_switch: defaultMode === 'direct' ? false : defaultKill
      });
      toast.ok(`Default policy updated to ${defaultMode}.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Failed to save default policy');
    } finally {
      savingPolicy = false;
    }
  }

  function openNewDevice(prefill?: { address?: string; name?: string; mac?: string }): void {
    devAddr = prefill?.address ? (prefill.address.includes('/') ? prefill.address : `${prefill.address}/32`) : '';
    devName = prefill?.name ?? '';
    devMAC = prefill?.mac ?? '';
    devMode = 'smart';
    devKill = false;
    showDeviceModal = true;
  }

  function openEditDevice(d: Device): void {
    devAddr = d.address;
    devName = d.name ?? '';
    devMAC = d.mac ?? '';
    devMode = d.policy.mode;
    devKill = Boolean(d.policy.kill_switch);
    showDeviceModal = true;
  }

  async function saveDevice(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    savingDevice = true;
    try {
      const addr = devAddr.trim().includes('/') ? devAddr.trim() : `${devAddr.trim()}/32`;
      await api.setDevice(addr, {
        address: addr,
        name: devName.trim() || undefined,
        mac: devMAC.trim() || undefined,
        policy: {
          mode: devMode,
          kill_switch: devMode === 'direct' ? false : devKill
        }
      });
      toast.ok(`Saved policy for ${addr}.`);
      showDeviceModal = false;
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not save device');
    } finally {
      savingDevice = false;
    }
  }

  async function removeDevice(d: Device): Promise<void> {
    if (!confirm(`Remove policy override for ${d.name ? `${d.name} (${d.address})` : d.address}?`)) return;
    try {
      await api.deleteDevice(d.address);
      toast.ok(`Removed device ${d.address}.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Delete failed');
    }
  }

  async function makeStatic(l: LeaseInfo): Promise<void> {
    staticBusy = l.address;
    try {
      await api.makeStaticLease(l.address);
      toast.ok(`Converted ${l.address} to a static DHCP lease on RouterOS.`);
      await loadLeases();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not make lease static');
    } finally {
      staticBusy = '';
    }
  }
</script>

<div class="stack-lg">
  <!-- Default Policy -->
  <div class="card stack">
    <div class="card-header" style="margin-bottom: 4px">
      <div>
        <h2 class="card-title">Default LAN Policy</h2>
        <p class="card-sub">Applies to every LAN client not listed in device overrides below</p>
      </div>
      <button class="btn btn-primary btn-sm" disabled={savingPolicy} onclick={saveDefaultPolicy}>
        {savingPolicy ? 'Saving…' : 'Save Default Policy'}
      </button>
    </div>

    <div class="policy-grid">
      <button
        type="button"
        class="policy-card {defaultMode === 'direct' ? 'active' : ''}"
        onclick={() => {
          defaultMode = 'direct';
          defaultKill = false;
        }}
      >
        <strong style="font-size: 14px">Direct</strong>
        <span class="hint">All traffic bypasses the proxy and goes straight out WAN.</span>
      </button>
      <button
        type="button"
        class="policy-card {defaultMode === 'smart' ? 'active' : ''}"
        onclick={() => (defaultMode = 'smart')}
      >
        <strong style="font-size: 14px">Smart Split</strong>
        <span class="hint">Domestic &amp; local LAN stay direct; international traffic goes through xray.</span>
      </button>
      <button
        type="button"
        class="policy-card {defaultMode === 'full' ? 'active' : ''}"
        onclick={() => (defaultMode = 'full')}
      >
        <strong style="font-size: 14px">Full Tunnel</strong>
        <span class="hint">All non-LAN traffic (including domestic) routes through xray.</span>
      </button>
    </div>

    <label class="toggle" style="opacity: {defaultMode === 'direct' ? 0.5 : 1}">
      <input type="checkbox" bind:checked={defaultKill} disabled={defaultMode === 'direct'} />
      <span>
        <strong>Kill Switch</strong> — block proxied traffic if the proxy tunnel goes down instead of failing open direct
      </span>
    </label>
  </div>

  <!-- Configured Devices -->
  <div class="card stack">
    <div class="card-header" style="margin-bottom: 0">
      <div>
        <h2 class="card-title">Device &amp; Subnet Overrides</h2>
        <p class="card-sub">Per-IP (/32) or CIDR policies enforced atomically by RouterOS policy routing</p>
      </div>
      <button class="btn btn-primary btn-sm" onclick={() => openNewDevice()}>
        <Icon name="plus" size={14} /> Add Device / CIDR
      </button>
    </div>

    {#if (stateData?.devices.length ?? 0) === 0}
      <div class="empty-state">No per-device overrides configured. All LAN hosts follow the default policy.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Address / CIDR</th>
              <th>Name</th>
              <th>MAC</th>
              <th>Policy</th>
              <th style="text-align: right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each stateData?.devices ?? [] as d (d.address)}
              <tr>
                <td class="mono" style="font-weight: 600">{d.address}</td>
                <td>{d.name || '—'}</td>
                <td class="mono" style="font-size: 12px; color: var(--text-muted)">{d.mac || '—'}</td>
                <td>
                  <div class="row" style="gap: 6px">
                    <span
                      class="badge {d.policy.mode === 'full'
                        ? 'accent'
                        : d.policy.mode === 'smart'
                          ? 'ok'
                          : ''}"
                    >
                      {d.policy.mode}
                    </span>
                    {#if d.policy.kill_switch}
                      <span class="badge warn">Kill Switch</span>
                    {/if}
                  </div>
                </td>
                <td style="text-align: right">
                  <div class="row" style="justify-content: flex-end; gap: 6px">
                    <button class="btn btn-sm" onclick={() => openEditDevice(d)}>Edit</button>
                    <button class="btn btn-sm btn-danger" onclick={() => removeDevice(d)} aria-label="Remove device">
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

  <!-- RouterOS DHCP Leases -->
  <div class="card stack">
    <div class="card-header" style="margin-bottom: 0">
      <div>
        <h2 class="card-title">RouterOS DHCP Leases</h2>
        <p class="card-sub">
          Active LAN clients discovered directly from MikroTik RouterOS (convert dynamic leases to static before
          assigning per-device policies)
        </p>
      </div>
      {#if status?.routeros}
        <button class="btn btn-sm" disabled={loadingLeases} onclick={loadLeases}>
          <Icon name="refresh" size={13} />
          {loadingLeases ? 'Loading…' : 'Refresh Leases'}
        </button>
      {/if}
    </div>

    {#if !status?.routeros}
      <div class="empty-state">
        Running in standalone mode without a managed MikroTik RouterOS peer. Install with the RouterOS installer to
        enable automatic DHCP lease discovery and static reservations.
      </div>
    {:else if leasesError}
      <div class="alert warn">{leasesError}</div>
    {:else if leases.length === 0}
      <div class="empty-state">{loadingLeases ? 'Reading leases from RouterOS…' : 'No bound DHCP leases observed.'}</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Hostname</th>
              <th>MAC Address</th>
              <th>Lease Type</th>
              <th style="text-align: right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each leases as l (l.address)}
              <tr>
                <td class="mono" style="font-weight: 600">{l.address}</td>
                <td>{l.name || '—'}</td>
                <td class="mono" style="font-size: 12px; color: var(--text-muted)">{l.mac}</td>
                <td>
                  {#if l.static}
                    <span class="badge ok">Static</span>
                  {:else}
                    <span class="badge warn">Dynamic</span>
                  {/if}
                </td>
                <td style="text-align: right">
                  <div class="row" style="justify-content: flex-end; gap: 6px">
                    {#if !l.static}
                      <button
                        class="btn btn-sm"
                        disabled={staticBusy === l.address}
                        onclick={() => makeStatic(l)}
                      >
                        {staticBusy === l.address ? 'Saving…' : 'Make Static'}
                      </button>
                    {/if}
                    <button
                      class="btn btn-sm btn-primary"
                      onclick={() => openNewDevice({ address: l.address, name: l.name, mac: l.mac })}
                    >
                      Assign Policy
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
</div>

<!-- Device Modal -->
{#if showDeviceModal}
  <Modal title="Configure Device / Subnet Policy" onClose={() => (showDeviceModal = false)}>
    <form class="stack" onsubmit={saveDevice}>
      <div class="field">
        <label for="dev-addr">IPv4 Address or CIDR</label>
        <input
          id="dev-addr"
          class="input mono"
          placeholder="192.168.88.25 or 192.168.88.0/24"
          bind:value={devAddr}
          required
        />
      </div>
      <div class="grid-2">
        <div class="field">
          <label for="dev-name">Label (optional)</label>
          <input id="dev-name" class="input" placeholder="e.g. Apple TV" bind:value={devName} />
        </div>
        <div class="field">
          <label for="dev-mac">MAC Address (optional)</label>
          <input id="dev-mac" class="input mono" placeholder="02:00:00:00:00:25" bind:value={devMAC} />
        </div>
      </div>
      <div class="field">
        <label for="dev-mode">Routing Mode</label>
        <select
          id="dev-mode"
          class="select"
          bind:value={devMode}
          onchange={() => {
            if (devMode === 'direct') devKill = false;
          }}
        >
          <option value="direct">Direct (bypass proxy)</option>
          <option value="smart">Smart (domestic direct, international proxied)</option>
          <option value="full">Full (all non-LAN proxied)</option>
        </select>
      </div>
      <label class="toggle" style="opacity: {devMode === 'direct' ? 0.5 : 1}">
        <input type="checkbox" bind:checked={devKill} disabled={devMode === 'direct'} />
        <span>Enable Kill Switch for this device</span>
      </label>
      <div class="row" style="justify-content: flex-end">
        <button type="button" class="btn" onclick={() => (showDeviceModal = false)}>Cancel</button>
        <button type="submit" class="btn btn-primary" disabled={savingDevice}>
          {savingDevice ? 'Saving…' : 'Save Device'}
        </button>
      </div>
    </form>
  </Modal>
{/if}
