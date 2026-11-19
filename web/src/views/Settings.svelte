<script lang="ts">
  import { api, ApiError, type BackupBundle, type ServiceStatus, type State, type TokenInfo } from '../lib/api';
  import { downloadJSON, formatTime, splitLines } from '../lib/format';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';

  interface Props {
    status: ServiceStatus | null;
    stateData: State | null;
    onRefresh: () => Promise<void>;
  }

  let { status, stateData, onRefresh }: Props = $props();

  // Encrypted Backup
  let exportPass = $state('');
  let exporting = $state(false);

  let restoreFile = $state<File | null>(null);
  let restorePass = $state('');
  let restoring = $state(false);

  // API Tokens
  let tokens = $state<TokenInfo[]>([]);
  let tokenName = $state('');
  let tokenExpires = $state('');
  let creatingToken = $state(false);
  let createdSecret = $state<{ token: string; name: string } | null>(null);

  // Admin Password
  let currentPass = $state('');
  let newPass = $state('');
  let confirmPass = $state('');
  let changingPass = $state(false);

  // Bridge repair
  let repairSubnet = $state('');
  let repairRemove = $state('');
  let repairRemoteDNS = $state('');
  let repairing = $state(false);

  async function loadTokens(): Promise<void> {
    try {
      tokens = await api.listTokens();
    } catch {
      tokens = [];
    }
  }

  $effect(() => {
    loadTokens();
  });

  async function exportBackup(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (exportPass.length < 10) {
      toast.warn('Backup passphrase must be at least 10 characters.');
      return;
    }
    exporting = true;
    try {
      const bundle = await api.exportBackup(exportPass);
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 16);
      downloadJSON(`tikray-backup-${stamp}.json`, bundle);
      exportPass = '';
      toast.ok('Encrypted backup downloaded (AES-256-GCM + Argon2id).');
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Backup export failed');
    } finally {
      exporting = false;
    }
  }

  async function restoreBackup(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (!restoreFile) {
      toast.warn('Select an encrypted backup JSON file first.');
      return;
    }
    if (!confirm('Restore this encrypted backup? Current servers, subscriptions, devices, routing, DNS, and health settings will be replaced atomically.')) {
      return;
    }
    restoring = true;
    try {
      const text = await restoreFile.text();
      let parsed: BackupBundle;
      try {
        parsed = JSON.parse(text) as BackupBundle;
      } catch {
        toast.err('Selected file is not valid JSON.');
        return;
      }
      const res = await api.restoreBackup(parsed, restorePass);
      restorePass = '';
      restoreFile = null;
      toast.ok(`Backup restored at revision ${res.revision}. Reconciler is applying state.`);
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Backup restore failed');
    } finally {
      restoring = false;
    }
  }

  async function createToken(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    creatingToken = true;
    try {
      const res = await api.createToken(tokenName.trim(), tokenExpires || undefined);
      createdSecret = { token: res.token, name: res.info.name };
      tokenName = '';
      tokenExpires = '';
      await loadTokens();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Could not create token');
    } finally {
      creatingToken = false;
    }
  }

  async function revokeToken(t: TokenInfo): Promise<void> {
    if (!confirm(`Revoke API token "${t.name}" (${t.id})?`)) return;
    try {
      await api.revokeToken(t.id);
      toast.ok(`Revoked token ${t.name}.`);
      await loadTokens();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Revoke failed');
    }
  }

  async function copySecret(): Promise<void> {
    if (!createdSecret) return;
    try {
      await navigator.clipboard.writeText(createdSecret.token);
      toast.ok('Copied API token to clipboard.');
    } catch {
      toast.warn('Copy manually from the box above.');
    }
  }

  async function changePassword(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (newPass.length < 10) {
      toast.warn('New password must be at least 10 characters.');
      return;
    }
    if (newPass !== confirmPass) {
      toast.warn('New passwords do not match.');
      return;
    }
    changingPass = true;
    try {
      await api.changePassword(currentPass, newPass);
      currentPass = '';
      newPass = '';
      confirmPass = '';
      toast.ok('Admin password changed. All other sessions were signed out.');
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Password change failed');
    } finally {
      changingPass = false;
    }
  }

  async function submitRepair(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    repairing = true;
    try {
      const res = await api.repairNetwork({
        subnet: repairSubnet.trim() || undefined,
        remove_devices: splitLines(repairRemove).length > 0 ? splitLines(repairRemove) : undefined,
        remote_dns: repairRemoteDNS.trim() || undefined
      });
      toast.ok(
        res.restart_required
          ? 'Network repaired. Restart the tikray container to reconnect the runner bridge.'
          : 'Network repaired.'
      );
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Network repair refused');
    } finally {
      repairing = false;
    }
  }
</script>

<div class="stack-lg">
  <!-- Encrypted Backup & Restore -->
  <div class="grid-2">
    <form class="card stack" onsubmit={exportBackup}>
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">Encrypted Backup Export</h2>
          <p class="card-sub">
            Seals your full configuration (including server credentials and subscription URLs) with Argon2id + AES-256-GCM
          </p>
        </div>
      </div>

      <div class="field">
        <label for="exp-pass">Encryption Passphrase (min 10 chars)</label>
        <input
          id="exp-pass"
          class="input"
          type="password"
          autocomplete="new-password"
          minlength="10"
          placeholder="Enter a strong passphrase"
          bind:value={exportPass}
          required
        />
        <span class="hint">Store this passphrase safely; tikray never stores or logs it.</span>
      </div>

      <div>
        <button type="submit" class="btn btn-primary" disabled={exporting}>
          <Icon name="download" size={14} />
          {exporting ? 'Encrypting…' : 'Download Encrypted Backup'}
        </button>
      </div>
    </form>

    <form class="card stack" onsubmit={restoreBackup}>
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">Restore Encrypted Backup</h2>
          <p class="card-sub">
            Decrypts and atomically replaces desired state (managed router bridge subnet is automatically preserved)
          </p>
        </div>
      </div>

      <div class="field">
        <label for="res-file">Backup File (<code>tikray-backup-*.json</code>)</label>
        <input
          id="res-file"
          class="input"
          type="file"
          accept=".json,application/json"
          onchange={(e) => (restoreFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null)}
          required
        />
      </div>

      <div class="field">
        <label for="res-pass">Decryption Passphrase</label>
        <input
          id="res-pass"
          class="input"
          type="password"
          autocomplete="current-password"
          bind:value={restorePass}
          required
        />
      </div>

      <div>
        <button type="submit" class="btn btn-danger" disabled={restoring || !restoreFile}>
          <Icon name="upload" size={14} />
          {restoring ? 'Decrypting & Restoring…' : 'Restore Backup'}
        </button>
      </div>
    </form>
  </div>

  <!-- API Tokens -->
  <div class="card stack">
    <div class="card-header" style="margin-bottom: 0">
      <div>
        <h2 class="card-title">Named API Tokens</h2>
        <p class="card-sub">
          Bearer tokens for automation scripts and monitoring (restricted from password changes, backups, and inbox
          uploads)
        </p>
      </div>
    </div>

    <form class="row" onsubmit={createToken}>
      <input
        class="input"
        style="flex: 1; min-width: 200px"
        placeholder="Token label (e.g. home-assistant)"
        bind:value={tokenName}
        required
      />
      <select class="select" style="width: 170px" bind:value={tokenExpires}>
        <option value="">No expiry</option>
        <option value="24h">Expires in 24 hours</option>
        <option value="168h">Expires in 7 days</option>
        <option value="720h">Expires in 30 days</option>
        <option value="8760h">Expires in 1 year</option>
      </select>
      <button type="submit" class="btn btn-primary" disabled={creatingToken}>
        <Icon name="plus" size={14} />
        {creatingToken ? 'Creating…' : 'Create Token'}
      </button>
    </form>

    {#if tokens.length === 0}
      <div class="empty-state">No named API tokens issued.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Last Used</th>
              <th style="text-align: right">Action</th>
            </tr>
          </thead>
          <tbody>
            {#each tokens as t (t.id)}
              <tr>
                <td class="mono">{t.id}</td>
                <td style="font-weight: 600">{t.name}</td>
                <td class="tabular" style="font-size: 12.5px; color: var(--text-muted)">{formatTime(t.created)}</td>
                <td class="tabular" style="font-size: 12.5px; color: var(--text-muted)">
                  {t.expires ? formatTime(t.expires) : 'Never'}
                </td>
                <td class="tabular" style="font-size: 12.5px; color: var(--text-muted)">
                  {t.last_used ? formatTime(t.last_used) : 'Never'}
                </td>
                <td style="text-align: right">
                  <button class="btn btn-sm btn-danger" onclick={() => revokeToken(t)}>Revoke</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  <!-- Password & Bridge Info -->
  <div class="grid-2">
    <form class="card stack" onsubmit={changePassword}>
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">Admin Password</h2>
          <p class="card-sub">Rotating your password revokes all other active browser sessions</p>
        </div>
      </div>

      <div class="field">
        <label for="cur-pw">Current Password</label>
        <input id="cur-pw" class="input" type="password" autocomplete="current-password" bind:value={currentPass} required />
      </div>
      <div class="field">
        <label for="new-pw">New Password (min 10 chars)</label>
        <input id="new-pw" class="input" type="password" autocomplete="new-password" minlength="10" bind:value={newPass} required />
      </div>
      <div class="field">
        <label for="cfm-pw">Confirm New Password</label>
        <input id="cfm-pw" class="input" type="password" autocomplete="new-password" minlength="10" bind:value={confirmPass} required />
      </div>
      <div>
        <button type="submit" class="btn btn-primary" disabled={changingPass}>
          {changingPass ? 'Updating…' : 'Update Password'}
        </button>
      </div>
    </form>

    <div class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">Container Bridge &amp; Process Info</h2>
          <p class="card-sub">Private link connecting MikroTik RouterOS, tikray, and tikray-runner</p>
        </div>
      </div>

      <div class="stack" style="gap: 8px; font-size: 13px">
        <div class="row-between">
          <span class="hint">Bridge Subnet</span>
          <span class="mono" style="font-weight: 600">{stateData?.network.subnet ?? '—'}</span>
        </div>
        <div class="row-between">
          <span class="hint">Control Version</span>
          <span class="mono">{status?.version || 'dev'}</span>
        </div>
        <div class="row-between">
          <span class="hint">Process Boot ID</span>
          <span class="mono">{status?.boot_id || '—'}</span>
        </div>
        <div class="row-between">
          <span class="hint">RouterOS Mode</span>
          <span>
            {#if status?.routeros?.version}
              Managed · RouterOS <code class="mono">{status.routeros.version}</code>
              {#if status.routeros.untested}
                <span class="badge warn" style="margin-left: 6px">untested</span>
              {/if}
            {:else if status?.routeros}
              Managed (Native API-SSL)
            {:else}
              Standalone
            {/if}
          </span>
        </div>
      </div>

      {#if status?.routeros?.degraded === 'bridge_repair'}
        <form class="stack" style="padding-top: 12px; border-top: 1px solid var(--border)" onsubmit={submitRepair}>
          <div class="alert danger">Bridge network overlap detected. Repair and restart <code>tikray serve</code>.</div>
          <div class="field">
            <label for="rep-sub">Proposed Bridge Subnet (optional)</label>
            <input id="rep-sub" class="input mono" placeholder="172.30.0.0/29" bind:value={repairSubnet} />
          </div>
          <div class="field">
            <label for="rep-dev">Conflicting Devices to Remove (comma/newline)</label>
            <input id="rep-dev" class="input mono" placeholder="172.30.0.2/32" bind:value={repairRemove} />
          </div>
          <div class="field">
            <label for="rep-dns">New Remote DNS (optional)</label>
            <input id="rep-dns" class="input mono" bind:value={repairRemoteDNS} />
          </div>
          <button type="submit" class="btn btn-danger" disabled={repairing}>
            {repairing ? 'Repairing…' : 'Apply Bridge Repair'}
          </button>
        </form>
      {/if}
    </div>
  </div>
</div>

<!-- One-time API token display modal -->
{#if createdSecret}
  <Modal title="API Token Created: {createdSecret.name}" closable={false}>
    <div class="alert warn">
      Copy this token now. Only its SHA-256 hash is stored — it will <strong>never</strong> be shown again.
    </div>
    <div class="code-block" style="word-break: break-all; user-select: all">{createdSecret.token}</div>
    <div class="row" style="justify-content: flex-end">
      <button class="btn" onclick={copySecret}>
        <Icon name="copy" size={14} /> Copy Token
      </button>
      <button class="btn btn-primary" onclick={() => (createdSecret = null)}>Done</button>
    </div>
  </Modal>
{/if}
