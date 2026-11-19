<script lang="ts">
  import { api, type CoreInfo, type GeoInfo, type ImageStatus, type ServiceStatus } from '../lib/api';
  import { formatBytes, formatTime, friendlyError } from '../lib/format';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';

  interface Props {
    status: ServiceStatus | null;
    onRefresh: () => Promise<void>;
  }

  let { status, onRefresh }: Props = $props();

  const runnerOnline = $derived(Boolean(status?.health.runner.reachable));
  const managedRouter = $derived(Boolean(status?.routeros));

  let core = $state<CoreInfo | null>(null);
  let geo = $state<GeoInfo | null>(null);
  let ctlImage = $state<ImageStatus | null>(null);
  let runnerImage = $state<ImageStatus | null>(null);
  let imageError = $state('');

  // Core update state
  let coreVersion = $state('latest');
  let allowUnverified = $state(false);
  let coreBusy = $state(false);
  let showCoreInbox = $state(false);
  let coreAssetName = $state('Xray-linux-arm64-v8a.zip');
  let coreFile = $state<File | null>(null);
  let uploadingCore = $state(false);

  // Geo update state
  let geoProfile = $state('iran');
  let geoVersion = $state('latest');
  let geoBusy = $state(false);
  let showGeoInbox = $state(false);
  let geoInboxVersion = $state('');
  let geoInboxFile = $state('geoip.dat');
  let geoUploadFile = $state<File | null>(null);
  let uploadingGeo = $state(false);

  // Image updates
  let ctlVersion = $state('');
  let runnerVersion = $state('');
  let imageBusy = $state<'tikray' | 'runner' | ''>('');

  async function loadAll(): Promise<void> {
    const [coreRes, geoRes] = await Promise.allSettled([api.getCore(), api.getGeo()]);
    if (coreRes.status === 'fulfilled') core = coreRes.value;
    if (geoRes.status === 'fulfilled') {
      geo = geoRes.value;
      if (geoRes.value.profile) geoProfile = geoRes.value.profile;
    }

    const [cImg, rImg] = await Promise.allSettled([api.getImageStatus('tikray'), api.getImageStatus('runner')]);
    if (cImg.status === 'fulfilled') {
      ctlImage = cImg.value;
      imageError = '';
    } else if (cImg.status === 'rejected') {
      imageError = friendlyError(
        cImg.reason,
        'Managed RouterOS installation required — container image updates run via the native RouterOS watchdog.'
      );
    }
    if (rImg.status === 'fulfilled') runnerImage = rImg.value;
  }

  $effect(() => {
    loadAll();
  });

  async function runCoreUpdate(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    coreBusy = true;
    try {
      const res = await api.updateCore(coreVersion.trim() || 'latest', allowUnverified);
      toast.ok(`xray-core update ${res.outcome}: ${res.to}`);
      await Promise.all([loadAll(), onRefresh()]);
    } catch (err) {
      toast.err(friendlyError(err, 'Core update failed'));
    } finally {
      coreBusy = false;
    }
  }

  async function runCoreRollback(): Promise<void> {
    if (!confirm('Roll back xray-core to the previous verified slot?')) return;
    coreBusy = true;
    try {
      const res = await api.rollbackCore();
      toast.ok(`xray-core rollback ${res.outcome}: ${res.to}`);
      await Promise.all([loadAll(), onRefresh()]);
    } catch (err) {
      toast.err(friendlyError(err, 'Core rollback failed'));
    } finally {
      coreBusy = false;
    }
  }

  async function uploadCore(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (!coreFile) {
      toast.warn('Select an Xray release .zip file first.');
      return;
    }
    uploadingCore = true;
    try {
      const res = await api.uploadCoreInbox(coreAssetName, coreFile);
      toast.ok(`Uploaded ${res.name} (${formatBytes(res.bytes)}) to offline inbox.`);
      coreFile = null;
    } catch (err) {
      toast.err(friendlyError(err, 'Core inbox upload failed'));
    } finally {
      uploadingCore = false;
    }
  }

  async function runGeoUpdate(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    geoBusy = true;
    try {
      const res = await api.updateGeo(geoProfile, geoVersion.trim() || 'latest');
      toast.ok(`Geo bundle ${res.outcome}: ${res.to}`);
      await Promise.all([loadAll(), onRefresh()]);
    } catch (err) {
      toast.err(friendlyError(err, 'Geo update failed'));
    } finally {
      geoBusy = false;
    }
  }

  async function runGeoRollback(): Promise<void> {
    if (!confirm('Roll back geo bundle and RouterOS domestic ranges to the previous slot?')) return;
    geoBusy = true;
    try {
      const res = await api.rollbackGeo();
      toast.ok(`Geo rollback ${res.outcome}: ${res.to}`);
      await Promise.all([loadAll(), onRefresh()]);
    } catch (err) {
      toast.err(friendlyError(err, 'Geo rollback failed'));
    } finally {
      geoBusy = false;
    }
  }

  async function uploadGeo(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (!geoUploadFile || !geoInboxVersion.trim()) {
      toast.warn('Specify release version and select a file.');
      return;
    }
    uploadingGeo = true;
    try {
      const res = await api.uploadGeoInbox(geoProfile, geoInboxVersion.trim(), geoInboxFile, geoUploadFile);
      toast.ok(`Uploaded ${res.name} (${formatBytes(res.bytes)}) to geo inbox.`);
      geoUploadFile = null;
    } catch (err) {
      toast.err(friendlyError(err, 'Geo inbox upload failed'));
    } finally {
      uploadingGeo = false;
    }
  }

  async function runImageUpdate(comp: 'tikray' | 'runner'): Promise<void> {
    const version = (comp === 'tikray' ? ctlVersion : runnerVersion).trim();
    if (!version) {
      toast.warn('Enter a target image version tag (e.g. v1.0.1).');
      return;
    }
    if (
      comp === 'runner' &&
      !confirm(
        'Updating tikray-runner briefly interrupts proxied traffic while RouterOS swaps the data-plane container. Continue?'
      )
    ) {
      return;
    }
    imageBusy = comp;
    try {
      const op = await api.updateImage(comp, version);
      toast.ok(`Queued ${comp} image update to ${op.target ?? version} (${op.state}).`);
      await loadAll();
    } catch (err) {
      toast.err(friendlyError(err, 'Image update failed'));
    } finally {
      imageBusy = '';
    }
  }

  async function runImageRollback(comp: 'tikray' | 'runner'): Promise<void> {
    if (!confirm(`Queue rollback for ${comp} container image?`)) return;
    imageBusy = comp;
    try {
      const op = await api.rollbackImage(comp);
      toast.ok(`Queued ${comp} image rollback (${op.state}).`);
      await loadAll();
    } catch (err) {
      toast.err(friendlyError(err, 'Image rollback failed'));
    } finally {
      imageBusy = '';
    }
  }
</script>

<div class="stack-lg">
  <div class="alert">
    tikray separates updates into <strong>four independent lifecycles</strong>: xray-core binaries, geoip/geosite data
    bundles, the control-plane image (blue/green zero-downtime), and the runner data-plane image. Every switch trials
    before commit and auto-rolls back on failure.
  </div>

  {#if !runnerOnline}
    <div class="alert warn">
      Data-plane runner (<code>tikray-runner</code>) is currently offline. Offline Inbox uploads remain available; live
      <code>xray-core</code> and Geo trials require a connected runner.
    </div>
  {/if}

  <div class="grid-2">
    <!-- 1. xray-core -->
    <div class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">1. xray-core Runtime</h2>
          <p class="card-sub">Hot-swapped inside the runner with SHA-256 verification and automatic trial rollback</p>
        </div>
        <span class="badge {status?.core_tested ? 'ok' : 'warn'} mono">
          {core?.active || status?.core || 'none'}
        </span>
      </div>

      <form class="stack" onsubmit={runCoreUpdate}>
        <div class="row">
          <input
            class="input mono"
            style="flex: 1"
            placeholder="latest or 26.11.9"
            bind:value={coreVersion}
            required
          />
          <button type="submit" class="btn btn-primary" disabled={coreBusy}>
            {coreBusy ? 'Updating…' : 'Update Core'}
          </button>
          <button type="button" class="btn" disabled={coreBusy || (core?.slots.length ?? 0) < 2} onclick={runCoreRollback}>
            Rollback
          </button>
        </div>
        <label class="toggle" style="font-size: 12.5px; color: var(--text-muted)">
          <input type="checkbox" bind:checked={allowUnverified} />
          <span>Allow unverified offline inbox archive (manual air-gapped install only)</span>
        </label>
      </form>

      {#if (core?.slots.length ?? 0) > 0}
        <div>
          <div class="label" style="margin-bottom: 6px">Installed Slots</div>
          <div class="stack" style="gap: 6px">
            {#each core?.slots ?? [] as sl (sl.version)}
              <div class="row-between" style="padding: 7px 10px; border: 1px solid var(--border); border-radius: 7px">
                <div class="row" style="gap: 8px">
                  <span class="mono" style="font-weight: 600">{sl.version}</span>
                  {#if sl.version === core?.active}
                    <span class="badge ok">Active</span>
                  {/if}
                  <span class="badge">{sl.verified || 'unverified'}</span>
                </div>
                <span class="hint tabular">{formatTime(sl.installed_at)}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <div>
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => (showCoreInbox = !showCoreInbox)}>
          <Icon name="upload" size={13} />
          {showCoreInbox ? 'Hide Offline Inbox Upload' : 'Upload Offline Xray .zip to Inbox'}
        </button>
        {#if showCoreInbox}
          <form class="stack" style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border)" onsubmit={uploadCore}>
            <div class="grid-2">
              <div class="field">
                <label for="core-asset">Target Asset Filename</label>
                <select id="core-asset" class="select mono" bind:value={coreAssetName}>
                  <option value="Xray-linux-arm64-v8a.zip">Xray-linux-arm64-v8a.zip (ARM64)</option>
                  <option value="Xray-linux-64.zip">Xray-linux-64.zip (AMD64)</option>
                </select>
              </div>
              <div class="field">
                <label for="core-file">Release Archive (.zip)</label>
                <input
                  id="core-file"
                  class="input"
                  type="file"
                  accept=".zip"
                  onchange={(e) => (coreFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null)}
                />
              </div>
            </div>
            <div>
              <button type="submit" class="btn btn-sm btn-primary" disabled={uploadingCore || !coreFile}>
                {uploadingCore ? 'Uploading…' : 'Upload to Inbox'}
              </button>
            </div>
          </form>
        {/if}
      </div>
    </div>

    <!-- 2. Geo Data Bundle -->
    <div class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">2. Geo Data Bundle</h2>
          <p class="card-sub">Synchronized geosite.dat, geoip.dat, and RouterOS domestic IPv4 bypass ranges</p>
        </div>
        <span class="badge {geo?.active ? (geo.degraded ? 'danger' : 'ok') : 'warn'} mono">
          {geo?.active || 'none'}
        </span>
      </div>

      <form class="stack" onsubmit={runGeoUpdate}>
        <div class="row">
          <select class="select" style="width: 145px" bind:value={geoProfile}>
            <option value="iran">iran</option>
            <option value="v2fly">v2fly</option>
            <option value="loyalsoldier">loyalsoldier</option>
            <option value="custom">custom</option>
          </select>
          <input
            class="input mono"
            style="flex: 1"
            placeholder="latest or release date"
            bind:value={geoVersion}
            required
          />
          <button type="submit" class="btn btn-primary" disabled={geoBusy}>
            {geoBusy ? 'Updating…' : 'Update Geo'}
          </button>
          <button type="button" class="btn" disabled={geoBusy || (geo?.slots.length ?? 0) < 2} onclick={runGeoRollback}>
            Rollback
          </button>
        </div>
      </form>

      {#if (geo?.slots.length ?? 0) > 0}
        <div>
          <div class="label" style="margin-bottom: 6px">Verified Geo Slots</div>
          <div class="stack" style="gap: 6px">
            {#each geo?.slots ?? [] as sl (sl.slot)}
              <div class="row-between" style="padding: 7px 10px; border: 1px solid var(--border); border-radius: 7px">
                <div class="row" style="gap: 8px">
                  <span class="mono" style="font-weight: 600">{sl.slot}</span>
                  {#if sl.slot === geo?.active}
                    <span class="badge ok">Active</span>
                  {/if}
                  {#if sl.profile}
                    <span class="badge accent">{sl.profile}</span>
                  {/if}
                </div>
                <span class="hint tabular">{sl.prefix_count} domestic prefixes</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <div>
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => (showGeoInbox = !showGeoInbox)}>
          <Icon name="upload" size={13} />
          {showGeoInbox ? 'Hide Offline Geo Upload' : 'Upload Offline Geo Asset to Inbox'}
        </button>
        {#if showGeoInbox}
          <form class="stack" style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border)" onsubmit={uploadGeo}>
            <div class="grid-2">
              <div class="field">
                <label for="geo-ver">Exact Release Tag</label>
                <input
                  id="geo-ver"
                  class="input mono"
                  placeholder={geoProfile === 'v2fly' ? '20261119+20261119' : '20261119'}
                  bind:value={geoInboxVersion}
                  required
                />
              </div>
              <div class="field">
                <label for="geo-asset">Asset Filename</label>
                <select id="geo-asset" class="select mono" bind:value={geoInboxFile}>
                  <option value="geoip.dat">geoip.dat</option>
                  {#if geoProfile === 'v2fly'}
                    <option value="dlc.dat">dlc.dat</option>
                  {:else}
                    <option value="geosite.dat">geosite.dat</option>
                  {/if}
                  {#if geoProfile === 'custom'}
                    <option value="domestic-v4.txt">domestic-v4.txt</option>
                  {/if}
                </select>
              </div>
            </div>
            <div class="row">
              <input
                class="input"
                style="flex: 1"
                type="file"
                onchange={(e) => (geoUploadFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null)}
              />
              <button type="submit" class="btn btn-sm btn-primary" disabled={uploadingGeo || !geoUploadFile}>
                {uploadingGeo ? 'Uploading…' : 'Upload'}
              </button>
            </div>
          </form>
        {/if}
      </div>
    </div>

    <!-- 3. Control Plane Image -->
    <div class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">3. tikray Control Image</h2>
          <p class="card-sub">Blue/green container replacement via RouterOS watchdog — zero traffic interruption</p>
        </div>
        <span class="badge accent mono">{ctlImage?.active || status?.version || 'dev'}</span>
      </div>

      {#if !ctlImage}
        <div class="empty-state">
          {managedRouter && imageError
            ? imageError
            : 'Managed RouterOS installation required — blue/green container image updates run via the native RouterOS watchdog.'}
        </div>
      {:else}
        <div class="row" style="gap: 8px">
          <span class="badge">State: {ctlImage.state || 'idle'}</span>
          {#if ctlImage.previous}
            <span class="badge mono">Previous: {ctlImage.previous}</span>
          {/if}
          {#if ctlImage.target}
            <span class="badge warn mono">Target: {ctlImage.target}</span>
          {/if}
        </div>
        {#if ctlImage.error}
          <div class="alert danger">{ctlImage.error}</div>
        {/if}
        <div class="row">
          <input class="input mono" style="flex: 1" placeholder="e.g. v1.0.1" bind:value={ctlVersion} />
          <button
            class="btn btn-primary"
            disabled={imageBusy !== ''}
            onclick={() => runImageUpdate('tikray')}
          >
            {imageBusy === 'tikray' ? 'Queueing…' : 'Queue Update'}
          </button>
          <button
            class="btn"
            disabled={imageBusy !== '' || !ctlImage.previous}
            onclick={() => runImageRollback('tikray')}
          >
            Rollback
          </button>
        </div>
      {/if}
    </div>

    <!-- 4. Runner Data Image -->
    <div class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">4. tikray-runner Data Image</h2>
          <p class="card-sub">TUN / policy-routing data-plane container — rare OS or supervisor updates only</p>
        </div>
        <span class="badge mono">{runnerImage?.active || '—'}</span>
      </div>

      {#if !runnerImage}
        <div class="empty-state">
          {managedRouter && imageError
            ? imageError
            : 'Managed RouterOS installation required — runner container image updates run via the native RouterOS watchdog.'}
        </div>
      {:else}
        <div class="alert warn" style="font-size: 12.5px">
          Swapping <code>tikray-runner</code> briefly drops active proxy connections while RouterOS recreates the
          data-plane container.
        </div>
        <div class="row" style="gap: 8px">
          <span class="badge">State: {runnerImage.state || 'idle'}</span>
          {#if runnerImage.previous}
            <span class="badge mono">Previous: {runnerImage.previous}</span>
          {/if}
        </div>
        {#if runnerImage.error}
          <div class="alert danger">{runnerImage.error}</div>
        {/if}
        <div class="row">
          <input class="input mono" style="flex: 1" placeholder="e.g. runner-v1.0.1" bind:value={runnerVersion} />
          <button
            class="btn btn-primary"
            disabled={imageBusy !== ''}
            onclick={() => runImageUpdate('runner')}
          >
            {imageBusy === 'runner' ? 'Queueing…' : 'Queue Update'}
          </button>
          <button
            class="btn"
            disabled={imageBusy !== '' || !runnerImage.previous}
            onclick={() => runImageRollback('runner')}
          >
            Rollback
          </button>
        </div>
      {/if}
    </div>
  </div>
</div>
