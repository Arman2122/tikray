<script lang="ts">
  import { inspectShareLink } from '../lib/linkPreview';

  interface Props {
    value: string;
    idPrefix?: string;
    placeholder?: string;
    required?: boolean;
  }

  let {
    value = $bindable(''),
    idPrefix = 'sle',
    placeholder = 'vless://... or trojan://... or vmess://... or ss://...',
    required = false
  }: Props = $props();

  const KNOWN_KEYS = new Set([
    'type',
    'security',
    'encryption',
    'flow',
    'sni',
    'fp',
    'alpn',
    'pbk',
    'sid',
    'spx',
    'pqv',
    'ech',
    'pcs',
    'vcn',
    'host',
    'path',
    'mode',
    'serviceName',
    'authority',
    'headerType',
    'extra'
  ]);

  let showSecret = $state(false);
  let showEditor = $state(true);

  // Parsed structured state (synchronized two-way for vless:// and trojan://)
  let scheme = $state('');
  let host = $state('');
  let port = $state('443');
  let secret = $state('');
  let remark = $state('');

  let netType = $state('tcp');
  let security = $state('reality');
  let flow = $state('');
  let encryption = $state('none');

  let sni = $state('');
  let fp = $state('');
  let alpn = $state('');
  let pbk = $state('');
  let sid = $state('');
  let spx = $state('');
  let pqv = $state('');
  let ech = $state('');
  let pcs = $state('');
  let vcn = $state('');

  let transHost = $state('');
  let transPath = $state('');
  let transMode = $state('');
  let serviceName = $state('');
  let authority = $state('');
  let headerType = $state('');
  let extraText = $state('');
  let extraErr = $state('');
  let preservedParams = $state<[string, string][]>([]);

  // Track last raw value we synced from/to so we never loop
  let lastSyncedValue = '';

  const preview = $derived(value.trim() ? inspectShareLink(value.trim()) : null);
  const canVisualEdit = $derived(scheme === 'vless' || scheme === 'trojan');

  function prettyExtra(raw: string): { text: string; err: string } {
    const trimmed = raw.trim();
    if (!trimmed) return { text: '', err: '' };
    try {
      const obj = JSON.parse(trimmed);
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        return { text: JSON.stringify(obj, null, 2), err: '' };
      }
      return { text: trimmed, err: 'extra must be a JSON object ({ ... })' };
    } catch {
      return { text: trimmed, err: 'Invalid JSON in extra parameter' };
    }
  }

  function parseFromValue(raw: string): void {
    const trimmed = raw.trim();
    if (!trimmed) {
      scheme = '';
      extraErr = '';
      return;
    }
    try {
      const u = new URL(trimmed);
      const sch = u.protocol.replace(/:$/, '').toLowerCase();
      if (sch !== 'vless' && sch !== 'trojan') {
        scheme = sch;
        extraErr = '';
        return;
      }
      scheme = sch;
      host = u.hostname.replace(/^\[|\]$/g, '');
      port = u.port || '443';
      secret = decodeURIComponent(u.username || '');
      remark = u.hash ? decodeURIComponent(u.hash.slice(1)) : '';

      const q = u.searchParams;
      const rawType = (q.get('type') || 'tcp').toLowerCase();
      netType = rawType === 'raw' ? 'tcp' : rawType === 'splithttp' ? 'xhttp' : rawType;
      security = (q.get('security') || (sch === 'trojan' ? 'tls' : 'none')).toLowerCase();
      flow = q.get('flow') || '';
      encryption = q.get('encryption') || 'none';

      sni = q.get('sni') || '';
      fp = q.get('fp') || '';
      alpn = q.get('alpn') || '';
      pbk = q.get('pbk') || '';
      sid = q.get('sid') || '';
      spx = q.get('spx') || '';
      pqv = q.get('pqv') || '';
      ech = q.get('ech') || '';
      pcs = q.get('pcs') || '';
      vcn = q.get('vcn') || '';

      transHost = q.get('host') || '';
      transPath = q.get('path') || '';
      transMode = q.get('mode') || '';
      serviceName = q.get('serviceName') || '';
      authority = q.get('authority') || '';
      headerType = q.get('headerType') || '';

      const pe = prettyExtra(q.get('extra') || '');
      extraText = pe.text;
      extraErr = pe.err;

      const kept: [string, string][] = [];
      for (const [k, v] of q.entries()) {
        if (!KNOWN_KEYS.has(k)) kept.push([k, v]);
      }
      preservedParams = kept;
    } catch {
      scheme = '';
      extraErr = '';
    }
  }

  function rebuildLink(): void {
    if (!canVisualEdit) return;
    const h = host.trim();
    const p = port.trim() || '443';
    if (!h) return;

    const params = new URLSearchParams();
    if (scheme === 'vless') {
      params.set('encryption', encryption.trim() || 'none');
      if (flow.trim()) params.set('flow', flow.trim());
    }
    if (security && security !== 'none') {
      params.set('security', security);
    } else if (scheme === 'vless') {
      params.set('security', 'none');
    }

    if (security === 'reality') {
      if (sni.trim()) params.set('sni', sni.trim());
      if (fp.trim()) params.set('fp', fp.trim());
      if (pbk.trim()) params.set('pbk', pbk.trim());
      if (sid.trim()) params.set('sid', sid.trim());
      if (spx.trim()) params.set('spx', spx.trim());
      if (pqv.trim()) params.set('pqv', pqv.trim());
    } else if (security === 'tls') {
      if (sni.trim()) params.set('sni', sni.trim());
      if (fp.trim()) params.set('fp', fp.trim());
      if (alpn.trim()) params.set('alpn', alpn.trim());
      if (ech.trim()) params.set('ech', ech.trim());
      if (pcs.trim()) params.set('pcs', pcs.trim());
      if (vcn.trim()) params.set('vcn', vcn.trim());
    }

    if (netType) params.set('type', netType);
    if (netType === 'tcp') {
      if (headerType.trim() && headerType !== 'none') {
        params.set('headerType', headerType.trim());
        if (transHost.trim()) params.set('host', transHost.trim());
        if (transPath.trim()) params.set('path', transPath.trim());
      } else if (headerType === 'none') {
        params.set('headerType', 'none');
      }
    } else if (netType === 'ws' || netType === 'httpupgrade') {
      if (transHost.trim()) params.set('host', transHost.trim());
      if (transPath.trim()) params.set('path', transPath.trim());
    } else if (netType === 'grpc') {
      if (serviceName.trim()) params.set('serviceName', serviceName.trim());
      if (authority.trim()) params.set('authority', authority.trim());
      if (transMode.trim()) params.set('mode', transMode.trim());
    } else if (netType === 'xhttp') {
      if (transHost.trim()) params.set('host', transHost.trim());
      if (transPath.trim()) params.set('path', transPath.trim());
      if (transMode.trim()) params.set('mode', transMode.trim());
      const trimmedExtra = extraText.trim();
      if (trimmedExtra) {
        try {
          const parsed = JSON.parse(trimmedExtra);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            extraErr = '';
            params.set('extra', JSON.stringify(parsed));
          } else {
            extraErr = 'extra must be a JSON object ({ ... })';
            params.set('extra', trimmedExtra);
          }
        } catch {
          extraErr = 'Invalid JSON in extra parameter';
          params.set('extra', trimmedExtra);
        }
      } else {
        extraErr = '';
      }
    }

    for (const [k, v] of preservedParams) {
      if (!params.has(k)) params.set(k, v);
    }

    const hostPart = h.includes(':') && !h.startsWith('[') ? `[${h}]` : h;
    const qs = params.toString();
    const frag = remark.trim() ? `#${encodeURIComponent(remark.trim())}` : '';
    const rebuilt = `${scheme}://${encodeURIComponent(secret)}@${hostPart}:${p}${qs ? '?' + qs : ''}${frag}`;
    lastSyncedValue = rebuilt;
    value = rebuilt;
  }

  function formatExtraJSON(): void {
    const pe = prettyExtra(extraText);
    extraText = pe.text;
    extraErr = pe.err;
    if (!pe.err) rebuildLink();
  }

  $effect(() => {
    if (value !== lastSyncedValue) {
      lastSyncedValue = value;
      parseFromValue(value);
    }
  });
</script>

<div class="stack" style="gap: 12px">
  <div class="field">
    <div class="row-between">
      <label for="{idPrefix}-raw">Share Link URI</label>
      {#if canVisualEdit}
        <button type="button" class="btn btn-ghost btn-sm" onclick={() => (showEditor = !showEditor)}>
          {showEditor ? 'Hide Visual Settings' : 'Show Visual Settings'}
        </button>
      {/if}
    </div>
    <textarea
      id="{idPrefix}-raw"
      class="textarea"
      style="min-height: 76px; font-size: 12px"
      {placeholder}
      bind:value
      {required}
    ></textarea>
  </div>

  {#if preview}
    <div class="preview-box">
      <div class="row-between" style="flex-wrap: wrap; gap: 6px">
        <div class="row" style="gap: 7px">
          <span class="dot {preview.valid ? 'ok' : 'danger'}"></span>
          <strong style="font-size: 12.5px">{preview.name || preview.scheme}</strong>
          {#if preview.endpoint}
            <span class="mono hint" style="font-size: 11.5px">{preview.endpoint}</span>
          {/if}
        </div>
        <div class="row" style="gap: 5px; flex-wrap: wrap">
          {#each preview.badges as b}
            <span class="badge {b.tone}" style="font-size: 10.5px; padding: 1px 7px">{b.label}</span>
          {/each}
        </div>
      </div>
      {#if preview.warning}
        <span style="font-size: 11.5px; color: var(--warn)">{preview.warning}</span>
      {/if}
    </div>
  {/if}

  {#if canVisualEdit && showEditor}
    <!-- Section 1: Endpoint & Identity -->
    <div class="editor-section">
      <div class="editor-section-title">Endpoint &amp; Authentication ({scheme.toUpperCase()})</div>
      <div class="grid-3">
        <div class="field col-span-2">
          <label for="{idPrefix}-host">Server Address / Host</label>
          <input id="{idPrefix}-host" class="input mono" bind:value={host} oninput={rebuildLink} />
        </div>
        <div class="field">
          <label for="{idPrefix}-port">Port</label>
          <input id="{idPrefix}-port" class="input mono" bind:value={port} oninput={rebuildLink} />
        </div>
      </div>

      <div class="grid-2">
        <div class="field">
          <div class="row-between">
            <label for="{idPrefix}-secret">{scheme === 'vless' ? 'UUID / ID' : 'Password'}</label>
            <button type="button" class="btn btn-ghost btn-sm" style="padding: 1px 6px; font-size: 11px" onclick={() => (showSecret = !showSecret)}>
              {showSecret ? 'Hide' : 'Show'}
            </button>
          </div>
          <input
            id="{idPrefix}-secret"
            class="input mono"
            type={showSecret ? 'text' : 'password'}
            bind:value={secret}
            oninput={rebuildLink}
          />
        </div>
        <div class="field">
          <label for="{idPrefix}-remark">Remark (#name)</label>
          <input id="{idPrefix}-remark" class="input" bind:value={remark} oninput={rebuildLink} />
        </div>
      </div>

      {#if scheme === 'vless'}
        <div class="grid-2">
          <div class="field">
            <label for="{idPrefix}-flow">VLESS Flow</label>
            <select id="{idPrefix}-flow" class="select mono" bind:value={flow} onchange={rebuildLink}>
              <option value="">(none)</option>
              <option value="xtls-rprx-vision">xtls-rprx-vision</option>
              <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
            </select>
          </div>
          <div class="field">
            <label for="{idPrefix}-enc">VLESS Encryption (none or PQ mlkem768…)</label>
            <input id="{idPrefix}-enc" class="input mono" bind:value={encryption} oninput={rebuildLink} />
          </div>
        </div>
      {/if}
    </div>

    <!-- Section 2: Transport -->
    <div class="editor-section">
      <div class="editor-section-title">Transport Layer</div>
      <div class="grid-2">
        <div class="field">
          <label for="{idPrefix}-type">Network Transport</label>
          <select id="{idPrefix}-type" class="select mono" bind:value={netType} onchange={rebuildLink}>
            <option value="tcp">tcp (raw)</option>
            <option value="xhttp">xhttp (splithttp)</option>
            <option value="ws">ws (WebSocket)</option>
            <option value="grpc">grpc</option>
            <option value="httpupgrade">httpupgrade</option>
          </select>
        </div>

        {#if netType === 'xhttp'}
          <div class="field">
            <label for="{idPrefix}-mode">XHTTP Mode</label>
            <select id="{idPrefix}-mode" class="select mono" bind:value={transMode} onchange={rebuildLink}>
              <option value="auto">auto</option>
              <option value="packet-up">packet-up</option>
              <option value="stream-up">stream-up</option>
              <option value="stream-one">stream-one</option>
            </select>
          </div>
        {:else if netType === 'grpc'}
          <div class="field">
            <label for="{idPrefix}-gmode">gRPC Mode</label>
            <select id="{idPrefix}-gmode" class="select mono" bind:value={transMode} onchange={rebuildLink}>
              <option value="gun">gun (single)</option>
              <option value="multi">multi</option>
            </select>
          </div>
        {:else if netType === 'tcp'}
          <div class="field">
            <label for="{idPrefix}-htype">TCP Header Type</label>
            <select id="{idPrefix}-htype" class="select mono" bind:value={headerType} onchange={rebuildLink}>
              <option value="none">none</option>
              <option value="http">http</option>
            </select>
          </div>
        {/if}
      </div>

      {#if netType === 'xhttp' || netType === 'ws' || netType === 'httpupgrade' || (netType === 'tcp' && headerType === 'http')}
        <div class="grid-2">
          <div class="field">
            <label for="{idPrefix}-thost">HTTP Host Header</label>
            <input id="{idPrefix}-thost" class="input mono" placeholder="optional" bind:value={transHost} oninput={rebuildLink} />
          </div>
          <div class="field">
            <label for="{idPrefix}-tpath">Path</label>
            <input id="{idPrefix}-tpath" class="input mono" placeholder="/" bind:value={transPath} oninput={rebuildLink} />
          </div>
        </div>
      {:else if netType === 'grpc'}
        <div class="grid-2">
          <div class="field">
            <label for="{idPrefix}-sname">gRPC Service Name</label>
            <input id="{idPrefix}-sname" class="input mono" bind:value={serviceName} oninput={rebuildLink} />
          </div>
          <div class="field">
            <label for="{idPrefix}-auth">gRPC Authority</label>
            <input id="{idPrefix}-auth" class="input mono" placeholder="optional" bind:value={authority} oninput={rebuildLink} />
          </div>
        </div>
      {/if}

      {#if netType === 'xhttp'}
        <div class="field">
          <div class="row-between">
            <label for="{idPrefix}-extra">XHTTP Extra JSON (XMUX, downloadSettings, padding)</label>
            <button type="button" class="btn btn-ghost btn-sm" style="padding: 1px 7px; font-size: 11px" onclick={formatExtraJSON}>
              Format JSON
            </button>
          </div>
          <textarea
            id="{idPrefix}-extra"
            class="textarea"
            style="min-height: 110px; font-size: 11.5px"
            placeholder={'{"xPaddingBytes":"100-500","noGRPCHeader":true}'}
            bind:value={extraText}
            oninput={rebuildLink}
          ></textarea>
          {#if extraErr}
            <span style="font-size: 11.5px; color: var(--danger)">{extraErr}</span>
          {:else if extraText.trim()}
            <span style="font-size: 11.5px; color: var(--ok)">Valid JSON object · auto-encoded into share link</span>
          {/if}
        </div>
      {/if}
    </div>

    <!-- Section 3: Security -->
    <div class="editor-section">
      <div class="editor-section-title">Security &amp; Cryptography</div>
      <div class="grid-3">
        <div class="field">
          <label for="{idPrefix}-sec">Security</label>
          <select id="{idPrefix}-sec" class="select mono" bind:value={security} onchange={rebuildLink}>
            <option value="reality">reality</option>
            <option value="tls">tls</option>
            <option value="none">none</option>
          </select>
        </div>

        {#if security === 'reality' || security === 'tls'}
          <div class="field">
            <label for="{idPrefix}-sni">SNI / Server Name</label>
            <input id="{idPrefix}-sni" class="input mono" placeholder="www.example.com" bind:value={sni} oninput={rebuildLink} />
          </div>
          <div class="field">
            <label for="{idPrefix}-fp">uTLS Fingerprint</label>
            <input
              id="{idPrefix}-fp"
              class="input mono"
              list="{idPrefix}-fp-list"
              placeholder="chrome"
              bind:value={fp}
              oninput={rebuildLink}
            />
            <datalist id="{idPrefix}-fp-list">
              <option value="chrome"></option>
              <option value="firefox"></option>
              <option value="safari"></option>
              <option value="ios"></option>
              <option value="android"></option>
              <option value="edge"></option>
              <option value="random"></option>
              <option value="randomized"></option>
            </datalist>
          </div>
        {/if}
      </div>

      {#if security === 'reality'}
        <div class="grid-2">
          <div class="field">
            <label for="{idPrefix}-pbk">REALITY Public Key (pbk)</label>
            <input id="{idPrefix}-pbk" class="input mono" bind:value={pbk} oninput={rebuildLink} />
          </div>
          <div class="field">
            <label for="{idPrefix}-sid">Short ID (sid)</label>
            <input id="{idPrefix}-sid" class="input mono" bind:value={sid} oninput={rebuildLink} />
          </div>
        </div>
        <div class="grid-2">
          <div class="field">
            <label for="{idPrefix}-spx">SpiderX (spx)</label>
            <input id="{idPrefix}-spx" class="input mono" placeholder="/" bind:value={spx} oninput={rebuildLink} />
          </div>
          <div class="field">
            <label for="{idPrefix}-pqv">Post-Quantum ML-DSA-65 (pqv)</label>
            <input id="{idPrefix}-pqv" class="input mono" placeholder="optional" bind:value={pqv} oninput={rebuildLink} />
          </div>
        </div>
      {:else if security === 'tls'}
        <div class="grid-2">
          <div class="field">
            <label for="{idPrefix}-alpn">ALPN</label>
            <input id="{idPrefix}-alpn" class="input mono" placeholder="h2,http/1.1" bind:value={alpn} oninput={rebuildLink} />
          </div>
          <div class="field">
            <label for="{idPrefix}-ech">TLS ECH Config List (ech)</label>
            <input id="{idPrefix}-ech" class="input mono" placeholder="optional" bind:value={ech} oninput={rebuildLink} />
          </div>
        </div>
        <div class="grid-2">
          <div class="field">
            <label for="{idPrefix}-pcs">Pinned Cert SHA-256 (pcs)</label>
            <input id="{idPrefix}-pcs" class="input mono" placeholder="Replaces allowInsecure safely" bind:value={pcs} oninput={rebuildLink} />
          </div>
          <div class="field">
            <label for="{idPrefix}-vcn">Verify Cert By Name (vcn)</label>
            <input id="{idPrefix}-vcn" class="input mono" placeholder="optional" bind:value={vcn} oninput={rebuildLink} />
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>
