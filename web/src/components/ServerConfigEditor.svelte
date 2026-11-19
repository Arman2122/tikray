<script lang="ts">
  import { KEEP_SECRET_SENTINEL } from '../lib/api';
  import { inspectShareLink } from '../lib/linkPreview';
  import { toast } from '../lib/toast.svelte';
  import Icon from './Icon.svelte';

  export interface ServerEditorResult {
    name: string;
    disabled: boolean;
    /** Set when user chose direct share-link submission (single or bulk). */
    link?: string;
    /** Set when submitting structured / JSON outbound config. */
    outbound?: Record<string, unknown>;
  }

  interface Props {
    mode: 'add' | 'edit';
    initialName?: string;
    initialDisabled?: boolean;
    initialOutbound?: Record<string, unknown> | null;
    saving?: boolean;
    onCancel: () => void;
    onSubmit: (result: ServerEditorResult) => Promise<void> | void;
  }

  let {
    mode,
    initialName = '',
    initialDisabled = false,
    initialOutbound = null,
    saving = false,
    onCancel,
    onSubmit
  }: Props = $props();

  type EditorTab = 'visual' | 'json' | 'link';

  let activeTab = $state<EditorTab>('visual');
  let alias = $state('');
  let disabled = $state(false);
  let showSecrets = $state(false);

  // Core protocol fields
  let protocol = $state('vless');
  let address = $state('');
  let port = $state('443');
  let uuid = $state('');
  let uuidSaved = $state(false);
  let password = $state('');
  let passwordSaved = $state(false);
  let flow = $state('');
  let encryption = $state('none');
  let encryptionSaved = $state(false);
  let vmessSecurity = $state('auto');
  let ssMethod = $state('2022-blake3-aes-128-gcm');

  // Mux
  let muxEnabled = $state(false);
  let muxConcurrency = $state('8');
  let muxXudpConcurrency = $state('16');
  let muxXudpProxyUDP443 = $state('reject');

  // Transport
  let network = $state('raw');
  let rawHeaderType = $state('none');
  let rawHttpHost = $state('');
  let rawHttpPath = $state('/');
  let xhttpMode = $state('auto');
  let xhttpHost = $state('');
  let xhttpPath = $state('/');
  let xhttpExtraText = $state('');
  let xhttpExtraErr = $state('');
  let wsHost = $state('');
  let wsPath = $state('/');
  let grpcServiceName = $state('');
  let grpcAuthority = $state('');
  let grpcMultiMode = $state(false);

  // Finalmask & Sockopt
  let showAdvancedTransport = $state(false);
  let finalmaskText = $state('');
  let finalmaskErr = $state('');
  let sockoptText = $state('');
  let sockoptErr = $state('');

  // TLS / REALITY
  let security = $state('reality');
  let sni = $state('');
  let fingerprint = $state('chrome');
  let publicKey = $state('');
  let publicKeySaved = $state(false);
  let shortId = $state('');
  let shortIdSaved = $state(false);
  let spiderX = $state('');
  let spiderXSaved = $state(false);
  let mldsa65 = $state('');
  let mldsa65Saved = $state(false);
  let alpn = $state('');
  let ech = $state('');
  let echSaved = $state(false);
  let pcs = $state('');
  let pcsSaved = $state(false);
  let vcn = $state('');

  // Lossless underlying JSON document + raw JSON editor text
  let baseDoc = $state<Record<string, unknown>>({});
  let jsonText = $state('');
  let jsonErr = $state('');
  let jsonDirty = $state(false);

  // Share link import/unpack tab
  let shareLinkInput = $state('');
  const sharePreview = $derived(shareLinkInput.trim() ? inspectShareLink(shareLinkInput.trim()) : null);

  function ciGet<T = unknown>(obj: unknown, key: string): T | undefined {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return undefined;
    const rec = obj as Record<string, unknown>;
    if (key in rec) return rec[key] as T;
    const lk = key.toLowerCase();
    for (const [k, v] of Object.entries(rec)) {
      if (k.toLowerCase() === lk) return v as T;
    }
    return undefined;
  }

  function asObj(v: unknown): Record<string, unknown> {
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  }

  function asStr(v: unknown, fallback = ''): string {
    return typeof v === 'string' ? v : fallback;
  }

  function splitSecret(raw: string): { value: string; saved: boolean } {
    if (raw === KEEP_SECRET_SENTINEL) {
      return { value: '', saved: true };
    }
    return { value: raw, saved: false };
  }

  function effectiveSecret(val: string, saved: boolean): string {
    const trimmed = val.trim();
    if (trimmed !== '') return trimmed;
    return saved ? KEEP_SECRET_SENTINEL : '';
  }

  function normalizeNetwork(n: string): string {
    const lo = n.trim().toLowerCase();
    if (!lo || lo === 'tcp') return 'raw';
    if (lo === 'splithttp') return 'xhttp';
    return lo;
  }

  function loadFromOutbound(raw: Record<string, unknown>, keepText = false): void {
    const clone = JSON.parse(JSON.stringify(raw)) as Record<string, unknown>;
    baseDoc = clone;

    const proto = asStr(ciGet(clone, 'protocol'), 'vless').toLowerCase();
    protocol = proto || 'vless';

    const settings = asObj(ciGet(clone, 'settings'));
    const vnext = ciGet<unknown[]>(settings, 'vnext');
    const servers = ciGet<unknown[]>(settings, 'servers');

    // Reset secret state before populating
    uuid = '';
    uuidSaved = false;
    password = '';
    passwordSaved = false;
    flow = '';
    encryption = 'none';
    encryptionSaved = false;
    vmessSecurity = 'auto';
    ssMethod = '2022-blake3-aes-128-gcm';

    if (Array.isArray(vnext) && vnext.length > 0) {
      const node = asObj(vnext[0]);
      address = asStr(ciGet(node, 'address'));
      const p = ciGet(node, 'port');
      port = p !== undefined && p !== null ? String(p) : '443';
      const users = ciGet<unknown[]>(node, 'users');
      if (Array.isArray(users) && users.length > 0) {
        const u = asObj(users[0]);
        const idSplit = splitSecret(asStr(ciGet(u, 'id')));
        uuid = idSplit.value;
        uuidSaved = idSplit.saved;
        flow = asStr(ciGet(u, 'flow'));
        const encRaw = asStr(ciGet(u, 'encryption'), 'none');
        const encSplit = splitSecret(encRaw);
        encryption = encSplit.saved ? '' : encSplit.value || 'none';
        encryptionSaved = encSplit.saved;
        vmessSecurity = asStr(ciGet(u, 'security'), 'auto');
      }
    } else if (Array.isArray(servers) && servers.length > 0) {
      const srv = asObj(servers[0]);
      address = asStr(ciGet(srv, 'address'));
      const p = ciGet(srv, 'port');
      port = p !== undefined && p !== null ? String(p) : '443';
      const pwSplit = splitSecret(asStr(ciGet(srv, 'password')));
      password = pwSplit.value;
      passwordSaved = pwSplit.saved;
      flow = asStr(ciGet(srv, 'flow'));
      ssMethod = asStr(ciGet(srv, 'method'), '2022-blake3-aes-128-gcm');
    } else {
      address = asStr(ciGet(settings, 'address'));
      const p = ciGet(settings, 'port');
      port = p !== undefined && p !== null ? String(p) : '443';
      const pwSplit = splitSecret(asStr(ciGet(settings, 'password')));
      password = pwSplit.value;
      passwordSaved = pwSplit.saved;
      const idSplit = splitSecret(asStr(ciGet(settings, 'id')));
      uuid = idSplit.value;
      uuidSaved = idSplit.saved;
      flow = asStr(ciGet(settings, 'flow'));
      const encRaw = asStr(ciGet(settings, 'encryption'), 'none');
      const encSplit = splitSecret(encRaw);
      encryption = encSplit.saved ? '' : encSplit.value || 'none';
      encryptionSaved = encSplit.saved;
      ssMethod = asStr(ciGet(settings, 'method'), '2022-blake3-aes-128-gcm');
    }

    // Mux
    const mux = asObj(ciGet(clone, 'mux'));
    muxEnabled = Boolean(ciGet(mux, 'enabled'));
    const conc = ciGet(mux, 'concurrency');
    muxConcurrency = conc !== undefined ? String(conc) : '8';
    const xudp = ciGet(mux, 'xudpConcurrency');
    muxXudpConcurrency = xudp !== undefined ? String(xudp) : '16';
    muxXudpProxyUDP443 = asStr(ciGet(mux, 'xudpProxyUDP443'), 'reject');

    // Stream settings
    const stream = asObj(ciGet(clone, 'streamSettings'));
    network = normalizeNetwork(asStr(ciGet(stream, 'network'), 'raw'));
    security = asStr(ciGet(stream, 'security'), 'none').toLowerCase() || 'none';

    const rawSet = asObj(ciGet(stream, 'rawSettings') ?? ciGet(stream, 'tcpSettings'));
    const header = asObj(ciGet(rawSet, 'header'));
    rawHeaderType = asStr(ciGet(header, 'type'), 'none') || 'none';
    const req = asObj(ciGet(header, 'request'));
    const reqPath = ciGet(req, 'path');
    rawHttpPath = Array.isArray(reqPath) && reqPath[0] ? String(reqPath[0]) : asStr(reqPath, '/');
    const reqHdrs = asObj(ciGet(req, 'headers'));
    const reqHost = ciGet(reqHdrs, 'Host');
    rawHttpHost = Array.isArray(reqHost) && reqHost[0] ? String(reqHost[0]) : asStr(reqHost);

    const xhttp = asObj(ciGet(stream, 'xhttpSettings') ?? ciGet(stream, 'splithttpSettings'));
    xhttpMode = asStr(ciGet(xhttp, 'mode'), 'auto') || 'auto';
    xhttpHost = asStr(ciGet(xhttp, 'host'));
    xhttpPath = asStr(ciGet(xhttp, 'path'), '/');
    const extraObj = ciGet(xhttp, 'extra');
    xhttpExtraText = extraObj ? JSON.stringify(extraObj, null, 2) : '';
    xhttpExtraErr = '';

    const ws = asObj(ciGet(stream, 'wsSettings') ?? ciGet(stream, 'httpupgradeSettings'));
    wsHost = asStr(ciGet(ws, 'host'));
    wsPath = asStr(ciGet(ws, 'path'), '/');

    const grpc = asObj(ciGet(stream, 'grpcSettings'));
    grpcServiceName = asStr(ciGet(grpc, 'serviceName'));
    grpcAuthority = asStr(ciGet(grpc, 'authority'));
    grpcMultiMode = Boolean(ciGet(grpc, 'multiMode'));

    const fm = ciGet(stream, 'finalmask');
    finalmaskText = fm ? JSON.stringify(fm, null, 2) : '';
    finalmaskErr = '';

    const so = ciGet(stream, 'sockopt');
    sockoptText = so ? JSON.stringify(so, null, 2) : '';
    sockoptErr = '';
    showAdvancedTransport = Boolean(fm || so);

    // TLS / REALITY
    sni = '';
    fingerprint = '';
    publicKey = '';
    publicKeySaved = false;
    shortId = '';
    shortIdSaved = false;
    spiderX = '';
    spiderXSaved = false;
    mldsa65 = '';
    mldsa65Saved = false;
    alpn = '';
    ech = '';
    echSaved = false;
    pcs = '';
    pcsSaved = false;
    vcn = '';

    const reality = asObj(ciGet(stream, 'realitySettings'));
    const tls = asObj(ciGet(stream, 'tlsSettings'));

    if (security === 'reality') {
      sni = asStr(ciGet(reality, 'serverName'));
      fingerprint = asStr(ciGet(reality, 'fingerprint'), 'chrome');
      const pbkS = splitSecret(asStr(ciGet(reality, 'publicKey')));
      publicKey = pbkS.value;
      publicKeySaved = pbkS.saved;
      const sidS = splitSecret(asStr(ciGet(reality, 'shortId')));
      shortId = sidS.value;
      shortIdSaved = sidS.saved;
      const spxS = splitSecret(asStr(ciGet(reality, 'spiderX')));
      spiderX = spxS.value;
      spiderXSaved = spxS.saved;
      const pqS = splitSecret(asStr(ciGet(reality, 'mldsa65Verify')));
      mldsa65 = pqS.value;
      mldsa65Saved = pqS.saved;
    } else if (security === 'tls') {
      sni = asStr(ciGet(tls, 'serverName'));
      fingerprint = asStr(ciGet(tls, 'fingerprint'), 'chrome');
      const alpnArr = ciGet<unknown[]>(tls, 'alpn');
      alpn = Array.isArray(alpnArr) ? alpnArr.map(String).join(',') : '';
      const echS = splitSecret(asStr(ciGet(tls, 'echConfigList')));
      ech = echS.value;
      echSaved = echS.saved;
      const pcsS = splitSecret(asStr(ciGet(tls, 'pinnedPeerCertSha256')));
      pcs = pcsS.value;
      pcsSaved = pcsS.saved;
      vcn = asStr(ciGet(tls, 'verifyPeerCertByName'));
    }

    if (!keepText) {
      jsonText = JSON.stringify(clone, null, 2);
    }
    jsonErr = '';
    jsonDirty = false;
  }

  function buildOutbound(): Record<string, unknown> {
    // Start from a deep copy of baseDoc so custom/advanced xray fields survive edits.
    const doc = (baseDoc && typeof baseDoc === 'object'
      ? JSON.parse(JSON.stringify(baseDoc))
      : {}) as Record<string, unknown>;
    delete doc.tag;

    const proto = protocol.trim().toLowerCase() || 'vless';
    doc.protocol = proto;

    const portNum = Number.parseInt(port.trim(), 10) || 443;
    const addr = address.trim();

    if (proto === 'vless') {
      const idVal = effectiveSecret(uuid, uuidSaved);
      const encVal = encryption.trim() ? encryption.trim() : encryptionSaved ? KEEP_SECRET_SENTINEL : 'none';
      const user: Record<string, unknown> = { id: idVal, encryption: encVal };
      if (flow.trim()) user.flow = flow.trim();
      doc.settings = { vnext: [{ address: addr, port: portNum, users: [user] }] };
    } else if (proto === 'vmess') {
      const idVal = effectiveSecret(uuid, uuidSaved);
      doc.settings = {
        vnext: [{ address: addr, port: portNum, users: [{ id: idVal, security: vmessSecurity || 'auto' }] }]
      };
    } else if (proto === 'trojan') {
      const pwVal = effectiveSecret(password, passwordSaved);
      const srv: Record<string, unknown> = { address: addr, port: portNum, password: pwVal };
      if (flow.trim()) srv.flow = flow.trim();
      doc.settings = { servers: [srv] };
    } else if (proto === 'shadowsocks') {
      const pwVal = effectiveSecret(password, passwordSaved);
      doc.settings = {
        servers: [{ address: addr, port: portNum, method: ssMethod || '2022-blake3-aes-128-gcm', password: pwVal }]
      };
    }

    // Mux
    if (muxEnabled) {
      const c = Number.parseInt(muxConcurrency, 10);
      const xc = Number.parseInt(muxXudpConcurrency, 10);
      doc.mux = {
        enabled: true,
        concurrency: Number.isFinite(c) && c !== 0 ? c : 8,
        xudpConcurrency: Number.isFinite(xc) && xc > 0 ? xc : 16,
        xudpProxyUDP443: muxXudpProxyUDP443 || 'reject'
      };
    } else {
      delete doc.mux;
    }

    // Stream settings (preserve unknown streamSettings keys like unknown future xray fields)
    const prevStream = asObj(doc.streamSettings);
    const stream: Record<string, unknown> = { ...prevStream };
    const net = normalizeNetwork(network);
    stream.network = net;
    stream.security = security || 'none';

    delete stream.rawSettings;
    delete stream.tcpSettings;
    delete stream.xhttpSettings;
    delete stream.splithttpSettings;
    delete stream.wsSettings;
    delete stream.httpupgradeSettings;
    delete stream.grpcSettings;

    if (net === 'raw') {
      if (rawHeaderType === 'http') {
        const hdr: Record<string, unknown> = {
          type: 'http',
          request: {
            path: [rawHttpPath.trim() || '/'],
            ...(rawHttpHost.trim() ? { headers: { Host: [rawHttpHost.trim()] } } : {})
          }
        };
        stream.rawSettings = { header: hdr };
      }
    } else if (net === 'xhttp') {
      const xs: Record<string, unknown> = { mode: xhttpMode || 'auto' };
      if (xhttpHost.trim()) xs.host = xhttpHost.trim();
      if (xhttpPath.trim()) xs.path = xhttpPath.trim();
      if (xhttpExtraText.trim()) {
        try {
          const parsedExtra = JSON.parse(xhttpExtraText);
          if (parsedExtra && typeof parsedExtra === 'object' && !Array.isArray(parsedExtra)) {
            xs.extra = parsedExtra;
            xhttpExtraErr = '';
          } else {
            xhttpExtraErr = 'Extra must be a JSON object ({ ... })';
          }
        } catch {
          xhttpExtraErr = 'Invalid JSON in XHTTP extra';
        }
      } else {
        xhttpExtraErr = '';
      }
      stream.xhttpSettings = xs;
    } else if (net === 'ws') {
      const ws: Record<string, unknown> = { path: wsPath.trim() || '/' };
      if (wsHost.trim()) ws.host = wsHost.trim();
      stream.wsSettings = ws;
    } else if (net === 'httpupgrade') {
      const hu: Record<string, unknown> = { path: wsPath.trim() || '/' };
      if (wsHost.trim()) hu.host = wsHost.trim();
      stream.httpupgradeSettings = hu;
    } else if (net === 'grpc') {
      const gr: Record<string, unknown> = { serviceName: grpcServiceName.trim() };
      if (grpcAuthority.trim()) gr.authority = grpcAuthority.trim();
      if (grpcMultiMode) gr.multiMode = true;
      stream.grpcSettings = gr;
    }

    // Finalmask & sockopt
    if (finalmaskText.trim()) {
      try {
        stream.finalmask = JSON.parse(finalmaskText);
        finalmaskErr = '';
      } catch {
        finalmaskErr = 'Invalid JSON in finalmask';
      }
    } else {
      delete stream.finalmask;
      finalmaskErr = '';
    }
    if (sockoptText.trim()) {
      try {
        stream.sockopt = JSON.parse(sockoptText);
        sockoptErr = '';
      } catch {
        sockoptErr = 'Invalid JSON in sockopt';
      }
    } else {
      delete stream.sockopt;
      sockoptErr = '';
    }

    // Security settings
    delete stream.tlsSettings;
    delete stream.realitySettings;
    if (security === 'reality') {
      const rs: Record<string, unknown> = {};
      if (sni.trim()) rs.serverName = sni.trim();
      if (fingerprint.trim()) rs.fingerprint = fingerprint.trim();
      const pbkV = effectiveSecret(publicKey, publicKeySaved);
      if (pbkV) rs.publicKey = pbkV;
      const sidV = effectiveSecret(shortId, shortIdSaved);
      if (sidV) rs.shortId = sidV;
      const spxV = effectiveSecret(spiderX, spiderXSaved);
      if (spxV) rs.spiderX = spxV;
      const pqV = effectiveSecret(mldsa65, mldsa65Saved);
      if (pqV) rs.mldsa65Verify = pqV;
      stream.realitySettings = rs;
    } else if (security === 'tls') {
      const ts: Record<string, unknown> = {};
      if (sni.trim()) ts.serverName = sni.trim();
      if (fingerprint.trim()) ts.fingerprint = fingerprint.trim();
      const alpnList = alpn
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (alpnList.length > 0) ts.alpn = alpnList;
      const echV = effectiveSecret(ech, echSaved);
      if (echV) ts.echConfigList = echV;
      const pcsV = effectiveSecret(pcs, pcsSaved);
      if (pcsV) ts.pinnedPeerCertSha256 = pcsV;
      if (vcn.trim()) ts.verifyPeerCertByName = vcn.trim();
      stream.tlsSettings = ts;
    }

    doc.streamSettings = stream;
    return doc;
  }

  function syncVisualToJSON(): void {
    const built = buildOutbound();
    baseDoc = built;
    jsonText = JSON.stringify(built, null, 2);
    jsonErr = '';
    jsonDirty = false;
  }

  function handleJSONInput(): void {
    jsonDirty = true;
    try {
      const parsed = JSON.parse(jsonText);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        jsonErr = 'Root value must be an Xray outbound JSON object ({ ... })';
        return;
      }
      jsonErr = '';
      loadFromOutbound(parsed as Record<string, unknown>, true);
      jsonDirty = false;
    } catch (err) {
      jsonErr = err instanceof Error ? err.message : 'Invalid JSON syntax';
    }
  }

  function formatJSONEditor(pretty: boolean): void {
    try {
      const parsed = JSON.parse(jsonText);
      jsonText = pretty ? JSON.stringify(parsed, null, 2) : JSON.stringify(parsed);
      jsonErr = '';
    } catch {
      toast.warn('Fix JSON syntax errors before formatting.');
    }
  }

  async function copyJSON(): Promise<void> {
    try {
      await navigator.clipboard.writeText(jsonText);
      toast.ok('Copied sanitized outbound JSON.');
    } catch {
      toast.warn('Clipboard unavailable in this browser context.');
    }
  }

  function generateUUID(): void {
    const gen =
      typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
            const r = (Math.random() * 16) | 0;
            return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
          });
    uuid = gen;
    uuidSaved = false;
    syncVisualToJSON();
  }

  function unpackShareLinkToEditor(): void {
    const raw = shareLinkInput.trim();
    if (!raw) {
      toast.warn('Paste a share link first.');
      return;
    }
    try {
      const u = new URL(raw);
      const sch = u.protocol.replace(/:$/, '').toLowerCase();
      if (sch !== 'vless' && sch !== 'trojan') {
        toast.info(`Click Confirm to import ${sch.toUpperCase()} link directly (visual unpack supports VLESS & Trojan).`);
        return;
      }
      const q = u.searchParams;
      const next: Record<string, unknown> = { protocol: sch };
      const pNum = Number.parseInt(u.port || '443', 10) || 443;
      const h = u.hostname.replace(/^\[|\]$/g, '');
      const userStr = decodeURIComponent(u.username || '');
      if (u.hash && !alias.trim()) {
        alias = decodeURIComponent(u.hash.slice(1));
      }

      if (sch === 'vless') {
        const user: Record<string, unknown> = {
          id: userStr,
          encryption: q.get('encryption') || 'none'
        };
        if (q.get('flow')) user.flow = q.get('flow');
        next.settings = { vnext: [{ address: h, port: pNum, users: [user] }] };
      } else {
        const srv: Record<string, unknown> = { address: h, port: pNum, password: userStr };
        if (q.get('flow')) srv.flow = q.get('flow');
        next.settings = { servers: [srv] };
      }

      const net = normalizeNetwork(q.get('type') || 'raw');
      const sec = (q.get('security') || (sch === 'trojan' ? 'tls' : 'none')).toLowerCase();
      const stream: Record<string, unknown> = { network: net, security: sec };

      if (net === 'raw' && (q.get('headerType') || '').toLowerCase() === 'http') {
        stream.rawSettings = {
          header: {
            type: 'http',
            request: {
              path: [q.get('path') || '/'],
              ...(q.get('host') ? { headers: { Host: [q.get('host')] } } : {})
            }
          }
        };
      } else if (net === 'xhttp') {
        const xs: Record<string, unknown> = { mode: q.get('mode') || 'auto' };
        if (q.get('host')) xs.host = q.get('host');
        if (q.get('path')) xs.path = q.get('path');
        if (q.get('extra')) {
          try {
            xs.extra = JSON.parse(q.get('extra')!);
          } catch {
            // ignore invalid extra here; user can refine in editor
          }
        }
        stream.xhttpSettings = xs;
      } else if (net === 'ws' || net === 'httpupgrade') {
        const key = net === 'ws' ? 'wsSettings' : 'httpupgradeSettings';
        stream[key] = { path: q.get('path') || '/', ...(q.get('host') ? { host: q.get('host') } : {}) };
      } else if (net === 'grpc') {
        stream.grpcSettings = {
          serviceName: q.get('serviceName') || '',
          ...(q.get('authority') ? { authority: q.get('authority') } : {}),
          ...(q.get('mode') === 'multi' ? { multiMode: true } : {})
        };
      }

      if (sec === 'reality') {
        stream.realitySettings = {
          ...(q.get('sni') ? { serverName: q.get('sni') } : {}),
          ...(q.get('fp') ? { fingerprint: q.get('fp') } : {}),
          ...(q.get('pbk') ? { publicKey: q.get('pbk') } : {}),
          ...(q.get('sid') ? { shortId: q.get('sid') } : {}),
          ...(q.get('spx') ? { spiderX: q.get('spx') } : {}),
          ...(q.get('pqv') ? { mldsa65Verify: q.get('pqv') } : {})
        };
      } else if (sec === 'tls') {
        const alpnList = (q.get('alpn') || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        stream.tlsSettings = {
          ...(q.get('sni') ? { serverName: q.get('sni') } : {}),
          ...(q.get('fp') ? { fingerprint: q.get('fp') } : {}),
          ...(alpnList.length > 0 ? { alpn: alpnList } : {}),
          ...(q.get('ech') ? { echConfigList: q.get('ech') } : {}),
          ...(q.get('pcs') ? { pinnedPeerCertSha256: q.get('pcs') } : {}),
          ...(q.get('vcn') ? { verifyPeerCertByName: q.get('vcn') } : {})
        };
      }

      next.streamSettings = stream;
      loadFromOutbound(next);
      activeTab = 'visual';
      toast.ok('Share link unpacked into Visual Config & JSON Editor.');
    } catch {
      toast.warn('Could not parse share link URI.');
    }
  }

  function switchTab(next: EditorTab): void {
    if (activeTab === 'visual' && next === 'json') {
      syncVisualToJSON();
    } else if (activeTab === 'json' && next === 'visual' && jsonErr) {
      toast.warn('Fix JSON syntax errors before switching to Visual Config.');
      return;
    }
    activeTab = next;
  }

  async function handleSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (activeTab === 'link') {
      const link = shareLinkInput.trim();
      if (!link) {
        toast.warn('Paste a share link or switch to Visual Config / JSON Editor.');
        return;
      }
      await onSubmit({ name: alias.trim(), disabled, link });
      return;
    }

    if (activeTab === 'json') {
      if (jsonErr) {
        toast.err(`Invalid JSON: ${jsonErr}`);
        return;
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(jsonText) as Record<string, unknown>;
      } catch {
        toast.err('Outbound JSON is not valid.');
        return;
      }
      await onSubmit({ name: alias.trim(), disabled, outbound: parsed });
      return;
    }

    // Visual mode
    if (xhttpExtraErr || finalmaskErr || sockoptErr) {
      toast.err(xhttpExtraErr || finalmaskErr || sockoptErr);
      return;
    }
    const built = buildOutbound();
    if (!address.trim()) {
      toast.warn('Server Address is required.');
      return;
    }
    if (mode === 'add') {
      if ((protocol === 'vless' || protocol === 'vmess') && !uuid.trim()) {
        toast.warn('UUID is required (click Generate or paste one).');
        return;
      }
      if ((protocol === 'trojan' || protocol === 'shadowsocks') && !password.trim()) {
        toast.warn('Password is required.');
        return;
      }
    }
    await onSubmit({ name: alias.trim(), disabled, outbound: built });
  }

  // Initialize from props once on mount / prop change
  let hydratedKey = '';
  $effect(() => {
    const key = `${mode}|${initialName}|${initialDisabled}|${initialOutbound ? JSON.stringify(initialOutbound) : ''}`;
    if (key === hydratedKey) return;
    hydratedKey = key;
    alias = initialName;
    disabled = initialDisabled;
    if (initialOutbound) {
      loadFromOutbound(initialOutbound);
    } else {
      loadFromOutbound({
        protocol: 'vless',
        settings: { vnext: [{ address: '', port: 443, users: [{ id: '', encryption: 'none' }] }] },
        streamSettings: { network: 'raw', security: 'reality', realitySettings: { fingerprint: 'chrome' } }
      });
    }
  });
</script>

<form class="stack" style="gap: 14px" onsubmit={handleSubmit}>
  <!-- Clean Segmented Mode Bar -->
  <div class="row-between" style="gap: 10px">
    <div class="tabs" role="tablist">
      <button type="button" class="tab {activeTab === 'visual' ? 'active' : ''}" role="tab" onclick={() => switchTab('visual')}>
        Visual Config
      </button>
      <button type="button" class="tab {activeTab === 'json' ? 'active' : ''}" role="tab" onclick={() => switchTab('json')}>
        JSON Editor
      </button>
      <button type="button" class="tab {activeTab === 'link' ? 'active' : ''}" role="tab" onclick={() => switchTab('link')}>
        {mode === 'edit' ? 'Replace via Share Link' : 'Import Share Link'}
      </button>
    </div>

    {#if activeTab === 'visual'}
      <span class="badge accent mono" style="text-transform: uppercase">{protocol}</span>
    {:else if activeTab === 'json'}
      <span class="badge {jsonErr ? 'danger' : 'ok'}">
        {jsonErr ? 'Syntax error' : 'Valid JSON'}
      </span>
    {/if}
  </div>

  {#if activeTab === 'visual'}
    <!-- Section 1: Configuration (v2rayN-style, Obsidian Pro polish) -->
    <div class="editor-section">
      <div class="row-between">
        <span class="editor-section-title">Configuration</span>
        <div class="row" style="gap: 12px">
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            style="padding: 2px 8px; font-size: 11px"
            onclick={() => (showSecrets = !showSecrets)}
          >
            {showSecrets ? 'Hide secrets' : 'Show secrets'}
          </button>
          {#if mode === 'edit'}
            <label class="switch" title="Enable or disable this server">
              <input class="switch-input" type="checkbox" checked={!disabled} onchange={(e) => (disabled = !(e.currentTarget as HTMLInputElement).checked)} />
              <span class="switch-track"></span>
              <span style="font-size: 12px; color: var(--text-muted)">{disabled ? 'Disabled' : 'Enabled'}</span>
            </label>
          {/if}
        </div>
      </div>

      <div class="cfg-grid">
        <label class="cfg-label" for="cfg-alias">Alias (remarks)</label>
        <div class="cfg-control">
          <input id="cfg-alias" class="input" placeholder="e.g. Frankfurt REALITY" bind:value={alias} required={mode === 'add'} />
        </div>

        <label class="cfg-label" for="cfg-proto">Protocol</label>
        <div class="cfg-control">
          <select id="cfg-proto" class="select mono" bind:value={protocol} onchange={syncVisualToJSON}>
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
          </select>
        </div>

        <label class="cfg-label" for="cfg-addr">Address</label>
        <div class="cfg-control">
          <input id="cfg-addr" class="input mono" placeholder="server.example.com or IP" bind:value={address} oninput={syncVisualToJSON} required />
        </div>

        <label class="cfg-label" for="cfg-port">Port</label>
        <div class="cfg-control">
          <input id="cfg-port" class="input mono" style="max-width: 150px" type="number" min="1" max="65535" bind:value={port} oninput={syncVisualToJSON} required />
        </div>

        {#if protocol === 'vless' || protocol === 'vmess'}
          <label class="cfg-label" for="cfg-uuid">
            <span>UUID (id)</span>
            {#if uuidSaved && !uuid}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-uuid"
              class="input mono"
              type={showSecrets ? 'text' : 'password'}
              placeholder={uuidSaved ? 'Saved — leave blank to keep current UUID' : 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'}
              bind:value={uuid}
              oninput={syncVisualToJSON}
            />
            <button type="button" class="btn btn-sm" onclick={generateUUID}>Generate</button>
          </div>
        {:else}
          <label class="cfg-label" for="cfg-pass">
            <span>Password</span>
            {#if passwordSaved && !password}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-pass"
              class="input mono"
              type={showSecrets ? 'text' : 'password'}
              placeholder={passwordSaved ? 'Saved — leave blank to keep current password' : 'Enter password / secret'}
              bind:value={password}
              oninput={syncVisualToJSON}
            />
          </div>
        {/if}

        {#if protocol === 'vless' || protocol === 'trojan'}
          <label class="cfg-label" for="cfg-flow">Flow</label>
          <div class="cfg-control">
            <select id="cfg-flow" class="select mono" bind:value={flow} onchange={syncVisualToJSON}>
              <option value="">(none)</option>
              <option value="xtls-rprx-vision">xtls-rprx-vision</option>
              <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
            </select>
          </div>
        {/if}

        {#if protocol === 'vless'}
          <label class="cfg-label" for="cfg-enc">
            <span>Encryption</span>
            {#if encryptionSaved && !encryption}
              <span class="saved-pill">PQ Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-enc"
              class="input mono"
              placeholder={encryptionSaved ? 'Saved PQ encryption key — leave blank to keep' : 'none'}
              bind:value={encryption}
              oninput={syncVisualToJSON}
            />
          </div>
        {:else if protocol === 'vmess'}
          <label class="cfg-label" for="cfg-vmess-sec">Security</label>
          <div class="cfg-control">
            <select id="cfg-vmess-sec" class="select mono" bind:value={vmessSecurity} onchange={syncVisualToJSON}>
              <option value="auto">auto</option>
              <option value="aes-128-gcm">aes-128-gcm</option>
              <option value="chacha20-poly1305">chacha20-poly1305</option>
              <option value="none">none</option>
              <option value="zero">zero</option>
            </select>
          </div>
        {:else if protocol === 'shadowsocks'}
          <label class="cfg-label" for="cfg-ss-method">Cipher Method</label>
          <div class="cfg-control">
            <select id="cfg-ss-method" class="select mono" bind:value={ssMethod} onchange={syncVisualToJSON}>
              <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
              <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
              <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
              <option value="aes-256-gcm">aes-256-gcm</option>
              <option value="aes-128-gcm">aes-128-gcm</option>
              <option value="chacha20-poly1305">chacha20-poly1305</option>
            </select>
          </div>
        {/if}

        <span class="cfg-label">Turn on Mux Multiplexing</span>
        <div class="cfg-control">
          <label class="switch">
            <input class="switch-input" type="checkbox" bind:checked={muxEnabled} onchange={syncVisualToJSON} />
            <span class="switch-track"></span>
            <span class="hint">{muxEnabled ? 'Enabled' : 'Off (recommended with XTLS Vision / XHTTP)'}</span>
          </label>
        </div>

        {#if muxEnabled}
          <label class="cfg-label" for="cfg-mux-conc">Mux Concurrency</label>
          <div class="cfg-control">
            <input id="cfg-mux-conc" class="input mono" style="max-width: 110px" type="number" bind:value={muxConcurrency} oninput={syncVisualToJSON} />
            <span class="hint">XUDP</span>
            <input class="input mono" style="max-width: 110px" type="number" bind:value={muxXudpConcurrency} oninput={syncVisualToJSON} aria-label="XUDP Concurrency" />
            <select class="select mono" style="max-width: 120px" bind:value={muxXudpProxyUDP443} onchange={syncVisualToJSON} aria-label="XUDP UDP 443">
              <option value="reject">reject 443</option>
              <option value="allow">allow 443</option>
              <option value="skip">skip 443</option>
            </select>
          </div>
        {/if}
      </div>
    </div>

    <!-- Section 2: Transport -->
    <div class="editor-section">
      <div class="row-between">
        <span class="editor-section-title">Transport</span>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          style="padding: 2px 8px; font-size: 11px"
          onclick={() => (showAdvancedTransport = !showAdvancedTransport)}
        >
          Finalmask / Sockopt {finalmaskText.trim() || sockoptText.trim() ? '●' : ''} {showAdvancedTransport ? '▴' : '▾'}
        </button>
      </div>

      <div class="cfg-grid">
        <label class="cfg-label" for="cfg-net">Transport protocol</label>
        <div class="cfg-control">
          <select id="cfg-net" class="select mono" bind:value={network} onchange={syncVisualToJSON}>
            <option value="raw">raw (tcp)</option>
            <option value="xhttp">xhttp (splithttp)</option>
            <option value="ws">ws (WebSocket)</option>
            <option value="grpc">grpc</option>
            <option value="httpupgrade">httpupgrade</option>
            <option value="kcp">kcp</option>
          </select>
          <span class="hint hide-xs" style="white-space: nowrap">*Default raw</span>
        </div>

        {#if network === 'raw'}
          <label class="cfg-label" for="cfg-raw-type">raw camouflage type</label>
          <div class="cfg-control">
            <select id="cfg-raw-type" class="select mono" bind:value={rawHeaderType} onchange={syncVisualToJSON}>
              <option value="none">none</option>
              <option value="http">http</option>
            </select>
          </div>
          {#if rawHeaderType === 'http'}
            <label class="cfg-label" for="cfg-raw-host">HTTP Host</label>
            <div class="cfg-control">
              <input id="cfg-raw-host" class="input mono" placeholder="optional" bind:value={rawHttpHost} oninput={syncVisualToJSON} />
            </div>
            <label class="cfg-label" for="cfg-raw-path">HTTP Path</label>
            <div class="cfg-control">
              <input id="cfg-raw-path" class="input mono" placeholder="/" bind:value={rawHttpPath} oninput={syncVisualToJSON} />
            </div>
          {/if}
        {:else if network === 'xhttp'}
          <label class="cfg-label" for="cfg-xh-mode">XHTTP Mode</label>
          <div class="cfg-control">
            <select id="cfg-xh-mode" class="select mono" bind:value={xhttpMode} onchange={syncVisualToJSON}>
              <option value="auto">auto</option>
              <option value="packet-up">packet-up</option>
              <option value="stream-up">stream-up</option>
              <option value="stream-one">stream-one</option>
            </select>
          </div>
          <label class="cfg-label" for="cfg-xh-host">Host</label>
          <div class="cfg-control">
            <input id="cfg-xh-host" class="input mono" placeholder="optional" bind:value={xhttpHost} oninput={syncVisualToJSON} />
          </div>
          <label class="cfg-label" for="cfg-xh-path">Path</label>
          <div class="cfg-control">
            <input id="cfg-xh-path" class="input mono" placeholder="/" bind:value={xhttpPath} oninput={syncVisualToJSON} />
          </div>
          <label class="cfg-label" for="cfg-xh-extra">XHTTP Extra JSON</label>
          <div class="stack" style="gap: 4px; min-width: 0">
            <textarea
              id="cfg-xh-extra"
              class="textarea"
              style="min-height: 92px; font-size: 11.5px"
              placeholder={'{"xPaddingBytes":"100-1000","downloadSettings":{...}}'}
              bind:value={xhttpExtraText}
              oninput={syncVisualToJSON}
            ></textarea>
            {#if xhttpExtraErr}
              <span style="font-size: 11.5px; color: var(--danger)">{xhttpExtraErr}</span>
            {/if}
          </div>
        {:else if network === 'ws' || network === 'httpupgrade'}
          <label class="cfg-label" for="cfg-ws-host">Host</label>
          <div class="cfg-control">
            <input id="cfg-ws-host" class="input mono" placeholder="optional" bind:value={wsHost} oninput={syncVisualToJSON} />
          </div>
          <label class="cfg-label" for="cfg-ws-path">Path</label>
          <div class="cfg-control">
            <input id="cfg-ws-path" class="input mono" placeholder="/" bind:value={wsPath} oninput={syncVisualToJSON} />
          </div>
        {:else if network === 'grpc'}
          <label class="cfg-label" for="cfg-gr-svc">Service Name</label>
          <div class="cfg-control">
            <input id="cfg-gr-svc" class="input mono" bind:value={grpcServiceName} oninput={syncVisualToJSON} />
          </div>
          <label class="cfg-label" for="cfg-gr-auth">Authority</label>
          <div class="cfg-control">
            <input id="cfg-gr-auth" class="input mono" placeholder="optional" bind:value={grpcAuthority} oninput={syncVisualToJSON} />
          </div>
          <span class="cfg-label">Multi Mode</span>
          <div class="cfg-control">
            <label class="switch">
              <input class="switch-input" type="checkbox" bind:checked={grpcMultiMode} onchange={syncVisualToJSON} />
              <span class="switch-track"></span>
              <span class="hint">{grpcMultiMode ? 'multi' : 'gun (single)'}</span>
            </label>
          </div>
        {/if}

        {#if showAdvancedTransport}
          <label class="cfg-label" for="cfg-fm">Finalmask JSON</label>
          <div class="stack" style="gap: 4px; min-width: 0">
            <textarea
              id="cfg-fm"
              class="textarea"
              style="min-height: 74px; font-size: 11.5px"
              placeholder={'Optional xray-core 26.x finalmask object (leave blank for none)'}
              bind:value={finalmaskText}
              oninput={syncVisualToJSON}
            ></textarea>
            {#if finalmaskErr}
              <span style="font-size: 11.5px; color: var(--danger)">{finalmaskErr}</span>
            {/if}
          </div>

          <label class="cfg-label" for="cfg-so">Sockopt JSON</label>
          <div class="stack" style="gap: 4px; min-width: 0">
            <textarea
              id="cfg-so"
              class="textarea"
              style="min-height: 74px; font-size: 11.5px"
              placeholder={'Optional sockopt object, e.g. {"tcpKeepAliveIdle":100}'}
              bind:value={sockoptText}
              oninput={syncVisualToJSON}
            ></textarea>
            {#if sockoptErr}
              <span style="font-size: 11.5px; color: var(--danger)">{sockoptErr}</span>
            {/if}
          </div>
        {/if}
      </div>
    </div>

    <!-- Section 3: TLS / REALITY -->
    <div class="editor-section">
      <span class="editor-section-title">TLS &amp; Security</span>
      <div class="cfg-grid">
        <label class="cfg-label" for="cfg-sec">TLS</label>
        <div class="cfg-control">
          <select id="cfg-sec" class="select mono" bind:value={security} onchange={syncVisualToJSON}>
            <option value="reality">reality</option>
            <option value="tls">tls</option>
            <option value="none">none</option>
          </select>
        </div>

        {#if security === 'reality' || security === 'tls'}
          <label class="cfg-label" for="cfg-sni">SNI</label>
          <div class="cfg-control">
            <input id="cfg-sni" class="input mono" placeholder="www.example.com" bind:value={sni} oninput={syncVisualToJSON} />
          </div>

          <label class="cfg-label" for="cfg-fp">Fingerprint</label>
          <div class="cfg-control">
            <input id="cfg-fp" class="input mono" list="cfg-fp-list" placeholder="chrome" bind:value={fingerprint} oninput={syncVisualToJSON} />
            <datalist id="cfg-fp-list">
              <option value="chrome"></option>
              <option value="firefox"></option>
              <option value="safari"></option>
              <option value="ios"></option>
              <option value="android"></option>
              <option value="edge"></option>
              <option value="qq"></option>
              <option value="360"></option>
              <option value="random"></option>
              <option value="randomized"></option>
            </datalist>
          </div>
        {/if}

        {#if security === 'reality'}
          <label class="cfg-label" for="cfg-pbk">
            <span>Public Key</span>
            {#if publicKeySaved && !publicKey}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-pbk"
              class="input mono"
              placeholder={publicKeySaved ? 'Saved — leave blank to keep current Public Key' : 'REALITY publicKey (pbk)'}
              bind:value={publicKey}
              oninput={syncVisualToJSON}
            />
          </div>

          <label class="cfg-label" for="cfg-sid">
            <span>Short Id</span>
            {#if shortIdSaved && !shortId}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-sid"
              class="input mono"
              placeholder={shortIdSaved ? 'Saved — leave blank to keep current Short Id' : 'optional hex shortId'}
              bind:value={shortId}
              oninput={syncVisualToJSON}
            />
          </div>

          <label class="cfg-label" for="cfg-spx">
            <span>SpiderX</span>
            {#if spiderXSaved && !spiderX}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-spx"
              class="input mono"
              placeholder={spiderXSaved ? 'Saved — leave blank to keep current SpiderX' : '/'}
              bind:value={spiderX}
              oninput={syncVisualToJSON}
            />
          </div>

          <label class="cfg-label" for="cfg-pqv">
            <span>ML-DSA-65 (pqv)</span>
            {#if mldsa65Saved && !mldsa65}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-pqv"
              class="input mono"
              placeholder={mldsa65Saved ? 'Saved — leave blank to keep' : 'optional post-quantum verify key'}
              bind:value={mldsa65}
              oninput={syncVisualToJSON}
            />
          </div>
        {:else if security === 'tls'}
          <label class="cfg-label" for="cfg-alpn">ALPN</label>
          <div class="cfg-control">
            <input id="cfg-alpn" class="input mono" placeholder="h2,http/1.1" bind:value={alpn} oninput={syncVisualToJSON} />
          </div>

          <label class="cfg-label" for="cfg-ech">
            <span>TLS ECH</span>
            {#if echSaved && !ech}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-ech"
              class="input mono"
              placeholder={echSaved ? 'Saved — leave blank to keep' : 'optional echConfigList'}
              bind:value={ech}
              oninput={syncVisualToJSON}
            />
          </div>

          <label class="cfg-label" for="cfg-pcs">
            <span>Cert Pin SHA-256</span>
            {#if pcsSaved && !pcs}
              <span class="saved-pill">Saved</span>
            {/if}
          </label>
          <div class="cfg-control">
            <input
              id="cfg-pcs"
              class="input mono"
              placeholder={pcsSaved ? 'Saved — leave blank to keep' : 'optional pinnedPeerCertSha256'}
              bind:value={pcs}
              oninput={syncVisualToJSON}
            />
          </div>

          <label class="cfg-label" for="cfg-vcn">Verify By Name</label>
          <div class="cfg-control">
            <input id="cfg-vcn" class="input mono" placeholder="optional verifyPeerCertByName" bind:value={vcn} oninput={syncVisualToJSON} />
          </div>
        {/if}
      </div>
    </div>
  {:else if activeTab === 'json'}
    <!-- Live Two-Way Xray Outbound JSON Editor -->
    <div class="editor-section">
      <div class="row-between" style="gap: 8px">
        <div>
          <span class="editor-section-title">Xray Outbound JSON Editor</span>
          <div class="hint" style="margin-top: 2px">
            Two-way synced with Visual Config · leave <code>{KEEP_SECRET_SENTINEL}</code> intact to preserve stored secrets.
          </div>
        </div>
        <div class="row" style="gap: 6px">
          <button type="button" class="btn btn-sm" onclick={() => formatJSONEditor(true)}>Format</button>
          <button type="button" class="btn btn-sm" onclick={() => formatJSONEditor(false)}>Minify</button>
          <button type="button" class="btn btn-sm" onclick={copyJSON}>
            <Icon name="copy" size={12} /> Copy
          </button>
        </div>
      </div>

      <div class="field">
        <label for="cfg-json-alias">Alias (remarks)</label>
        <input id="cfg-json-alias" class="input" placeholder="Server display name" bind:value={alias} required={mode === 'add'} />
      </div>

      <textarea
        class="json-editor"
        spellcheck="false"
        bind:value={jsonText}
        oninput={handleJSONInput}
        aria-label="Xray outbound JSON"
      ></textarea>

      {#if jsonErr}
        <div class="alert danger" style="font-size: 12px">{jsonErr}</div>
      {:else}
        <div class="row-between hint tabular" style="font-size: 11.5px">
          <span>{jsonText.length} chars · {jsonDirty ? 'unsynced' : 'synced with Visual Config'}</span>
          <span>Validated by xray-core before saving</span>
        </div>
      {/if}
    </div>
  {:else}
    <!-- Share Link Import / Unpack -->
    <div class="editor-section">
      <div class="row-between">
        <span class="editor-section-title">{mode === 'edit' ? 'Replace From Share Link' : 'Import From Share Link'}</span>
        {#if shareLinkInput.trim()}
          <button type="button" class="btn btn-sm" onclick={unpackShareLinkToEditor}>
            Unpack to Visual &amp; JSON →
          </button>
        {/if}
      </div>

      <div class="field">
        <label for="cfg-share-uri">Share Link URI</label>
        <textarea
          id="cfg-share-uri"
          class="textarea"
          style="min-height: 100px"
          placeholder="Paste vless://, trojan://, vmess://, or ss:// — click Unpack to edit visually or Confirm to save directly"
          bind:value={shareLinkInput}
        ></textarea>
      </div>

      {#if sharePreview}
        <div class="preview-box">
          <div class="row-between" style="gap: 8px">
            <div class="row" style="gap: 7px">
              <span class="dot {sharePreview.valid ? 'ok' : 'danger'}"></span>
              <strong style="font-size: 12.5px">{sharePreview.name || sharePreview.scheme}</strong>
              {#if sharePreview.endpoint}
                <span class="mono hint" style="font-size: 11.5px">{sharePreview.endpoint}</span>
              {/if}
            </div>
            <div class="row" style="gap: 5px">
              {#each sharePreview.badges as b}
                <span class="badge {b.tone}" style="font-size: 10.5px; padding: 1px 7px">{b.label}</span>
              {/each}
            </div>
          </div>
          {#if sharePreview.warning}
            <span style="font-size: 11.5px; color: var(--warn)">{sharePreview.warning}</span>
          {/if}
        </div>
      {/if}

      <div class="field">
        <label for="cfg-link-alias">Alias (optional)</label>
        <input id="cfg-link-alias" class="input" placeholder="Defaults to #remark in share link" bind:value={alias} />
      </div>
    </div>
  {/if}

  <div class="row" style="justify-content: flex-end; padding-top: 4px; border-top: 1px solid var(--border)">
    <button type="button" class="btn" onclick={onCancel}>Cancel</button>
    <button type="submit" class="btn btn-primary" disabled={saving || (activeTab === 'json' && Boolean(jsonErr))}>
      {saving ? 'Validating & Saving…' : 'Confirm'}
    </button>
  </div>
</form>
