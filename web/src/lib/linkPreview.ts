// Pure client-side share-link inspector for live preview badges before save.
// Never extracts or returns credentials (UUIDs, passwords, keys) — only public
// protocol, host:port, transport, and modern xray-core capability flags.

export interface LinkPreview {
  valid: boolean;
  scheme: string;
  name: string;
  endpoint: string;
  badges: { label: string; tone: 'accent' | 'ok' | 'purple' | 'warn' }[];
  warning?: string;
}

export function inspectShareLink(raw: string): LinkPreview | null {
  const line = raw.trim();
  if (!line) return null;
  const sep = line.indexOf('://');
  if (sep <= 0) return null;
  const scheme = line.slice(0, sep).toLowerCase();
  if (!['vless', 'trojan', 'vmess', 'ss'].includes(scheme)) {
    return {
      valid: false,
      scheme: scheme.toUpperCase(),
      name: '',
      endpoint: '',
      badges: [],
      warning: `Unsupported scheme "${scheme}://"`
    };
  }

  if (scheme === 'vmess') {
    const payload = line.slice(sep + 3).split('#')[0];
    try {
      const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
      const json = JSON.parse(atob(normalized)) as Record<string, unknown>;
      const host = String(json.add ?? '');
      const port = String(json.port ?? '');
      const badges: LinkPreview['badges'] = [{ label: 'VMess', tone: 'accent' }];
      if (json.net) badges.push({ label: String(json.net).toUpperCase(), tone: 'purple' });
      if (json.tls === 'tls') badges.push({ label: 'TLS', tone: 'ok' });
      return {
        valid: Boolean(host && port),
        scheme: 'VMess',
        name: String(json.ps ?? '') || `${host}:${port}`,
        endpoint: host && port ? `${host}:${port}` : 'invalid',
        badges
      };
    } catch {
      return {
        valid: false,
        scheme: 'VMess',
        name: '',
        endpoint: '',
        badges: [],
        warning: 'Could not decode base64 VMess payload'
      };
    }
  }

  if (scheme === 'ss') {
    const hashIdx = line.indexOf('#');
    const frag = hashIdx >= 0 ? safeDecode(line.slice(hashIdx + 1)) : '';
    const body = hashIdx >= 0 ? line.slice(sep + 3, hashIdx) : line.slice(sep + 3);
    const atIdx = body.lastIndexOf('@');
    const hostPort = atIdx >= 0 ? body.slice(atIdx + 1).split('?')[0] : '';
    return {
      valid: Boolean(hostPort),
      scheme: 'Shadowsocks',
      name: frag || hostPort || 'Shadowsocks',
      endpoint: hostPort || 'SIP002',
      badges: [{ label: 'Shadowsocks', tone: 'accent' }]
    };
  }

  // VLESS & Trojan share standard URI query structure.
  const hashIdx = line.indexOf('#');
  const main = hashIdx >= 0 ? line.slice(0, hashIdx) : line;
  const frag = hashIdx >= 0 ? safeDecode(line.slice(hashIdx + 1)) : '';
  try {
    const u = new URL(main);
    const q = u.searchParams;
    const host = u.hostname;
    const port = u.port;
    const badges: LinkPreview['badges'] = [{ label: scheme.toUpperCase(), tone: 'accent' }];

    const net = (q.get('type') || 'tcp').toLowerCase();
    if (net === 'xhttp' || net === 'splithttp') {
      badges.push({ label: `XHTTP (${q.get('mode') || 'auto'})`, tone: 'purple' });
    } else if (net !== 'tcp' && net !== 'raw') {
      badges.push({ label: net.toUpperCase(), tone: 'purple' });
    }

    const sec = (q.get('security') || (scheme === 'trojan' ? 'tls' : 'none')).toLowerCase();
    if (sec === 'reality') {
      badges.push({ label: 'REALITY', tone: 'ok' });
    } else if (sec === 'tls') {
      badges.push({ label: 'TLS', tone: 'ok' });
    }

    const flow = q.get('flow') || '';
    if (flow.includes('vision')) {
      badges.push({ label: 'XTLS-Vision', tone: 'ok' });
    }
    const enc = q.get('encryption') || '';
    if (scheme === 'vless' && enc && enc !== 'none') {
      badges.push({ label: 'PQ VLESS Encryption', tone: 'ok' });
    }
    if (q.get('pqv')) {
      badges.push({ label: 'ML-DSA-65 PQ', tone: 'ok' });
    }
    if (q.get('ech')) {
      badges.push({ label: 'TLS ECH', tone: 'ok' });
    }
    if (q.get('extra')) {
      badges.push({ label: 'XHTTP Extra', tone: 'purple' });
    }
    if (q.get('pcs')) {
      badges.push({ label: 'Pinned Cert', tone: 'ok' });
    }

    let warning: string | undefined;
    if ((q.get('allowInsecure') === '1' || q.get('allowInsecure') === 'true' || q.get('insecure') === '1') && !q.get('pcs')) {
      warning = 'allowInsecure is ignored by xray-core 26+; server certificate will be verified (or use pcs= pin).';
    }

    return {
      valid: Boolean(host && port),
      scheme: scheme.toUpperCase(),
      name: frag || `${host}:${port}`,
      endpoint: host && port ? `${host}:${port}` : 'missing host:port',
      badges,
      warning
    };
  } catch {
    return {
      valid: false,
      scheme: scheme.toUpperCase(),
      name: '',
      endpoint: '',
      badges: [],
      warning: 'Malformed share link URI'
    };
  }
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
