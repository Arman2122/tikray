<script lang="ts">
  import { api, ApiError, type Rule, type RuleAction, type State } from '../lib/api';
  import { splitLines } from '../lib/format';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';

  interface Props {
    stateData: State | null;
    onRefresh: () => Promise<void>;
  }

  let { stateData, onRefresh }: Props = $props();

  let pinned = $state('');
  let rules = $state<Rule[]>([]);
  let domesticDomains = $state('');
  let domesticIPs = $state('');
  let blockList = $state('');
  let savingRouting = $state(false);

  // DNS
  let remoteDNS = $state('');
  let domesticDNS = $state('');
  let savingDNS = $state(false);

  // Health Probe
  let probeURL = $state('');
  let savingHealth = $state(false);

  // Add/Edit Rule modal
  let showRuleModal = $state(false);
  let editIndex = $state<number | null>(null);
  let ruleDomains = $state('');
  let ruleIPs = $state('');
  let ruleAction = $state<RuleAction>('proxy');
  let ruleServer = $state('');

  const dnsPresets = [
    { label: 'Cloudflare DoH', value: 'https://1.1.1.1/dns-query' },
    { label: 'Google DoH', value: 'https://8.8.8.8/dns-query' },
    { label: 'Quad9 DoH', value: 'https://9.9.9.9/dns-query' }
  ];

  $effect(() => {
    if (!stateData) return;
    pinned = stateData.routing.pinned ?? '';
    rules = (stateData.routing.rules ?? []).map((r) => ({
      domains: r.domains ? [...r.domains] : [],
      ips: r.ips ? [...r.ips] : [],
      action: r.action,
      server: r.server
    }));
    domesticDomains = (stateData.routing.domestic.domains ?? []).join('\n');
    domesticIPs = (stateData.routing.domestic.ips ?? []).join('\n');
    blockList = (stateData.routing.block_list ?? []).join('\n');
    remoteDNS = stateData.dns.remote ?? '';
    domesticDNS = stateData.dns.domestic ?? '';
    probeURL = stateData.health.probe_url ?? '';
  });

  const enabledServers = $derived((stateData?.servers ?? []).filter((s) => !s.disabled));

  function openRuleModal(idx: number | null): void {
    editIndex = idx;
    if (idx !== null && rules[idx]) {
      const r = rules[idx];
      ruleDomains = (r.domains ?? []).join('\n');
      ruleIPs = (r.ips ?? []).join('\n');
      ruleAction = r.action;
      ruleServer = r.server ?? '';
    } else {
      ruleDomains = '';
      ruleIPs = '';
      ruleAction = 'proxy';
      ruleServer = enabledServers[0]?.id ?? '';
    }
    showRuleModal = true;
  }

  function saveRuleLocal(e: SubmitEvent): void {
    e.preventDefault();
    const domains = splitLines(ruleDomains);
    const ips = splitLines(ruleIPs);
    if (domains.length === 0 && ips.length === 0) {
      toast.warn('Specify at least one domain matcher or IP/CIDR.');
      return;
    }
    if (ruleAction === 'server' && !ruleServer) {
      toast.warn('Choose a target server for action "server".');
      return;
    }
    const next: Rule = {
      domains: domains.length > 0 ? domains : undefined,
      ips: ips.length > 0 ? ips : undefined,
      action: ruleAction,
      server: ruleAction === 'server' ? ruleServer : undefined
    };
    if (editIndex !== null) {
      rules = rules.map((r, i) => (i === editIndex ? next : r));
    } else {
      rules = [...rules, next];
    }
    showRuleModal = false;
  }

  function moveRule(idx: number, dir: -1 | 1): void {
    const target = idx + dir;
    if (target < 0 || target >= rules.length) return;
    const copy = [...rules];
    const [item] = copy.splice(idx, 1);
    copy.splice(target, 0, item);
    rules = copy;
  }

  function removeRule(idx: number): void {
    rules = rules.filter((_, i) => i !== idx);
  }

  async function saveRouting(): Promise<void> {
    savingRouting = true;
    try {
      await api.setRouting({
        pinned: pinned || undefined,
        rules: rules.length > 0 ? rules : undefined,
        block_list: splitLines(blockList),
        domestic: {
          domains: splitLines(domesticDomains),
          ips: splitLines(domesticIPs)
        }
      });
      toast.ok('Routing rules saved. Reconciler will apply changes automatically.');
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Failed to save routing');
    } finally {
      savingRouting = false;
    }
  }

  async function saveDNS(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    savingDNS = true;
    try {
      await api.setDNS({
        remote: remoteDNS.trim(),
        domestic: domesticDNS.trim() || undefined
      });
      toast.ok('DNS settings saved.');
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Failed to save DNS');
    } finally {
      savingDNS = false;
    }
  }

  async function saveHealth(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    savingHealth = true;
    try {
      await api.setHealth({ probe_url: probeURL.trim() });
      toast.ok('Health probe URL saved.');
      await onRefresh();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Failed to save probe URL');
    } finally {
      savingHealth = false;
    }
  }
</script>

<div class="stack-lg">
  <!-- Pinned Exit & Custom Rules -->
  <div class="card stack">
    <div class="card-header" style="margin-bottom: 0">
      <div>
        <h2 class="card-title">Exit Selection &amp; Custom Routing Rules</h2>
        <p class="card-sub">Rules are evaluated top-to-bottom before domestic split and default proxy routing</p>
      </div>
      <div class="row">
        <button class="btn btn-sm" onclick={() => openRuleModal(null)}>
          <Icon name="plus" size={14} /> Add Rule
        </button>
        <button class="btn btn-primary btn-sm" disabled={savingRouting} onclick={saveRouting}>
          {savingRouting ? 'Saving…' : 'Save Routing'}
        </button>
      </div>
    </div>

    <div class="field" style="max-width: 380px">
      <label for="pin-select">Active Exit Server</label>
      <select id="pin-select" class="select" bind:value={pinned}>
        <option value="">Auto — Lowest Latency (Observatory leastPing)</option>
        {#each enabledServers as srv (srv.id)}
          <option value={srv.id}>{srv.name} ({srv.id})</option>
        {/each}
      </select>
    </div>

    {#if rules.length === 0}
      <div class="empty-state">No custom routing rules defined.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Domains</th>
              <th>IPs / CIDRs</th>
              <th>Action</th>
              <th style="text-align: right">Order &amp; Edit</th>
            </tr>
          </thead>
          <tbody>
            {#each rules as r, idx}
              <tr>
                <td class="mono tabular" style="color: var(--text-dim)">{idx + 1}</td>
                <td class="mono" style="font-size: 12px">{(r.domains ?? []).join(', ') || '—'}</td>
                <td class="mono" style="font-size: 12px">{(r.ips ?? []).join(', ') || '—'}</td>
                <td>
                  <span
                    class="badge {r.action === 'block'
                      ? 'danger'
                      : r.action === 'direct'
                        ? 'ok'
                        : r.action === 'server'
                          ? 'purple'
                          : 'accent'}"
                  >
                    {r.action}{r.server ? `: ${stateData?.servers.find((s) => s.id === r.server)?.name ?? r.server}` : ''}
                  </span>
                </td>
                <td style="text-align: right">
                  <div class="row" style="justify-content: flex-end; gap: 4px">
                    <button class="btn btn-sm" disabled={idx === 0} onclick={() => moveRule(idx, -1)}>↑</button>
                    <button class="btn btn-sm" disabled={idx === rules.length - 1} onclick={() => moveRule(idx, 1)}>↓</button>
                    <button class="btn btn-sm" onclick={() => openRuleModal(idx)}>Edit</button>
                    <button class="btn btn-sm btn-danger" onclick={() => removeRule(idx)} aria-label="Remove rule">
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

    <div class="grid-3">
      <div class="field">
        <label for="dom-domains">Extra Domestic Bypass Domains</label>
        <textarea
          id="dom-domains"
          class="textarea"
          placeholder="domain:bank.local&#10;geosite:ir"
          bind:value={domesticDomains}
        ></textarea>
      </div>
      <div class="field">
        <label for="dom-ips">Extra Domestic Bypass IPs / CIDRs</label>
        <textarea
          id="dom-ips"
          class="textarea"
          placeholder="203.0.113.0/24&#10;geoip:ir"
          bind:value={domesticIPs}
        ></textarea>
      </div>
      <div class="field">
        <label for="block-list">Blocked Domains</label>
        <textarea
          id="block-list"
          class="textarea"
          placeholder="geosite:category-ads-all&#10;domain:tracker.example"
          bind:value={blockList}
        ></textarea>
      </div>
    </div>
  </div>

  <!-- DNS & Health Probe -->
  <div class="grid-2">
    <form class="card stack" onsubmit={saveDNS}>
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">DNS Resolvers</h2>
          <p class="card-sub">Proxied DoH resolver prevents DNS leaks; domestic resolver handles local &amp; domestic queries</p>
        </div>
        <button type="submit" class="btn btn-primary btn-sm" disabled={savingDNS}>
          {savingDNS ? 'Saving…' : 'Save DNS'}
        </button>
      </div>

      <div class="field">
        <label for="remote-dns">Remote Resolver (HTTPS DoH or IPv4)</label>
        <input id="remote-dns" class="input mono" bind:value={remoteDNS} required />
        <div class="row" style="margin-top: 4px">
          {#each dnsPresets as p}
            <button type="button" class="chip {remoteDNS === p.value ? 'active' : ''}" onclick={() => (remoteDNS = p.value)}>
              {p.label}
            </button>
          {/each}
        </div>
      </div>

      <div class="field">
        <label for="domestic-dns">Domestic Resolver IPv4 (optional)</label>
        <input
          id="domestic-dns"
          class="input mono"
          placeholder="Blank = RouterOS bridge address"
          bind:value={domesticDNS}
        />
      </div>
    </form>

    <form class="card stack" onsubmit={saveHealth}>
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">Connectivity Health Probe</h2>
          <p class="card-sub">End-to-end HTTP probe run through the proxy during trials and continuous monitoring</p>
        </div>
        <button type="submit" class="btn btn-primary btn-sm" disabled={savingHealth}>
          {savingHealth ? 'Saving…' : 'Save Probe'}
        </button>
      </div>

      <div class="field">
        <label for="probe-url">Probe URL</label>
        <input
          id="probe-url"
          class="input mono"
          type="url"
          placeholder="https://www.gstatic.com/generate_204"
          bind:value={probeURL}
          required
        />
        <span class="hint">Must be an HTTPS URL returning HTTP 200 or 204.</span>
      </div>
    </form>
  </div>
</div>

{#if showRuleModal}
  <Modal title={editIndex !== null ? 'Edit Routing Rule' : 'Add Routing Rule'} onClose={() => (showRuleModal = false)}>
    <form class="stack" onsubmit={saveRuleLocal}>
      <div class="field">
        <label for="r-dom">Domains (one per line or comma-separated)</label>
        <textarea
          id="r-dom"
          class="textarea"
          placeholder="domain:example.com&#10;full:api.example.org&#10;geosite:netflix"
          bind:value={ruleDomains}
        ></textarea>
      </div>
      <div class="field">
        <label for="r-ip">IPs / CIDRs (optional)</label>
        <textarea
          id="r-ip"
          class="textarea"
          placeholder="198.51.100.0/24&#10;geoip:us"
          bind:value={ruleIPs}
        ></textarea>
      </div>
      <div class="grid-2">
        <div class="field">
          <label for="r-act">Action</label>
          <select id="r-act" class="select" bind:value={ruleAction}>
            <option value="proxy">Proxy (active exit)</option>
            <option value="direct">Direct (bypass proxy)</option>
            <option value="block">Block (drop)</option>
            <option value="server">Specific Server</option>
          </select>
        </div>
        {#if ruleAction === 'server'}
          <div class="field">
            <label for="r-srv">Target Server</label>
            <select id="r-srv" class="select" bind:value={ruleServer} required>
              {#each enabledServers as srv (srv.id)}
                <option value={srv.id}>{srv.name}</option>
              {/each}
            </select>
          </div>
        {/if}
      </div>
      <div class="row" style="justify-content: flex-end">
        <button type="button" class="btn" onclick={() => (showRuleModal = false)}>Cancel</button>
        <button type="submit" class="btn btn-primary">Stage Rule</button>
      </div>
    </form>
  </Modal>
{/if}
