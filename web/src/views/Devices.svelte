<script lang="ts">
  import {
    api,
    type Device,
    type InterfacePolicy,
    type LeaseInfo,
    type NetworkInventory,
    type PolicyMode,
    type RouterInterface,
    type ServiceStatus,
    type State
  } from '../lib/api';
  import { formatBytes, friendlyError } from '../lib/format';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';

  interface Props {
    status: ServiceStatus | null;
    stateData: State | null;
    onRefresh: () => Promise<void>;
  }

  let { status, stateData, onRefresh }: Props = $props();

  type TabId = 'interfaces' | 'devices' | 'leases';
  type IfaceFilter = 'all' | 'lan' | 'bridge-port' | 'wan' | 'rules';
  type RecipeKind = 'wifi' | 'port';
  type WifiDriver = 'wifi' | 'wireless';

  let activeTab = $state<TabId>('interfaces');

  // Default LAN policy state (synced without overwriting in-progress edits on 5s refresh)
  let defaultMode = $state<PolicyMode>('direct');
  let defaultKill = $state(false);
  let lastPolicySync = $state('');
  let savingPolicy = $state(false);

  // Internet-in (WAN uplink for Xray)
  let wanChoice = $state('');
  let wanCustom = $state('');
  let lastWanSync = $state<string | null>(null);
  let savingWan = $state(false);

  // RouterOS live interface inventory (fetched once when RouterOS becomes available, plus manual Refresh)
  let inventory = $state<NetworkInventory | null>(null);
  let loadingInventory = $state(false);
  let inventoryError = $state('');
  let loadedInventoryForRouter = $state(false);
  let ifaceFilter = $state<IfaceFilter>('all');

  // Interface Policy Modal
  let showIfaceModal = $state(false);
  let ifaceEditing = $state(false);
  let ifaceKey = $state('');
  let ifaceLabel = $state('');
  let ifaceMode = $state<PolicyMode>('full');
  let ifaceKill = $state(true);
  let ifaceInScope = $state<boolean | null>(null);
  let savingIface = $state(false);

  // MikroTik RouterOS v7 provisioning recipe builder
  let recipeKind = $state<RecipeKind>('wifi');
  let wifiDriver = $state<WifiDriver>('wifi');
  let wifiIface = $state('wifi-vpn');
  let wifiMaster = $state('wifi1');
  let wifiSSID = $state('Home-VPN');
  let wifiCIDR = $state('192.168.99.0/24');
  let portIface = $state('ether4');
  let portBridge = $state('bridge');
  let portCIDR = $state('192.168.98.0/24');
  let recipeSeeded = $state(false);
  let stagingRecipe = $state(false);

  // Device modal
  let showDeviceModal = $state(false);
  let devAddr = $state('');
  let devName = $state('');
  let devMAC = $state('');
  let devMode = $state<PolicyMode>('smart');
  let devKill = $state(false);
  let savingDevice = $state(false);

  // RouterOS DHCP leases (fetched once when managed mode is active, plus manual Refresh)
  let leases = $state<LeaseInfo[]>([]);
  let loadingLeases = $state(false);
  let leasesError = $state('');
  let loadedLeasesForRouter = $state(false);
  let staticBusy = $state('');

  const configuredInterfaces = $derived(stateData?.interfaces ?? []);

  const ifaceRuleMap = $derived.by(() => {
    const m = new Map<string, InterfacePolicy>();
    for (const item of configuredInterfaces) {
      m.set(item.interface, item);
    }
    return m;
  });

  const liveInterfaces = $derived(inventory?.managed ? inventory.interfaces : []);
  const liveUplinks = $derived(inventory?.managed ? inventory.uplinks : []);

  const liveIfaceNames = $derived(new Set(liveInterfaces.map((i) => i.name)));

  const stagedOnlyRules = $derived(configuredInterfaces.filter((r) => !liveIfaceNames.has(r.interface)));

  const filteredLiveInterfaces = $derived.by(() => {
    return liveInterfaces.filter((i) => {
      if (ifaceFilter === 'lan') return i.role === 'lan' || i.role === 'unassigned';
      if (ifaceFilter === 'bridge-port') return i.role === 'bridge-port';
      if (ifaceFilter === 'wan') return i.role === 'wan';
      if (ifaceFilter === 'rules') return ifaceRuleMap.has(i.name);
      return true;
    });
  });

  const configuredWan = $derived(stateData?.network.wan_interface ?? '');

  // Keep Default LAN Policy synced with backend state
  $effect(() => {
    if (!stateData) return;
    const key = `${stateData.default_policy.mode}:${Boolean(stateData.default_policy.kill_switch)}`;
    if (key !== lastPolicySync) {
      defaultMode = stateData.default_policy.mode;
      defaultKill = Boolean(stateData.default_policy.kill_switch);
      lastPolicySync = key;
    }
  });

  // Keep WAN selector synced with backend state & discovered uplinks
  $effect(() => {
    if (!stateData) return;
    const saved = stateData.network.wan_interface ?? '';
    const uplinkKey = `${saved}|${liveUplinks.map((u) => u.interface).join(',')}`;
    if (uplinkKey !== lastWanSync) {
      if (!saved) {
        wanChoice = '';
        wanCustom = '';
      } else if (liveUplinks.some((u) => u.interface === saved)) {
        wanChoice = saved;
        wanCustom = '';
      } else {
        wanChoice = '__custom__';
        wanCustom = saved;
      }
      lastWanSync = uplinkKey;
    }
  });

  // One-shot discovery fetch when RouterOS managed mode is active (zero polling load on router)
  $effect(() => {
    const managed = Boolean(status?.routeros);
    if (managed && !loadedInventoryForRouter) {
      loadedInventoryForRouter = true;
      loadInventory();
    } else if (!managed && loadedInventoryForRouter) {
      loadedInventoryForRouter = false;
      inventory = null;
    }
    if (managed && !loadedLeasesForRouter) {
      loadedLeasesForRouter = true;
      loadLeases();
    } else if (!managed && loadedLeasesForRouter) {
      loadedLeasesForRouter = false;
      leases = [];
    }
  });

  // Seed recipe defaults from live router interfaces once discovered
  $effect(() => {
    if (!inventory?.managed || recipeSeeded) return;
    recipeSeeded = true;
    const firstWifi = inventory.interfaces.find((i) => isWifiType(i.type));
    if (firstWifi) {
      wifiMaster = firstWifi.name;
      wifiDriver = firstWifi.type.toLowerCase().includes('wlan') || firstWifi.type.toLowerCase() === 'wireless'
        ? 'wireless'
        : 'wifi';
    }
    const firstBridge = inventory.interfaces.find((i) => i.type === 'bridge');
    if (firstBridge) {
      portBridge = firstBridge.name;
    }
    const candidatePort = inventory.interfaces.find(
      (i) => i.type === 'ether' && i.role === 'bridge-port'
    );
    if (candidatePort) {
      portIface = candidatePort.name;
      if (candidatePort.bridge) portBridge = candidatePort.bridge;
    }
  });

  function isWifiType(t: string): boolean {
    const lower = t.toLowerCase();
    return lower.includes('wifi') || lower.includes('wlan') || lower.includes('wireless');
  }

  function formatIfaceType(t: string): string {
    const lower = t.toLowerCase();
    if (lower === 'ether') return 'Ethernet';
    if (lower === 'bridge') return 'Bridge';
    if (lower === 'vlan') return 'VLAN';
    if (lower.includes('wifi') || lower === 'wlan' || lower === 'wireless') return 'Wi-Fi';
    if (lower.includes('pppoe')) return 'PPPoE';
    if (lower === 'lte') return 'LTE / 5G';
    if (lower === 'wireguard') return 'WireGuard';
    if (lower === 'veth') return 'Container';
    return t || 'Interface';
  }

  function formatRole(role: RouterInterface['role']): { label: string; cls: string } {
    if (role === 'wan') return { label: 'WAN', cls: 'accent' };
    if (role === 'lan') return { label: 'Routed LAN', cls: 'ok' };
    if (role === 'bridge-port') return { label: 'Bridge Port', cls: '' };
    return { label: 'Unassigned', cls: 'warn' };
  }

  function rosQuote(s: string): string {
    const clean = s.replace(/[\r\n]/g, '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$');
    return `"${clean}"`;
  }

  function parseIPv4Subnet(cidr: string): { gw: string; gwCidr: string; net: string; pool: string; valid: boolean } {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr.trim());
    if (!m) {
      return {
        gw: '192.168.99.1',
        gwCidr: '192.168.99.1/24',
        net: '192.168.99.0/24',
        pool: '192.168.99.10-192.168.99.250',
        valid: false
      };
    }
    const oct = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
    const prefix = Number(m[5]);
    if (oct.some((n) => n < 0 || n > 255) || prefix < 16 || prefix > 29) {
      return {
        gw: '192.168.99.1',
        gwCidr: '192.168.99.1/24',
        net: '192.168.99.0/24',
        pool: '192.168.99.10-192.168.99.250',
        valid: false
      };
    }
    const base = `${oct[0]}.${oct[1]}.${oct[2]}`;
    const hostStart = prefix === 24 ? 10 : Math.min(oct[3] + 2, 250);
    const hostEnd = prefix === 24 ? 250 : Math.min(oct[3] + (1 << (32 - prefix)) - 2, 254);
    const gwOct = prefix === 24 ? 1 : oct[3] + 1;
    const netOct = prefix === 24 ? 0 : oct[3];
    return {
      gw: `${base}.${gwOct}`,
      gwCidr: `${base}.${gwOct}/${prefix}`,
      net: `${base}.${netOct}/${prefix}`,
      pool: `${base}.${hostStart}-${base}.${hostEnd}`,
      valid: true
    };
  }

  const recipeTargetIface = $derived(
    (recipeKind === 'wifi' ? wifiIface : portIface).trim() || (recipeKind === 'wifi' ? 'wifi-vpn' : 'ether4')
  );

  const recipeLanList = $derived(inventory?.lan_list || 'LAN');

  const recipeScript = $derived.by(() => {
    const lanList = rosQuote(recipeLanList);
    if (recipeKind === 'wifi') {
      const iface = wifiIface.trim() || 'wifi-vpn';
      const master = wifiMaster.trim() || 'wifi1';
      const ssid = wifiSSID.trim() || 'Home-VPN';
      const sub = parseIPv4Subnet(wifiCIDR);
      const poolName = `pool-${iface}`;
      const dhcpName = `dhcp-${iface}`;
      const createWifi =
        wifiDriver === 'wifi'
          ? `/interface/wifi/add name=${rosQuote(iface)} master-interface=${rosQuote(master)} configuration.ssid=${rosQuote(ssid)} security.authentication-types=wpa2-psk,wpa3-psk security.passphrase="CHANGE_ME_STRONG_PASS" disabled=no`
          : `/interface/wireless/security-profiles/add name=${rosQuote(`sec-${iface}`)} authentication-types=wpa2-psk mode=dynamic-keys wpa2-pre-shared-key="CHANGE_ME_STRONG_PASS"\n/interface/wireless/add name=${rosQuote(iface)} master-interface=${rosQuote(master)} ssid=${rosQuote(ssid)} security-profile=${rosQuote(`sec-${iface}`)} disabled=no`;
      return [
        `# 1. Create a dedicated virtual Wi-Fi SSID (keeps your main Wi-Fi & bridge HW offload untouched)`,
        createWifi,
        ``,
        `# 2. Assign a dedicated L3 subnet & DHCP server to ${iface}`,
        `/ip/address/add address=${sub.gwCidr} interface=${rosQuote(iface)} comment="tikray vpn wifi"`,
        `/ip/pool/add name=${rosQuote(poolName)} ranges=${sub.pool}`,
        `/ip/dhcp-server/add name=${rosQuote(dhcpName)} interface=${rosQuote(iface)} address-pool=${rosQuote(poolName)} disabled=no`,
        `/ip/dhcp-server/network/add address=${sub.net} gateway=${sub.gw} dns-server=${sub.gw}`,
        ``,
        `# 3. Join the ${recipeLanList} interface list so tikray discovers and routes ${iface} natively`,
        `/interface/list/member/add list=${lanList} interface=${rosQuote(iface)}`
      ].join('\n');
    } else {
      const port = portIface.trim() || 'ether4';
      const bridge = portBridge.trim() || 'bridge';
      const sub = parseIPv4Subnet(portCIDR);
      const poolName = `pool-${port}`;
      const dhcpName = `dhcp-${port}`;
      return [
        `# 1. Detach ${port} from ${bridge} so it routes directly (preserves HW switch offload on all other ports)`,
        `/interface/bridge/port/remove [find interface=${rosQuote(port)} bridge=${rosQuote(bridge)}]`,
        ``,
        `# 2. Assign a dedicated L3 subnet & DHCP server to ${port}`,
        `/ip/address/add address=${sub.gwCidr} interface=${rosQuote(port)} comment="tikray vpn port"`,
        `/ip/pool/add name=${rosQuote(poolName)} ranges=${sub.pool}`,
        `/ip/dhcp-server/add name=${rosQuote(dhcpName)} interface=${rosQuote(port)} address-pool=${rosQuote(poolName)} disabled=no`,
        `/ip/dhcp-server/network/add address=${sub.net} gateway=${sub.gw} dns-server=${sub.gw}`,
        ``,
        `# 3. Join the ${recipeLanList} interface list so tikray routes every device plugged into ${port}`,
        `/interface/list/member/add list=${lanList} interface=${rosQuote(port)}`
      ].join('\n');
    }
  });

  async function loadInventory(): Promise<void> {
    loadingInventory = true;
    inventoryError = '';
    try {
      inventory = await api.getRouterInterfaces();
    } catch (err) {
      inventoryError = friendlyError(err, 'Unable to read RouterOS interfaces');
    } finally {
      loadingInventory = false;
    }
  }

  async function loadLeases(): Promise<void> {
    loadingLeases = true;
    leasesError = '';
    try {
      leases = await api.getLeases();
    } catch (err) {
      leasesError = friendlyError(err, 'Unable to read RouterOS DHCP leases');
    } finally {
      loadingLeases = false;
    }
  }

  async function saveWAN(override?: string): Promise<void> {
    const next = override !== undefined ? override : wanChoice === '__custom__' ? wanCustom.trim() : wanChoice;
    if (override === undefined && wanChoice === '__custom__' && !next) {
      toast.err('Enter a RouterOS WAN interface name (e.g. pppoe-out1, ether1, lte1).');
      return;
    }
    savingWan = true;
    try {
      await api.setWANInterface(next);
      toast.ok(
        next
          ? `Xray outbound tunnel pinned to WAN interface "${next}" (with automatic primary WAN failover).`
          : 'Xray outbound tunnel set to Auto (RouterOS active primary WAN).'
      );
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Could not update WAN uplink'));
    } finally {
      savingWan = false;
    }
  }

  function openNewInterfacePolicy(prefill?: { iface?: string; label?: string; inScope?: boolean }): void {
    const existing = prefill?.iface ? ifaceRuleMap.get(prefill.iface) : undefined;
    ifaceEditing = Boolean(existing || prefill?.iface);
    ifaceKey = prefill?.iface ?? '';
    ifaceLabel = existing?.name ?? prefill?.label ?? '';
    ifaceMode = existing?.policy.mode ?? 'full';
    ifaceKill = existing ? Boolean(existing.policy.kill_switch) : true;
    ifaceInScope = prefill?.inScope ?? null;
    showIfaceModal = true;
  }

  function openEditInterfaceRule(rule: InterfacePolicy): void {
    const live = liveInterfaces.find((i) => i.name === rule.interface);
    ifaceEditing = true;
    ifaceKey = rule.interface;
    ifaceLabel = rule.name ?? '';
    ifaceMode = rule.policy.mode;
    ifaceKill = Boolean(rule.policy.kill_switch);
    ifaceInScope = live ? Boolean(live.in_scope) : null;
    showIfaceModal = true;
  }

  async function saveInterfacePolicy(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    const key = ifaceKey.trim();
    if (!key) {
      toast.err('Enter a RouterOS interface name.');
      return;
    }
    savingIface = true;
    try {
      await api.setInterfacePolicy(key, {
        name: ifaceLabel.trim() || undefined,
        policy: {
          mode: ifaceMode,
          kill_switch: ifaceMode === 'direct' ? false : ifaceKill
        }
      });
      toast.ok(`Saved ${ifaceMode} policy for interface ${key}.`);
      showIfaceModal = false;
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Could not save interface policy'));
    } finally {
      savingIface = false;
    }
  }

  async function removeInterfacePolicy(iface: string): Promise<void> {
    if (!confirm(`Clear custom routing policy for interface "${iface}" so it inherits the Default LAN Policy?`)) {
      return;
    }
    try {
      await api.deleteInterfacePolicy(iface);
      toast.ok(`Interface ${iface} now inherits the Default LAN Policy.`);
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Could not remove interface policy'));
    }
  }

  function jumpToDetachRecipe(iface: RouterInterface): void {
    if (isWifiType(iface.type)) {
      recipeKind = 'wifi';
      wifiMaster = iface.name;
      wifiIface = `${iface.name}-vpn`;
    } else {
      recipeKind = 'port';
      portIface = iface.name;
      if (iface.bridge) portBridge = iface.bridge;
    }
    toast.ok(`Prepared RouterOS v7 recipe for ${iface.name} below.`);
    const el = document.getElementById('ros-provisioning-recipes');
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function copyRecipe(): Promise<void> {
    try {
      await navigator.clipboard.writeText(recipeScript);
      toast.ok('Copied RouterOS v7 CLI commands to clipboard.');
    } catch {
      toast.err('Clipboard permission unavailable — select and copy the script manually.');
    }
  }

  async function stageRecipePolicy(mode: PolicyMode, killSwitch: boolean): Promise<void> {
    const target = recipeTargetIface;
    const label = recipeKind === 'wifi' ? `Wi-Fi · ${wifiSSID.trim() || target}` : `LAN Port · ${target}`;
    stagingRecipe = true;
    try {
      await api.setInterfacePolicy(target, {
        name: label,
        policy: { mode, kill_switch: mode === 'direct' ? false : killSwitch }
      });
      toast.ok(`Staged ${mode}${killSwitch ? ' + Kill Switch' : ''} policy for interface "${target}".`);
      await onRefresh();
    } catch (err) {
      toast.err(friendlyError(err, 'Could not stage interface policy'));
    } finally {
      stagingRecipe = false;
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
      toast.err(friendlyError(err, 'Failed to save default policy'));
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
      toast.err(friendlyError(err, 'Could not save device'));
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
      toast.err(friendlyError(err, 'Delete failed'));
    }
  }

  async function makeStatic(l: LeaseInfo): Promise<void> {
    staticBusy = l.address;
    try {
      await api.makeStaticLease(l.address);
      toast.ok(`Converted ${l.address} to a static DHCP lease on RouterOS.`);
      await loadLeases();
    } catch (err) {
      toast.err(friendlyError(err, 'Could not make lease static'));
    } finally {
      staticBusy = '';
    }
  }
</script>

<div class="stack-lg">
  <!-- Section Tabs -->
  <div class="row-between">
    <div class="tabs" role="tablist" aria-label="Network and Devices sections">
      <button
        type="button"
        role="tab"
        aria-selected={activeTab === 'interfaces'}
        class="tab {activeTab === 'interfaces' ? 'active' : ''}"
        onclick={() => (activeTab = 'interfaces')}
      >
        Wi-Fi, Ports &amp; WAN ({configuredInterfaces.length})
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={activeTab === 'devices'}
        class="tab {activeTab === 'devices' ? 'active' : ''}"
        onclick={() => (activeTab = 'devices')}
      >
        Devices &amp; Policy ({stateData?.devices.length ?? 0})
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={activeTab === 'leases'}
        class="tab {activeTab === 'leases' ? 'active' : ''}"
        onclick={() => (activeTab = 'leases')}
      >
        DHCP Leases{status?.routeros ? ` (${leases.length})` : ''}
      </button>
    </div>

    <div class="row" style="gap: 8px">
      {#if configuredWan}
        <span class="badge accent">WAN · {configuredWan}</span>
      {:else if inventory?.active_wan}
        <span class="badge ok">WAN · {inventory.active_wan} (Auto)</span>
      {/if}
      <span class="badge">Default · {defaultMode}</span>
    </div>
  </div>

  <!-- TAB 1: Wi-Fi, LAN Ports, Bridges, VLANs & Internet-In WAN Uplink -->
  {#if activeTab === 'interfaces'}
    <!-- Internet-In (WAN Uplink for Xray) -->
    <div class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">Internet-In (WAN Uplink for Xray)</h2>
          <p class="card-sub">
            Choose which MikroTik Internet-in interface carries Xray's outbound VPN tunnels. Failover to the active
            primary WAN is built in automatically.
          </p>
        </div>
        <div class="row" style="gap: 6px">
          {#if configuredWan}
            <span class="badge accent">Pinned · {configuredWan}</span>
          {:else if inventory?.active_wan}
            <span class="badge ok">Auto · {inventory.active_wan}</span>
          {:else}
            <span class="badge">Auto Primary WAN</span>
          {/if}
        </div>
      </div>

      {#if liveUplinks.length > 0}
        <div class="grid-3">
          {#each liveUplinks as u (`${u.interface}-${u.gateway ?? ''}`)}
            {@const isPinned = configuredWan === u.interface}
            <button
              type="button"
              class="policy-card {isPinned ? 'active' : ''}"
              onclick={() => {
                wanChoice = u.interface;
                wanCustom = '';
              }}
            >
              <div class="row-between" style="gap: 6px; margin-bottom: 4px">
                <span class="row" style="gap: 6px">
                  <span class="dot {u.active && u.running ? 'ok' : u.running ? 'warn' : 'danger'}"></span>
                  <strong class="mono" style="font-size: 13px">{u.interface}</strong>
                </span>
                <span class="badge {u.active ? 'ok' : ''}">{u.active ? 'Active' : 'Standby'}</span>
              </div>
              <div class="hint mono" style="font-size: 11.5px">
                {formatIfaceType(u.type || '')} · {u.point_to_point ? 'Point-to-Point' : u.gateway || 'Direct'}
                {#if u.distance !== undefined}
                  · dist {u.distance}
                {/if}
              </div>
            </button>
          {/each}
        </div>
      {/if}

      <div class="form-inline">
        <select
          class="select"
          aria-label="Xray WAN uplink interface"
          style="flex: 1; min-width: 220px"
          bind:value={wanChoice}
        >
          <option value="">
            Auto — Active RouterOS Default Route{inventory?.active_wan ? ` (${inventory.active_wan})` : ' (Recommended)'}
          </option>
          {#each liveUplinks as u (u.interface)}
            <option value={u.interface}>
              {u.interface} ({u.active ? 'Active' : 'Standby'} · {formatIfaceType(u.type || '')}{u.gateway
                ? ` · ${u.gateway}`
                : ''})
            </option>
          {/each}
          <option value="__custom__">Custom WAN interface name…</option>
        </select>

        {#if wanChoice === '__custom__'}
          <input
            class="input mono form-inline-narrow"
            style="min-width: 180px"
            placeholder="pppoe-out1, lte1, ether1"
            aria-label="Custom WAN interface name"
            bind:value={wanCustom}
          />
        {/if}

        <div class="form-inline-actions">
          <button type="button" class="btn btn-primary" disabled={savingWan} onclick={() => saveWAN()}>
            {savingWan ? 'Saving…' : 'Save WAN Uplink'}
          </button>
          {#if configuredWan}
            <button type="button" class="btn" disabled={savingWan} onclick={() => saveWAN('')}>
              Reset Auto
            </button>
          {/if}
        </div>
      </div>

      <p class="hint" style="margin: 0">
        When pinned, tikray installs a dedicated <code class="mono">tikray-wan</code> routing table with
        <code class="mono">check-gateway=ping</code> and a distance-2 failover route to your active WAN so Xray tunnels
        stay resilient during dual-WAN failovers.
      </p>
    </div>

    <!-- Wi-Fi SSIDs, LAN Ports, Bridges & VLANs -->
    <div class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">Wi-Fi SSIDs, LAN Ports, Bridges &amp; VLANs</h2>
          <p class="card-sub">
            Route an entire Wi-Fi SSID, dedicated Ethernet port, VLAN, or bridge through Xray without sacrificing
            FastTrack or L2 switch hardware offload on other ports.
          </p>
        </div>
        <div class="row" style="gap: 8px">
          {#if status?.routeros}
            <button type="button" class="btn btn-sm" disabled={loadingInventory} onclick={loadInventory}>
              <Icon name="refresh" size={13} />
              {loadingInventory ? 'Scanning…' : 'Refresh'}
            </button>
          {/if}
          <button type="button" class="btn btn-primary btn-sm" onclick={() => openNewInterfacePolicy()}>
            <Icon name="plus" size={14} /> Add Interface Rule
          </button>
        </div>
      </div>

      {#if inventoryError}
        <div class="alert warn">{inventoryError}</div>
      {/if}

      {#if liveInterfaces.length > 0}
        <div class="chips">
          <button
            type="button"
            class="chip {ifaceFilter === 'all' ? 'active' : ''}"
            onclick={() => (ifaceFilter = 'all')}
          >
            All ({liveInterfaces.length})
          </button>
          <button
            type="button"
            class="chip {ifaceFilter === 'lan' ? 'active' : ''}"
            onclick={() => (ifaceFilter = 'lan')}
          >
            Routed LAN &amp; Wi-Fi ({liveInterfaces.filter((i) => i.role === 'lan' || i.role === 'unassigned').length})
          </button>
          <button
            type="button"
            class="chip {ifaceFilter === 'bridge-port' ? 'active' : ''}"
            onclick={() => (ifaceFilter = 'bridge-port')}
          >
            Bridge Ports ({liveInterfaces.filter((i) => i.role === 'bridge-port').length})
          </button>
          <button
            type="button"
            class="chip {ifaceFilter === 'wan' ? 'active' : ''}"
            onclick={() => (ifaceFilter = 'wan')}
          >
            WAN ({liveInterfaces.filter((i) => i.role === 'wan').length})
          </button>
          <button
            type="button"
            class="chip {ifaceFilter === 'rules' ? 'active' : ''}"
            onclick={() => (ifaceFilter = 'rules')}
          >
            With Rule ({liveInterfaces.filter((i) => ifaceRuleMap.has(i.name)).length})
          </button>
        </div>

        {#if filteredLiveInterfaces.length === 0}
          <div class="empty-state">No RouterOS interfaces match the selected filter.</div>
        {:else}
          <div class="table-wrap">
            <table class="responsive-table">
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>Type / Role</th>
                  <th>SSID / Bridge / Subnet</th>
                  <th class="hide-xs">Traffic</th>
                  <th>Policy</th>
                  <th style="text-align: right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {#each filteredLiveInterfaces as iface (iface.name)}
                  {@const rule = ifaceRuleMap.get(iface.name)}
                  {@const roleBadge = formatRole(iface.role)}
                  {@const isPinnedWan = configuredWan === iface.name}
                  {@const isActiveAutoWan = !configuredWan && inventory?.active_wan === iface.name}
                  <tr>
                    <td data-label="Interface" class="cell-primary">
                      <div class="row" style="gap: 8px">
                        <span class="dot {iface.disabled ? '' : iface.running ? 'ok' : 'warn'}"></span>
                        <div>
                          <div class="mono" style="font-weight: 600">{iface.name}</div>
                          {#if rule?.name}
                            <div class="hint">{rule.name}</div>
                          {/if}
                        </div>
                      </div>
                    </td>
                    <td data-label="Type / Role">
                      <div class="row" style="gap: 6px">
                        <span class="badge">
                          {#if isWifiType(iface.type)}
                            <Icon name="wifi" size={11} />
                          {/if}
                          {formatIfaceType(iface.type)}
                        </span>
                        <span class="badge {roleBadge.cls}">{roleBadge.label}</span>
                      </div>
                    </td>
                    <td data-label="Details">
                      <div class="stack" style="gap: 3px">
                        {#if iface.ssid}
                          <span style="font-size: 12px">
                            SSID: <strong>{iface.ssid}</strong>
                          </span>
                        {/if}
                        {#if iface.bridge}
                          <span class="hint">
                            Member of <code class="mono">{iface.bridge}</code>
                          </span>
                        {/if}
                        {#if iface.subnets && iface.subnets.length > 0}
                          <span class="mono" style="font-size: 11.5px; color: var(--text-muted)">
                            {iface.subnets.join(', ')}
                          </span>
                        {:else if !iface.ssid && !iface.bridge}
                          <span class="hint">—</span>
                        {/if}
                      </div>
                    </td>
                    <td data-label="Traffic" class="hide-xs mono tabular" style="font-size: 11.5px; color: var(--text-muted)">
                      {#if (iface.rx_bytes ?? 0) > 0 || (iface.tx_bytes ?? 0) > 0}
                        ↓ {formatBytes(iface.rx_bytes ?? 0)}<br />↑ {formatBytes(iface.tx_bytes ?? 0)}
                      {:else}
                        —
                      {/if}
                    </td>
                    <td data-label="Policy">
                      {#if iface.role === 'wan'}
                        <div class="row" style="gap: 6px">
                          {#if isPinnedWan}
                            <span class="badge accent">Xray Uplink (Pinned)</span>
                          {:else if isActiveAutoWan}
                            <span class="badge ok">Xray Uplink (Auto)</span>
                          {:else}
                            <span class="badge">Standby WAN</span>
                          {/if}
                        </div>
                      {:else if rule}
                        <div class="row" style="gap: 6px">
                          <span
                            class="badge {rule.policy.mode === 'full'
                              ? 'accent'
                              : rule.policy.mode === 'smart'
                                ? 'ok'
                                : ''}"
                          >
                            {rule.policy.mode}
                          </span>
                          {#if rule.policy.kill_switch}
                            <span class="badge warn">Kill Switch</span>
                          {/if}
                        </div>
                      {:else if iface.role === 'bridge-port'}
                        <span class="hint">Follows {iface.bridge || 'bridge'}</span>
                      {:else}
                        <span class="badge">Inherit ({defaultMode})</span>
                      {/if}
                    </td>
                    <td data-label="Actions" class="cell-actions" style="text-align: right">
                      <div class="row action-row" style="justify-content: flex-end; gap: 6px">
                        {#if iface.role === 'wan'}
                          {#if isPinnedWan}
                            <button type="button" class="btn btn-sm" disabled={savingWan} onclick={() => saveWAN('')}>
                              Unpin
                            </button>
                          {:else}
                            <button
                              type="button"
                              class="btn btn-sm btn-primary"
                              disabled={savingWan}
                              onclick={() => saveWAN(iface.name)}
                            >
                              Use for Xray
                            </button>
                          {/if}
                        {:else if iface.role === 'bridge-port'}
                          <button
                            type="button"
                            class="btn btn-sm"
                            onclick={() => jumpToDetachRecipe(iface)}
                          >
                            Detach Guide
                          </button>
                        {:else}
                          <button
                            type="button"
                            class="btn btn-sm {rule ? '' : 'btn-primary'}"
                            onclick={() =>
                              openNewInterfacePolicy({
                                iface: iface.name,
                                label: iface.ssid ? `Wi-Fi · ${iface.ssid}` : undefined,
                                inScope: Boolean(iface.in_scope)
                              })}
                          >
                            {rule ? 'Edit Policy' : 'Set Policy'}
                          </button>
                          {#if rule}
                            <button
                              type="button"
                              class="btn btn-sm btn-danger"
                              aria-label="Clear interface policy"
                              onclick={() => removeInterfacePolicy(iface.name)}
                            >
                              <Icon name="trash" size={13} />
                            </button>
                          {/if}
                        {/if}
                      </div>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/if}

      {#if stagedOnlyRules.length > 0}
        <div class="stack" style="gap: 8px">
          <div class="editor-section-title">
            {liveInterfaces.length > 0 ? 'Staged Interface Rules (Not Yet Discovered on RouterOS)' : 'Configured Interface Rules'}
          </div>
          <div class="table-wrap">
            <table class="responsive-table">
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>Label</th>
                  <th>Policy</th>
                  <th>Status</th>
                  <th style="text-align: right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {#each stagedOnlyRules as r (r.interface)}
                  <tr>
                    <td data-label="Interface" class="mono cell-primary" style="font-weight: 600">{r.interface}</td>
                    <td data-label="Label">{r.name || '—'}</td>
                    <td data-label="Policy">
                      <div class="row" style="gap: 6px">
                        <span
                          class="badge {r.policy.mode === 'full'
                            ? 'accent'
                            : r.policy.mode === 'smart'
                              ? 'ok'
                              : ''}"
                        >
                          {r.policy.mode}
                        </span>
                        {#if r.policy.kill_switch}
                          <span class="badge warn">Kill Switch</span>
                        {/if}
                      </div>
                    </td>
                    <td data-label="Status">
                      <span class="badge {status?.routeros ? 'warn' : ''}">
                        {status?.routeros ? 'Waiting on RouterOS interface' : 'Staged (Standalone)'}
                      </span>
                    </td>
                    <td data-label="Actions" class="cell-actions" style="text-align: right">
                      <div class="row action-row" style="justify-content: flex-end; gap: 6px">
                        <button type="button" class="btn btn-sm" onclick={() => openEditInterfaceRule(r)}>Edit</button>
                        <button
                          type="button"
                          class="btn btn-sm btn-danger"
                          aria-label="Remove interface policy"
                          onclick={() => removeInterfacePolicy(r.interface)}
                        >
                          <Icon name="trash" size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      {:else if liveInterfaces.length === 0 && !loadingInventory}
        <div class="empty-state">
          {#if status?.routeros}
            No RouterOS interfaces discovered yet. Click Refresh or add an interface rule manually.
          {:else}
            Running in standalone mode without a managed MikroTik RouterOS peer. On MikroTik, tikray auto-discovers
            every Wi-Fi radio, Ethernet port, bridge, VLAN, and WAN uplink — and you can pre-stage interface policies
            here now with <strong>+ Add Interface Rule</strong>.
          {/if}
        </div>
      {/if}
    </div>

    <!-- MikroTik RouterOS v7 Provisioning Recipes -->
    <div id="ros-provisioning-recipes" class="card stack">
      <div class="card-header" style="margin-bottom: 0">
        <div>
          <h2 class="card-title">MikroTik RouterOS v7 Setup Recipes</h2>
          <p class="card-sub">
            Create a dedicated VPN Wi-Fi SSID or detach a dedicated VPN LAN port while keeping hardware bridge
            switching &amp; FastTrack at full wire speed on your main LAN.
          </p>
        </div>
        <div class="tabs">
          <button
            type="button"
            class="tab {recipeKind === 'wifi' ? 'active' : ''}"
            onclick={() => (recipeKind = 'wifi')}
          >
            <Icon name="wifi" size={13} /> VPN Wi-Fi SSID
          </button>
          <button
            type="button"
            class="tab {recipeKind === 'port' ? 'active' : ''}"
            onclick={() => (recipeKind = 'port')}
          >
            VPN LAN Port
          </button>
        </div>
      </div>

      {#if recipeKind === 'wifi'}
        <div class="grid-4">
          <div class="field">
            <label for="rec-wifi-iface">Virtual Interface</label>
            <input id="rec-wifi-iface" class="input mono" bind:value={wifiIface} placeholder="wifi-vpn" />
          </div>
          <div class="field">
            <label for="rec-wifi-master">Parent Radio</label>
            <input id="rec-wifi-master" class="input mono" bind:value={wifiMaster} placeholder="wifi1" />
          </div>
          <div class="field">
            <label for="rec-wifi-ssid">Wi-Fi SSID Name</label>
            <input id="rec-wifi-ssid" class="input" bind:value={wifiSSID} placeholder="Home-VPN" />
          </div>
          <div class="field">
            <label for="rec-wifi-cidr">Subnet (CIDR)</label>
            <input id="rec-wifi-cidr" class="input mono" bind:value={wifiCIDR} placeholder="192.168.99.0/24" />
          </div>
        </div>
        <div class="row" style="gap: 12px">
          <label class="label" for="rec-wifi-driver">RouterOS Wi-Fi package:</label>
          <select id="rec-wifi-driver" class="select" style="width: auto; min-width: 220px" bind:value={wifiDriver}>
            <option value="wifi">RouterOS v7 WiFiWave2 / wifi (/interface/wifi)</option>
            <option value="wireless">Legacy Wireless (/interface/wireless)</option>
          </select>
        </div>
      {:else}
        <div class="grid-3">
          <div class="field">
            <label for="rec-port-iface">Ethernet Port</label>
            <input id="rec-port-iface" class="input mono" bind:value={portIface} placeholder="ether4" />
          </div>
          <div class="field">
            <label for="rec-port-bridge">Current Bridge</label>
            <input id="rec-port-bridge" class="input mono" bind:value={portBridge} placeholder="bridge" />
          </div>
          <div class="field">
            <label for="rec-port-cidr">Subnet (CIDR)</label>
            <input id="rec-port-cidr" class="input mono" bind:value={portCIDR} placeholder="192.168.98.0/24" />
          </div>
        </div>
      {/if}

      <pre class="code-block" style="margin: 0; white-space: pre-wrap">{recipeScript}</pre>

      <div class="row-between">
        <span class="hint">
          Paste in WinBox / RouterOS Terminal, replace the Wi-Fi passphrase placeholder, then stage the policy here so
          tikray routes <code class="mono">{recipeTargetIface}</code> immediately.
        </span>
        <div class="row" style="gap: 8px">
          <button type="button" class="btn btn-sm" onclick={copyRecipe}>
            <Icon name="copy" size={13} /> Copy CLI
          </button>
          <button
            type="button"
            class="btn btn-sm"
            disabled={stagingRecipe}
            onclick={() => stageRecipePolicy('smart', false)}
          >
            Stage Smart for {recipeTargetIface}
          </button>
          <button
            type="button"
            class="btn btn-sm btn-primary"
            disabled={stagingRecipe}
            onclick={() => stageRecipePolicy('full', true)}
          >
            Stage Full + Kill Switch
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- TAB 2: Default LAN Policy & Per-Device Overrides -->
  {#if activeTab === 'devices'}
    <!-- Default Policy -->
    <div class="card stack">
      <div class="card-header" style="margin-bottom: 4px">
        <div>
          <h2 class="card-title">Default LAN Policy</h2>
          <p class="card-sub">
            Fallback policy for every LAN interface and host that does not have a specific interface or device override
          </p>
        </div>
        <button type="button" class="btn btn-primary btn-sm" disabled={savingPolicy} onclick={saveDefaultPolicy}>
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
          <p class="card-sub">
            Per-IP (/32) or CIDR policies enforced atomically by RouterOS policy routing (always take precedence over
            interface &amp; default policies)
          </p>
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openNewDevice()}>
          <Icon name="plus" size={14} /> Add Device / CIDR
        </button>
      </div>

      {#if (stateData?.devices.length ?? 0) === 0}
        <div class="empty-state">
          No per-device overrides configured. Clients follow their interface policy (if set) or the Default LAN Policy.
        </div>
      {:else}
        <div class="table-wrap">
          <table class="responsive-table">
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
                  <td data-label="Address" class="mono cell-primary" style="font-weight: 600">{d.address}</td>
                  <td data-label="Name">{d.name || '—'}</td>
                  <td data-label="MAC" class="mono" style="font-size: 12px; color: var(--text-muted)">{d.mac || '—'}</td>
                  <td data-label="Policy">
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
                  <td data-label="Actions" class="cell-actions" style="text-align: right">
                    <div class="row action-row" style="justify-content: flex-end; gap: 6px">
                      <button type="button" class="btn btn-sm" onclick={() => openEditDevice(d)}>Edit</button>
                      <button
                        type="button"
                        class="btn btn-sm btn-danger"
                        onclick={() => removeDevice(d)}
                        aria-label="Remove device"
                      >
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
  {/if}

  <!-- TAB 3: RouterOS DHCP Leases -->
  {#if activeTab === 'leases'}
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
          <button type="button" class="btn btn-sm" disabled={loadingLeases} onclick={loadLeases}>
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
          <table class="responsive-table">
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
                  <td data-label="IP Address" class="mono cell-primary" style="font-weight: 600">{l.address}</td>
                  <td data-label="Hostname">{l.name || '—'}</td>
                  <td data-label="MAC" class="mono" style="font-size: 12px; color: var(--text-muted)">{l.mac}</td>
                  <td data-label="Lease">
                    {#if l.static}
                      <span class="badge ok">Static</span>
                    {:else}
                      <span class="badge warn">Dynamic</span>
                    {/if}
                  </td>
                  <td data-label="Actions" class="cell-actions" style="text-align: right">
                    <div class="row action-row" style="justify-content: flex-end; gap: 6px">
                      {#if !l.static}
                        <button
                          type="button"
                          class="btn btn-sm"
                          disabled={staticBusy === l.address}
                          onclick={() => makeStatic(l)}
                        >
                          {staticBusy === l.address ? 'Saving…' : 'Make Static'}
                        </button>
                      {/if}
                      <button
                        type="button"
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
  {/if}
</div>

<!-- Interface Policy Modal -->
{#if showIfaceModal}
  <Modal title="Configure Interface Routing Policy" onClose={() => (showIfaceModal = false)}>
    <form class="stack" onsubmit={saveInterfacePolicy}>
      <div class="field">
        <label for="iface-key">RouterOS Interface Name</label>
        <input
          id="iface-key"
          class="input mono"
          placeholder="e.g. wifi-vpn, ether4, vlan20, bridge-guest"
          bind:value={ifaceKey}
          readonly={ifaceEditing}
          required
        />
        <span class="hint">Exact MikroTik L3 interface name (Wi-Fi interface, routed Ethernet port, VLAN, or bridge).</span>
      </div>

      <div class="field">
        <label for="iface-label">Friendly Label (optional)</label>
        <input id="iface-label" class="input" placeholder="e.g. Home-VPN Wi-Fi or Apple TV Port" bind:value={ifaceLabel} />
      </div>

      <div class="field">
        <label for="iface-mode">Routing Mode</label>
        <select
          id="iface-mode"
          class="select"
          bind:value={ifaceMode}
          onchange={() => {
            if (ifaceMode === 'direct') ifaceKill = false;
          }}
        >
          <option value="direct">Direct (bypass proxy)</option>
          <option value="smart">Smart Split (domestic direct, international proxied)</option>
          <option value="full">Full Tunnel (all non-LAN traffic proxied)</option>
        </select>
      </div>

      <label class="toggle" style="opacity: {ifaceMode === 'direct' ? 0.5 : 1}">
        <input type="checkbox" bind:checked={ifaceKill} disabled={ifaceMode === 'direct'} />
        <span>Enable Kill Switch for every client on this interface</span>
      </label>

      {#if ifaceInScope === false}
        <div class="alert warn">
          This interface is not currently in your RouterOS <code class="mono">{recipeLanList}</code> interface list. Add
          it to <code class="mono">{recipeLanList}</code> (see the setup recipe) so tikray enforces this policy on its
          subnet.
        </div>
      {/if}

      <div class="row" style="justify-content: flex-end">
        <button type="button" class="btn" onclick={() => (showIfaceModal = false)}>Cancel</button>
        <button type="submit" class="btn btn-primary" disabled={savingIface}>
          {savingIface ? 'Saving…' : 'Save Interface Policy'}
        </button>
      </div>
    </form>
  </Modal>
{/if}

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
