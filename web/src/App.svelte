<script lang="ts">
  import {
    api,
    ApiError,
    onUnauthorized,
    type ServiceEvent,
    type ServiceStats,
    type ServiceStatus,
    type State
  } from './lib/api';
  import { toast } from './lib/toast.svelte';
  import Icon from './components/Icon.svelte';
  import CommandPalette from './components/CommandPalette.svelte';
  import type { RateSample } from './components/TrafficChart.svelte';
  import SetupLogin from './views/SetupLogin.svelte';
  import Dashboard from './views/Dashboard.svelte';
  import Servers from './views/Servers.svelte';
  import Devices from './views/Devices.svelte';
  import Routing from './views/Routing.svelte';
  import Updates from './views/Updates.svelte';
  import Settings from './views/Settings.svelte';
  import Events from './views/Events.svelte';

  type ViewId = 'dashboard' | 'servers' | 'devices' | 'routing' | 'updates' | 'settings' | 'events';

  const navGroups: { title?: string; items: { id: ViewId; label: string; icon: ViewId }[] }[] = [
    {
      items: [{ id: 'dashboard', label: 'Dashboard', icon: 'dashboard' }]
    },
    {
      title: 'Proxy & Network',
      items: [
        { id: 'servers', label: 'Servers & Subs', icon: 'servers' },
        { id: 'devices', label: 'Devices & Leases', icon: 'devices' },
        { id: 'routing', label: 'Routing & DNS', icon: 'routing' }
      ]
    },
    {
      title: 'Operations',
      items: [
        { id: 'updates', label: 'Updates & Cores', icon: 'updates' },
        { id: 'events', label: 'Live Events', icon: 'events' },
        { id: 'settings', label: 'Settings & Security', icon: 'settings' }
      ]
    }
  ];

  const navItems = navGroups.flatMap((g) => g.items);

  function viewFromPath(): ViewId {
    const seg = window.location.pathname.replace(/^\/+|\/+$/g, '') as ViewId;
    if (navItems.some((n) => n.id === seg)) return seg;
    return 'dashboard';
  }

  let view = $state<ViewId>(viewFromPath());
  let theme = $state<'dark' | 'light'>(
    (localStorage.getItem('tikray_theme') as 'dark' | 'light') || 'dark'
  );
  let mobileMenu = $state(false);

  // Auth phase
  let loadingAuth = $state(true);
  let setupRequired = $state(false);
  let signedIn = $state(false);
  let username = $state('');

  // Control plane snapshots
  let status = $state<ServiceStatus | null>(null);
  let stateData = $state<State | null>(null);
  let stats = $state<ServiceStats | null>(null);
  let events = $state<ServiceEvent[]>([]);
  let bootId = $state('');
  let eventsPaused = $state(false);
  let paletteOpen = $state(false);
  let rateHistory = $state<RateSample[]>([]);
  let lastCounter: { at: number; down: number; up: number } | null = null;

  function recordStatsSample(next: ServiceStats): void {
    stats = next;
    if (!next.available) return;
    const now = Date.now();
    const tun = next.inbounds.find((i) => i.tag === 'tun-in');
    let down = 0;
    let up = 0;
    if (tun && (tun.downlink > 0 || tun.uplink > 0)) {
      down = tun.downlink;
      up = tun.uplink;
    } else {
      for (const o of next.outbounds) {
        down += o.downlink;
        up += o.uplink;
      }
    }
    if (lastCounter && now > lastCounter.at) {
      const dt = (now - lastCounter.at) / 1000;
      const downBps = down >= lastCounter.down ? (down - lastCounter.down) / dt : 0;
      const upBps = up >= lastCounter.up ? (up - lastCounter.up) / dt : 0;
      rateHistory = [...rateHistory, { at: now, downBps, upBps }].slice(-36);
    } else if (rateHistory.length === 0) {
      rateHistory = [{ at: now, downBps: 0, upBps: 0 }];
    }
    lastCounter = { at: now, down, up };
  }

  async function quickApplyNow(): Promise<void> {
    try {
      const res = await api.applyNow();
      toast.ok(res.hot ? 'Applied live via xray hot-reload.' : `Applied (${res.outcome}).`);
      await refreshAll();
    } catch (err) {
      toast.err(err instanceof ApiError ? err.detail || err.message : 'Apply failed');
    }
  }

  $effect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('tikray_theme', theme);
  });

  function navigate(next: string): void {
    const id = (navItems.some((n) => n.id === next) ? next : 'dashboard') as ViewId;
    view = id;
    mobileMenu = false;
    const target = id === 'dashboard' ? '/' : `/${id}`;
    if (window.location.pathname !== target) {
      window.history.pushState({}, '', target);
    }
  }

  async function checkAuth(): Promise<void> {
    loadingAuth = true;
    try {
      const a = await api.getAuthState();
      setupRequired = a.setup_required;
      signedIn = a.signed_in;
      if (signedIn) {
        const sess = await api.getSession();
        username = sess.username ?? 'admin';
        await refreshAll();
      }
    } catch {
      signedIn = false;
    } finally {
      loadingAuth = false;
    }
  }

  async function refreshAll(): Promise<void> {
    const [stRes, stateRes, statsRes] = await Promise.allSettled([
      api.getStatus(),
      api.getState(),
      api.getStats()
    ]);
    if (stRes.status === 'fulfilled') status = stRes.value;
    if (stateRes.status === 'fulfilled') stateData = stateRes.value;
    if (statsRes.status === 'fulfilled') recordStatsSample(statsRes.value);
    await pollEvents(false);
  }

  async function pollEvents(incremental: boolean): Promise<void> {
    try {
      const lastSeq = incremental && events.length > 0 ? events[events.length - 1].seq : 0;
      const res = await api.getEvents(lastSeq);
      if (res.bootId && bootId && res.bootId !== bootId) {
        // Control plane restarted — seq reset from 1, reload full ring buffer.
        bootId = res.bootId;
        const fresh = await api.getEvents(0);
        events = fresh.events;
        toast.info('Control plane restarted — refreshed event log.');
        return;
      }
      if (res.bootId) bootId = res.bootId;
      if (!incremental || lastSeq === 0) {
        events = res.events;
      } else if (res.events.length > 0) {
        events = [...events, ...res.events].slice(-200);
      }
    } catch {
      // Ignore transient poll errors; 401 is handled globally.
    }
  }

  async function handleAuthenticated(): Promise<void> {
    setupRequired = false;
    signedIn = true;
    const sess = await api.getSession();
    username = sess.username ?? 'admin';
    await refreshAll();
  }

  async function signOut(): Promise<void> {
    try {
      await api.logout();
    } catch {
      // Clear local session regardless.
    }
    signedIn = false;
    status = null;
    stateData = null;
    stats = null;
    events = [];
  }

  $effect(() => {
    onUnauthorized(() => {
      if (signedIn) {
        signedIn = false;
        toast.warn('Your session expired. Sign in again.');
      }
    });
    const onPop = () => {
      view = viewFromPath();
    };
    const onGlobalKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (signedIn) paletteOpen = !paletteOpen;
      }
    };
    window.addEventListener('popstate', onPop);
    window.addEventListener('keydown', onGlobalKey);
    checkAuth();
    return () => {
      window.removeEventListener('popstate', onPop);
      window.removeEventListener('keydown', onGlobalKey);
    };
  });

  // Live background polling while signed in
  $effect(() => {
    if (!signedIn) return;
    const statusTimer = setInterval(async () => {
      const [stRes, statsRes] = await Promise.allSettled([api.getStatus(), api.getStats()]);
      if (stRes.status === 'fulfilled') status = stRes.value;
      if (statsRes.status === 'fulfilled') recordStatsSample(statsRes.value);
    }, 5000);
    const eventTimer = setInterval(() => {
      if (!eventsPaused) {
        pollEvents(true);
      }
    }, 3000);
    return () => {
      clearInterval(statusTimer);
      clearInterval(eventTimer);
    };
  });

  const activeTitle = $derived(navItems.find((n) => n.id === view)?.label ?? 'Dashboard');
</script>

{#if loadingAuth}
  <div class="auth-page">
    <div class="hint">Connecting to tikray…</div>
  </div>
{:else if !signedIn}
  <SetupLogin {setupRequired} onAuthenticated={handleAuthenticated} />
{:else}
  <div class="shell">
    {#if mobileMenu}
      <div class="sidebar-scrim" role="presentation" onclick={() => (mobileMenu = false)}></div>
    {/if}

    <aside class="sidebar {mobileMenu ? 'open' : ''}">
      <div class="brand-row">
        <div class="brand">
          <div class="brand-mark">
            <svg width="16" height="16" viewBox="0 0 32 32" aria-hidden="true">
              <path d="M16 4L27 10V22L16 28L5 22V10L16 4Z" fill="none" stroke="var(--accent)" stroke-width="2.6" />
              <circle cx="16" cy="16" r="3.8" fill="var(--ok)" />
            </svg>
          </div>
          <div>
            <span class="brand-title">tikray</span>
            <span class="brand-sub mono">{status?.version || 'v1.0.0'}</span>
          </div>
        </div>
        {#if status}
          {@const lvl = status.health.level}
          {@const liveTone =
            lvl === 'ok'
              ? 'ok'
              : lvl === 'degraded'
                ? 'warn'
                : lvl === 'down' || lvl === 'outage'
                  ? 'danger'
                  : 'accent'}
          <span class="live-pill">
            <span class="dot {liveTone}"></span>
            {lvl === 'ok' ? 'Live' : lvl === 'idle' ? 'Idle' : lvl}
          </span>
        {/if}
      </div>

      <div class="sidebar-tools">
        <button
          type="button"
          class="sidebar-search"
          title="Open Command Palette (Ctrl+K)"
          onclick={() => (paletteOpen = true)}
        >
          <span class="row" style="gap: 6px">
            <Icon name="search" size={13} />
            <span>Search</span>
          </span>
          <span class="kbd">Ctrl K</span>
        </button>
        <button
          type="button"
          class="sidebar-bell"
          title="View Live Events"
          aria-label="View Live Events"
          onclick={() => navigate('events')}
        >
          <Icon name="bell" size={14} />
          {#if status && (status.health.level === 'degraded' || status.health.level === 'outage' || status.health.level === 'down' || status.geo_degraded)}
            <span class="bell-dot"></span>
          {/if}
        </button>
      </div>

      <nav class="nav" aria-label="Primary">
        {#each navGroups as group}
          {#if group.title}
            <div class="nav-group">{group.title}</div>
          {/if}
          {#each group.items as item (item.id)}
            <button
              type="button"
              class="nav-item {view === item.id ? 'active' : ''}"
              onclick={() => navigate(item.id)}
            >
              <Icon name={item.icon} size={15} />
              <span>{item.label}</span>
              {#if item.id === 'servers' && stateData}
                <span class="nav-badge tabular">{stateData.servers.length}</span>
              {:else if item.id === 'devices' && stateData}
                <span class="nav-badge tabular">{stateData.devices.length}</span>
              {/if}
            </button>
          {/each}
        {/each}
      </nav>

      <div class="sidebar-footer">
        <div class="sidebar-profile">
          <span class="avatar">{(username || 'A').slice(0, 1)}</span>
          <div class="sidebar-user-meta">
            <span class="sidebar-user-name">{username || 'admin'}</span>
            <span class="sidebar-user-role">Administrator</span>
          </div>
        </div>
        <div class="row" style="gap: 2px">
          <button
            type="button"
            class="btn btn-ghost btn-icon"
            title="Toggle dark/light theme"
            aria-label="Toggle color theme"
            onclick={() => (theme = theme === 'dark' ? 'light' : 'dark')}
          >
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={14} />
          </button>
          <button
            type="button"
            class="btn btn-ghost btn-icon"
            title="Sign Out"
            aria-label="Sign Out"
            onclick={signOut}
          >
            <Icon name="logout" size={14} />
          </button>
        </div>
      </div>
    </aside>

    <div class="main-col">
      <header class="mobile-topbar">
        <div class="row" style="gap: 10px">
          <button
            type="button"
            class="btn btn-ghost btn-icon"
            aria-label="Open menu"
            onclick={() => (mobileMenu = !mobileMenu)}
          >
            <Icon name="menu" size={18} />
          </button>
          <span style="font-size: 14px; font-weight: 600">{activeTitle}</span>
        </div>
        <div class="row" style="gap: 6px">
          <button type="button" class="btn btn-sm" onclick={() => (paletteOpen = true)}>
            <Icon name="search" size={13} />
          </button>
          <button type="button" class="btn btn-sm" onclick={refreshAll}>
            <Icon name="refresh" size={13} />
          </button>
        </div>
      </header>

      <main class="content">
        {#key view}
          <div class="view-enter">
            {#if view === 'dashboard'}
              <Dashboard
                {username}
                {status}
                {stateData}
                {stats}
                {rateHistory}
                {events}
                onRefresh={refreshAll}
                onNavigate={navigate}
              />
            {:else}
              <div class="page-header">
                <div>
                  <h1 class="page-title">{activeTitle}</h1>
                  <p class="page-sub">
                    {#if view === 'servers'}
                      Manage proxy outbounds, subscriptions, visual share-link settings, and v2rayN-style latency probes
                    {:else if view === 'devices'}
                      Configure LAN default policy, per-device overrides, kill switches, and static RouterOS DHCP leases
                    {:else if view === 'routing'}
                      Ordered domain/IP rules, domestic bypass lists, DoH resolvers, and connectivity probes
                    {:else if view === 'updates'}
                      Four independent update lifecycles with cryptographic verification, offline inbox, and automatic rollback
                    {:else if view === 'events'}
                      Redacted real-time control-plane, health, and RouterOS reconciliation audit trail
                    {:else if view === 'settings'}
                      Encrypted backups, scoped API tokens, password rotation, and RouterOS bridge configuration
                    {/if}
                  </p>
                </div>
                <button type="button" class="btn btn-sm" onclick={refreshAll}>
                  <Icon name="refresh" size={13} /> Refresh
                </button>
              </div>
              {#if view === 'servers'}
                <Servers {status} {stateData} onRefresh={refreshAll} />
              {:else if view === 'devices'}
                <Devices {status} {stateData} onRefresh={refreshAll} />
              {:else if view === 'routing'}
                <Routing {stateData} onRefresh={refreshAll} />
              {:else if view === 'updates'}
                <Updates {status} onRefresh={refreshAll} />
              {:else if view === 'events'}
                <Events
                  {events}
                  {bootId}
                  paused={eventsPaused}
                  onTogglePause={() => (eventsPaused = !eventsPaused)}
                  onReload={() => pollEvents(false)}
                />
              {:else if view === 'settings'}
                <Settings {status} {stateData} onRefresh={refreshAll} />
              {/if}
            {/if}
          </div>
        {/key}
      </main>
    </div>
  </div>

  <CommandPalette
    open={paletteOpen}
    servers={stateData?.servers ?? []}
    onClose={() => (paletteOpen = false)}
    onNavigate={navigate}
    onToggleTheme={() => (theme = theme === 'dark' ? 'light' : 'dark')}
    onRefresh={refreshAll}
    onApplyNow={quickApplyNow}
    onSignOut={signOut}
  />
{/if}

<!-- Toast notifications -->
{#if toast.items.length > 0}
  <div class="toasts" role="status" aria-live="polite">
    {#each toast.items as item (item.id)}
      <div class="toast {item.kind}">
        <span>{item.message}</span>
        <button class="btn btn-ghost btn-sm" style="padding: 1px 6px" onclick={() => toast.dismiss(item.id)}>×</button>
      </div>
    {/each}
  </div>
{/if}
