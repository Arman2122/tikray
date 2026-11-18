<script lang="ts">
  import {
    api,
    onUnauthorized,
    type ServiceEvent,
    type ServiceStats,
    type ServiceStatus,
    type State
  } from './lib/api';
  import { toast } from './lib/toast.svelte';
  import Icon from './components/Icon.svelte';
  import SetupLogin from './views/SetupLogin.svelte';
  import Dashboard from './views/Dashboard.svelte';
  import Servers from './views/Servers.svelte';
  import Devices from './views/Devices.svelte';
  import Routing from './views/Routing.svelte';
  import Updates from './views/Updates.svelte';
  import Settings from './views/Settings.svelte';
  import Events from './views/Events.svelte';

  type ViewId = 'dashboard' | 'servers' | 'devices' | 'routing' | 'updates' | 'settings' | 'events';

  const navItems: { id: ViewId; label: string; icon: ViewId }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
    { id: 'servers', label: 'Servers & Subs', icon: 'servers' },
    { id: 'devices', label: 'Devices & Policy', icon: 'devices' },
    { id: 'routing', label: 'Routing & DNS', icon: 'routing' },
    { id: 'updates', label: 'Updates', icon: 'updates' },
    { id: 'events', label: 'Events', icon: 'events' },
    { id: 'settings', label: 'Settings', icon: 'settings' }
  ];

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
    if (statsRes.status === 'fulfilled') stats = statsRes.value;
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
    window.addEventListener('popstate', onPop);
    checkAuth();
    return () => window.removeEventListener('popstate', onPop);
  });

  // Live background polling while signed in
  $effect(() => {
    if (!signedIn) return;
    const statusTimer = setInterval(async () => {
      const [stRes, statsRes] = await Promise.allSettled([api.getStatus(), api.getStats()]);
      if (stRes.status === 'fulfilled') status = stRes.value;
      if (statsRes.status === 'fulfilled') stats = statsRes.value;
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
      <div class="brand">
        <div class="brand-mark">
          <svg width="18" height="18" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 4L27 10V22L16 28L5 22V10L16 4Z" fill="none" stroke="var(--accent)" stroke-width="2.6" />
            <circle cx="16" cy="16" r="3.8" fill="var(--ok)" />
          </svg>
        </div>
        <div>
          <span class="brand-title">tikray</span>
          <span class="brand-sub mono">{status?.version || 'v1.0'}</span>
        </div>
      </div>

      <nav class="nav" aria-label="Primary">
        {#each navItems as item (item.id)}
          <button
            class="nav-item {view === item.id ? 'active' : ''}"
            onclick={() => navigate(item.id)}
          >
            <Icon name={item.icon} size={16} />
            <span>{item.label}</span>
            {#if item.id === 'servers' && stateData}
              <span class="nav-badge tabular">{stateData.servers.length}</span>
            {:else if item.id === 'devices' && stateData}
              <span class="nav-badge tabular">{stateData.devices.length}</span>
            {/if}
          </button>
        {/each}
      </nav>

      <div class="sidebar-footer">
        <div class="sidebar-user">
          <span>Signed in as <strong>{username}</strong></span>
          <button
            class="btn btn-ghost btn-icon"
            title="Toggle color theme"
            aria-label="Toggle color theme"
            onclick={() => (theme = theme === 'dark' ? 'light' : 'dark')}
          >
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={15} />
          </button>
        </div>
        <button class="btn btn-sm" style="width: 100%" onclick={signOut}>
          <Icon name="logout" size={14} /> Sign Out
        </button>
      </div>
    </aside>

    <div class="main-col">
      <header class="topbar">
        <div class="topbar-left">
          <button
            class="btn btn-ghost btn-icon mobile-menu-btn"
            aria-label="Open menu"
            onclick={() => (mobileMenu = !mobileMenu)}
          >
            <Icon name="menu" size={18} />
          </button>
          <h1 class="topbar-title">{activeTitle}</h1>
        </div>

        <div class="topbar-actions">
          {#if status}
            <span
              class="badge {status.health.level === 'healthy'
                ? 'ok'
                : status.health.level === 'degraded'
                  ? 'warn'
                  : status.health.level === 'down'
                    ? 'danger'
                    : ''}"
            >
              <span
                class="dot {status.health.level === 'healthy'
                  ? 'ok'
                  : status.health.level === 'degraded'
                    ? 'warn'
                    : status.health.level === 'down'
                      ? 'danger'
                      : ''}"
              ></span>
              {status.health.level}
            </span>
          {/if}
          <button class="btn btn-sm" onclick={refreshAll}>
            <Icon name="refresh" size={13} /> Refresh
          </button>
        </div>
      </header>

      <main class="content">
        {#if view === 'dashboard'}
          <Dashboard {status} {stateData} {stats} {events} onRefresh={refreshAll} onNavigate={navigate} />
        {:else if view === 'servers'}
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
      </main>
    </div>
  </div>
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
