<script lang="ts">
  import type { Server } from '../lib/api';

  interface CommandItem {
    id: string;
    group: string;
    label: string;
    hint?: string;
    run: () => void;
  }

  interface Props {
    open: boolean;
    servers: Server[];
    onClose: () => void;
    onNavigate: (view: string) => void;
    onToggleTheme: () => void;
    onRefresh: () => void;
    onApplyNow: () => void;
    onSignOut: () => void;
  }

  let { open, servers, onClose, onNavigate, onToggleTheme, onRefresh, onApplyNow, onSignOut }: Props = $props();

  let query = $state('');
  let selectedIdx = $state(0);
  let inputEl = $state<HTMLInputElement | null>(null);

  const items = $derived.by<CommandItem[]>(() => {
    const base: CommandItem[] = [
      { id: 'nav-dashboard', group: 'Navigate', label: 'Dashboard', hint: 'Health, throughput & topology', run: () => onNavigate('dashboard') },
      { id: 'nav-servers', group: 'Navigate', label: 'Servers & Subscriptions', hint: 'Manage share links & feeds', run: () => onNavigate('servers') },
      { id: 'nav-devices', group: 'Navigate', label: 'Devices & Policy', hint: 'LAN overrides & RouterOS leases', run: () => onNavigate('devices') },
      { id: 'nav-routing', group: 'Navigate', label: 'Routing & DNS', hint: 'Rules, domestic bypass & DoH', run: () => onNavigate('routing') },
      { id: 'nav-updates', group: 'Navigate', label: 'Updates & Offline Inbox', hint: 'xray-core, geo & images', run: () => onNavigate('updates') },
      { id: 'nav-events', group: 'Navigate', label: 'Live Events', hint: 'Control-plane log stream', run: () => onNavigate('events') },
      { id: 'nav-settings', group: 'Navigate', label: 'Settings & Encrypted Backups', hint: 'Backups, tokens & password', run: () => onNavigate('settings') },
      { id: 'act-apply', group: 'Actions', label: 'Apply Configuration Now', hint: 'Hot-reload or trial active state', run: onApplyNow },
      { id: 'act-refresh', group: 'Actions', label: 'Refresh Live Telemetry', hint: 'Reload status, stats & state', run: onRefresh },
      { id: 'act-theme', group: 'Actions', label: 'Toggle Dark / Light Theme', hint: 'Switch UI color palette', run: onToggleTheme },
      { id: 'act-logout', group: 'Actions', label: 'Sign Out', hint: 'End current admin session', run: onSignOut }
    ];
    for (const s of servers.slice(0, 12)) {
      base.push({
        id: `srv-${s.id}`,
        group: 'Servers',
        label: s.name,
        hint: `${s.outbound?.protocol?.toUpperCase() ?? 'PROXY'} · ${s.id}`,
        run: () => onNavigate('servers')
      });
    }
    const q = query.trim().toLowerCase();
    if (!q) return base;
    return base.filter(
      (i) =>
        i.label.toLowerCase().includes(q) ||
        i.group.toLowerCase().includes(q) ||
        (i.hint && i.hint.toLowerCase().includes(q))
    );
  });

  $effect(() => {
    if (open) {
      query = '';
      selectedIdx = 0;
      setTimeout(() => inputEl?.focus(), 10);
    }
  });

  $effect(() => {
    if (selectedIdx >= items.length) {
      selectedIdx = Math.max(0, items.length - 1);
    }
  });

  function exec(item: CommandItem): void {
    onClose();
    item.run();
  }

  function handleKey(e: KeyboardEvent): void {
    if (!open) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (items.length > 0) selectedIdx = (selectedIdx + 1) % items.length;
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (items.length > 0) selectedIdx = (selectedIdx - 1 + items.length) % items.length;
    } else if (e.key === 'Enter' && items[selectedIdx]) {
      e.preventDefault();
      exec(items[selectedIdx]);
    }
  }
</script>

<svelte:window onkeydown={handleKey} />

{#if open}
  <div
    class="modal-backdrop"
    style="align-items: start; padding-top: 12vh"
    role="presentation"
    onclick={(e) => {
      if (e.target === e.currentTarget) onClose();
    }}
  >
    <div class="modal palette" role="dialog" aria-modal="true" aria-label="Command palette" tabindex="-1">
      <input
        bind:this={inputEl}
        class="palette-input"
        type="search"
        placeholder="Jump to view, server, or action… (↑↓ Enter Esc)"
        bind:value={query}
      />
      <div class="palette-list">
        {#if items.length === 0}
          <div class="hint" style="padding: 18px; text-align: center">No matching commands.</div>
        {:else}
          {#each items as item, idx (item.id)}
            <button
              type="button"
              class="palette-item {idx === selectedIdx ? 'active' : ''}"
              onmouseenter={() => (selectedIdx = idx)}
              onclick={() => exec(item)}
            >
              <div class="row" style="gap: 8px">
                <span class="badge" style="font-size: 10.5px; padding: 1px 7px">{item.group}</span>
                <span style="font-weight: 550">{item.label}</span>
              </div>
              {#if item.hint}
                <span class="hint" style="font-size: 12px">{item.hint}</span>
              {/if}
            </button>
          {/each}
        {/if}
      </div>
    </div>
  </div>
{/if}
