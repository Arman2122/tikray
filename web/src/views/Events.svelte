<script lang="ts">
  import type { ServiceEvent } from '../lib/api';
  import { formatTime } from '../lib/format';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../components/Icon.svelte';

  interface Props {
    events: ServiceEvent[];
    bootId: string;
    paused: boolean;
    onTogglePause: () => void;
    onReload: () => Promise<void>;
  }

  let { events, bootId, paused, onTogglePause, onReload }: Props = $props();

  let selectedKind = $state('all');
  let search = $state('');

  const kinds = ['all', 'apply', 'core', 'geo', 'image', 'routeros', 'refresh', 'auth', 'warning', 'degraded', 'error'];

  const filtered = $derived.by(() => {
    const q = search.trim().toLowerCase();
    return [...events]
      .reverse()
      .filter((ev) => {
        if (selectedKind !== 'all' && ev.kind !== selectedKind) return false;
        if (!q) return true;
        return ev.message.toLowerCase().includes(q) || ev.kind.toLowerCase().includes(q);
      });
  });

  async function copyLogs(): Promise<void> {
    const lines = filtered
      .map((ev) => `${ev.seq}\t${ev.at}\t${ev.kind}\t${ev.message}`)
      .join('\n');
    try {
      await navigator.clipboard.writeText(lines);
      toast.ok(`Copied ${filtered.length} event lines to clipboard.`);
    } catch {
      toast.warn('Clipboard unavailable in this browser context.');
    }
  }
</script>

<div class="card stack">
  <div class="card-header" style="margin-bottom: 0">
    <div>
      <h2 class="card-title">Live Control-Plane Event Stream</h2>
      <p class="card-sub">
        Redacted ring buffer (up to 200 events per process lifetime)
        {#if bootId}
          · Boot ID <code class="mono">{bootId}</code>
        {/if}
      </p>
    </div>
    <div class="row">
      <button class="btn btn-sm" onclick={onTogglePause}>
        {paused ? 'Resume Auto-Poll' : 'Pause Auto-Poll'}
      </button>
      <button class="btn btn-sm" onclick={onReload}>
        <Icon name="refresh" size={13} /> Reload
      </button>
      <button class="btn btn-sm" disabled={filtered.length === 0} onclick={copyLogs}>
        <Icon name="copy" size={13} /> Copy
      </button>
    </div>
  </div>

  <div class="row-between">
    <div class="row" style="gap: 5px">
      {#each kinds as k}
        <button class="chip {selectedKind === k ? 'active' : ''}" onclick={() => (selectedKind = k)}>
          {k}
        </button>
      {/each}
    </div>
    <input
      class="input search-input"
      type="search"
      placeholder="Filter message…"
      bind:value={search}
    />
  </div>

  {#if filtered.length === 0}
    <div class="empty-state">No matching events.</div>
  {:else}
    <div class="table-wrap">
      <table class="responsive-table">
        <thead>
          <tr>
            <th>Seq</th>
            <th>Timestamp</th>
            <th>Kind</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as ev (ev.seq)}
            <tr>
              <td data-label="Seq" class="mono tabular" style="color: var(--text-dim)">{ev.seq}</td>
              <td data-label="Time" class="tabular" style="white-space: nowrap; color: var(--text-muted); font-size: 12.5px">
                {formatTime(ev.at)}
              </td>
              <td data-label="Kind">
                <span
                  class="badge {ev.kind === 'error' || ev.kind === 'degraded'
                    ? 'danger'
                    : ev.kind === 'warning' || ev.kind === 'untested'
                      ? 'warn'
                      : ev.kind === 'apply' || ev.kind === 'routeros'
                        ? 'ok'
                        : 'accent'}"
                >
                  {ev.kind}
                </span>
              </td>
              <td data-label="Message" class="mono" style="font-size: 12.5px; word-break: break-word">{ev.message}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
