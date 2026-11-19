<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    wide?: boolean;
    closable?: boolean;
    onClose?: () => void;
    children: Snippet;
  }

  let { title, wide = false, closable = true, onClose, children }: Props = $props();

  function handleWindowKey(e: KeyboardEvent): void {
    if (closable && e.key === 'Escape') {
      onClose?.();
    }
  }

  function handleBackdropClick(e: MouseEvent): void {
    if (closable && e.target === e.currentTarget) {
      onClose?.();
    }
  }
</script>

<svelte:window onkeydown={handleWindowKey} />

<div class="modal-backdrop" role="presentation" onclick={handleBackdropClick}>
  <div class="modal {wide ? 'modal-wide' : ''} stack" role="dialog" aria-modal="true" aria-label={title} tabindex="-1">
    <div class="modal-header">
      <h3 class="card-title">{title}</h3>
      {#if closable && onClose}
        <button type="button" class="btn btn-ghost btn-sm" onclick={onClose}>Close</button>
      {/if}
    </div>
    {@render children()}
  </div>
</div>
