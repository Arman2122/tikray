<script lang="ts">
  import { api, ApiError } from '../lib/api';

  interface Props {
    setupRequired: boolean;
    onAuthenticated: () => Promise<void>;
  }

  let { setupRequired, onAuthenticated }: Props = $props();

  let code = $state('');
  let username = $state('admin');
  let password = $state('');
  let confirmPassword = $state('');
  let busy = $state(false);
  let error = $state('');
  let retrySeconds = $state(0);

  $effect(() => {
    if (retrySeconds <= 0) return;
    const id = setInterval(() => {
      retrySeconds = Math.max(0, retrySeconds - 1);
    }, 1000);
    return () => clearInterval(id);
  });

  async function submit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    error = '';
    if (setupRequired) {
      if (password.length < 10) {
        error = 'Password must be at least 10 characters long.';
        return;
      }
      if (password !== confirmPassword) {
        error = 'Passwords do not match.';
        return;
      }
    }
    busy = true;
    try {
      if (setupRequired) {
        await api.setup(code.trim(), username.trim(), password);
      } else {
        await api.login(username.trim(), password);
      }
      password = '';
      confirmPassword = '';
      code = '';
      await onAuthenticated();
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.detail || err.message;
        if (err.status === 429 && err.retryAfter) {
          retrySeconds = err.retryAfter;
        }
      } else {
        error = 'Request failed. Check connectivity to the router.';
      }
    } finally {
      busy = false;
    }
  }
</script>

<div class="auth-page">
  <div class="auth-card stack-lg">
    <div class="row" style="gap: 12px">
      <div class="brand-mark" style="width: 40px; height: 40px">
        <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
          <path d="M16 4L27 10V22L16 28L5 22V10L16 4Z" fill="none" stroke="var(--accent)" stroke-width="2.4" />
          <circle cx="16" cy="16" r="3.6" fill="var(--ok)" />
        </svg>
      </div>
      <div>
        <h1 style="font-size: 20px; font-weight: 700; letter-spacing: -0.02em">tikray</h1>
        <p class="card-sub">
          {setupRequired ? 'Initial Administrator Setup' : 'MikroTik RouterOS Proxy Control Plane'}
        </p>
      </div>
    </div>

    {#if setupRequired}
      <div class="alert">
        <div style="font-weight: 600; margin-bottom: 6px">Get your one-time setup code</div>
        <div class="hint" style="margin-bottom: 8px">
          Run this command inside the <code>tikray</code> container on your MikroTik router:
        </div>
        <div class="code-block">/container/shell [find comment="tikray:ctl"] cmd="tikray setup-code"</div>
      </div>
    {/if}

    {#if error}
      <div class="alert danger" role="alert">
        {error}
        {#if retrySeconds > 0}
          <div class="hint tabular" style="margin-top: 4px; color: var(--danger)">
            Rate limited — try again in {retrySeconds}s
          </div>
        {/if}
      </div>
    {/if}

    <form class="stack" onsubmit={submit}>
      {#if setupRequired}
        <div class="field">
          <label for="setup-code">Setup Code</label>
          <input
            id="setup-code"
            class="input mono"
            type="text"
            autocomplete="one-time-code"
            placeholder="XXXX-XXXX-XXXX"
            bind:value={code}
            required
          />
        </div>
      {/if}

      <div class="field">
        <label for="username">Username</label>
        <input
          id="username"
          class="input"
          type="text"
          autocomplete="username"
          bind:value={username}
          required
        />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          class="input"
          type="password"
          autocomplete={setupRequired ? 'new-password' : 'current-password'}
          bind:value={password}
          minlength={setupRequired ? 10 : undefined}
          required
        />
        {#if setupRequired}
          <span class="hint">Minimum 10 characters. Stored with Argon2id.</span>
        {/if}
      </div>

      {#if setupRequired}
        <div class="field">
          <label for="confirm">Confirm Password</label>
          <input
            id="confirm"
            class="input"
            type="password"
            autocomplete="new-password"
            bind:value={confirmPassword}
            minlength={10}
            required
          />
        </div>
      {/if}

      <button
        type="submit"
        class="btn btn-primary"
        style="width: 100%; padding: 10px 14px; margin-top: 4px"
        disabled={busy || retrySeconds > 0}
      >
        {#if busy}
          Authenticating…
        {:else if retrySeconds > 0}
          Wait {retrySeconds}s
        {:else if setupRequired}
          Create Admin Account
        {:else}
          Sign In
        {/if}
      </button>
    </form>

    <div class="hint" style="text-align: center">
      Session secured with <code>HttpOnly</code> + <code>SameSite=Strict</code> cookie &amp; CSRF protection.
    </div>
  </div>
</div>
