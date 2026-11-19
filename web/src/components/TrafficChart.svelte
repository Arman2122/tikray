<script lang="ts">
  import { formatBytes } from '../lib/format';

  export interface RateSample {
    at: number;
    downBps: number;
    upBps: number;
  }

  interface Props {
    samples: RateSample[];
    available: boolean;
  }

  let { samples, available }: Props = $props();

  const W = 560;
  const H = 132;
  const PAD_X = 6;
  const PAD_Y = 12;

  const maxBps = $derived.by(() => {
    let m = 1024; // minimum 1 KiB/s scale so flatlines sit nicely at the bottom
    for (const s of samples) {
      if (s.downBps > m) m = s.downBps;
      if (s.upBps > m) m = s.upBps;
    }
    return m * 1.15;
  });

  const latest = $derived(samples.length > 0 ? samples[samples.length - 1] : { at: 0, downBps: 0, upBps: 0 });

  function buildPath(values: number[]): { line: string; area: string } {
    if (values.length === 0) return { line: '', area: '' };
    const count = Math.max(values.length - 1, 1);
    const pts = values.map((v, idx) => {
      const x = PAD_X + (idx / count) * (W - PAD_X * 2);
      const ratio = Math.min(1, Math.max(0, v / maxBps));
      const y = H - PAD_Y - ratio * (H - PAD_Y * 2);
      return [x, y] as const;
    });
    if (pts.length === 1) {
      const [, y] = pts[0];
      return {
        line: `M ${PAD_X} ${y.toFixed(1)} L ${(W - PAD_X).toFixed(1)} ${y.toFixed(1)}`,
        area: `M ${PAD_X} ${H - PAD_Y} L ${PAD_X} ${y.toFixed(1)} L ${(W - PAD_X).toFixed(1)} ${y.toFixed(1)} L ${(W - PAD_X).toFixed(1)} ${H - PAD_Y} Z`
      };
    }
    let d = `M ${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
    for (let i = 1; i < pts.length; i++) {
      const [x0, y0] = pts[i - 1];
      const [x1, y1] = pts[i];
      const cx = ((x0 + x1) / 2).toFixed(1);
      d += ` C ${cx} ${y0.toFixed(1)}, ${cx} ${y1.toFixed(1)}, ${x1.toFixed(1)} ${y1.toFixed(1)}`;
    }
    const last = pts[pts.length - 1];
    const first = pts[0];
    const area = `${d} L ${last[0].toFixed(1)} ${(H - PAD_Y).toFixed(1)} L ${first[0].toFixed(1)} ${(H - PAD_Y).toFixed(1)} Z`;
    return { line: d, area };
  }

  const downGeo = $derived(buildPath(samples.map((s) => s.downBps)));
  const upGeo = $derived(buildPath(samples.map((s) => s.upBps)));
</script>

<div class="card stack" style="gap: 12px">
  <div class="row-between">
    <div>
      <h2 class="card-title">Live Proxy Throughput</h2>
      <p class="card-sub">Real-time transfer rate sampled from xray-core gRPC counters (5s window)</p>
    </div>
    <div class="row" style="gap: 10px">
      <span class="badge accent tabular">↓ {formatBytes(latest.downBps)}/s</span>
      <span class="badge ok tabular">↑ {formatBytes(latest.upBps)}/s</span>
    </div>
  </div>

  {#if !available}
    <div class="empty-state" style="padding: 24px">
      Waiting for xray-core stats stream to come online…
    </div>
  {:else}
    <div class="chart-wrap">
      <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" class="spark-svg" role="img" aria-label="Live bandwidth chart">
        <defs>
          <linearGradient id="downFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.34" />
            <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.02" />
          </linearGradient>
          <linearGradient id="upFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--ok)" stop-opacity="0.28" />
            <stop offset="100%" stop-color="var(--ok)" stop-opacity="0.01" />
          </linearGradient>
        </defs>

        <!-- Grid lines -->
        {#each [0.25, 0.5, 0.75] as frac}
          <line
            x1={PAD_X}
            x2={W - PAD_X}
            y1={PAD_Y + frac * (H - PAD_Y * 2)}
            y2={PAD_Y + frac * (H - PAD_Y * 2)}
            stroke="var(--border)"
            stroke-dasharray="3 4"
            stroke-width="1"
          />
        {/each}

        {#if downGeo.area}
          <path d={downGeo.area} fill="url(#downFill)" />
          <path d={downGeo.line} fill="none" stroke="var(--accent)" stroke-width="2" />
        {/if}
        {#if upGeo.area}
          <path d={upGeo.area} fill="url(#upFill)" />
          <path d={upGeo.line} fill="none" stroke="var(--ok)" stroke-width="1.8" />
        {/if}
      </svg>
      <div class="row-between hint tabular" style="margin-top: 4px; font-size: 11.5px">
        <span>Peak scale: {formatBytes(maxBps)}/s</span>
        <span>{samples.length} sample{samples.length === 1 ? '' : 's'} · zero external telemetry</span>
      </div>
    </div>
  {/if}
</div>
