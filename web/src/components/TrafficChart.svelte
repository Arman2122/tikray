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

  const W = 540;
  const H = 160;
  const PAD_L = 6;
  const PAD_R = 62;
  const PAD_T = 14;
  const PAD_B = 22;

  let hoverIdx = $state<number | null>(null);

  const plotW = W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;

  const maxBps = $derived.by(() => {
    let m = 2048;
    for (const s of samples) {
      if (s.downBps > m) m = s.downBps;
      if (s.upBps > m) m = s.upBps;
    }
    return m * 1.15;
  });

  const latest = $derived(samples.length > 0 ? samples[samples.length - 1] : { at: Date.now(), downBps: 0, upBps: 0 });
  const peakDown = $derived(samples.reduce((acc, s) => Math.max(acc, s.downBps), 0));

  function pointFor(i: number, value: number): [number, number] {
    const count = Math.max(samples.length - 1, 1);
    const x = PAD_L + (i / count) * plotW;
    const y = PAD_T + plotH - Math.min(1, Math.max(0, value / maxBps)) * plotH;
    return [x, y];
  }

  function buildSmoothPath(pts: [number, number][]): string {
    if (pts.length === 0) return '';
    if (pts.length === 1) {
      const [, y] = pts[0];
      return `M ${PAD_L} ${y.toFixed(1)} L ${(PAD_L + plotW).toFixed(1)} ${y.toFixed(1)}`;
    }
    let d = `M ${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const [x0, y0] = pts[i];
      const [x1, y1] = pts[i + 1];
      const cx = ((x0 + x1) / 2).toFixed(1);
      d += ` C ${cx} ${y0.toFixed(1)}, ${cx} ${y1.toFixed(1)}, ${x1.toFixed(1)} ${y1.toFixed(1)}`;
    }
    return d;
  }

  function buildAreaPath(pts: [number, number][], linePath: string): string {
    if (!linePath) return '';
    const baseY = (PAD_T + plotH).toFixed(1);
    if (pts.length === 1) {
      return `${linePath} L ${(PAD_L + plotW).toFixed(1)} ${baseY} L ${PAD_L} ${baseY} Z`;
    }
    return `${linePath} L ${pts[pts.length - 1][0].toFixed(1)} ${baseY} L ${pts[0][0].toFixed(1)} ${baseY} Z`;
  }

  const downPts = $derived(samples.map((s, i) => pointFor(i, s.downBps)));
  const upPts = $derived(samples.map((s, i) => pointFor(i, s.upBps)));

  const downLine = $derived(buildSmoothPath(downPts));
  const upLine = $derived(buildSmoothPath(upPts));
  const downArea = $derived(buildAreaPath(downPts, downLine));
  const upArea = $derived(buildAreaPath(upPts, upLine));

  const hoveredSample = $derived(
    hoverIdx !== null && hoverIdx >= 0 && hoverIdx < samples.length ? samples[hoverIdx] : null
  );
  const hoveredDownPt = $derived(hoverIdx !== null && hoverIdx < downPts.length ? downPts[hoverIdx] : null);
  const hoveredUpPt = $derived(hoverIdx !== null && hoverIdx < upPts.length ? upPts[hoverIdx] : null);

  function fmtRate(bps: number): string {
    return `${formatBytes(bps)}/s`;
  }

  function fmtSampleTime(ts: number): string {
    return new Date(ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function handlePointerMove(e: MouseEvent): void {
    if (samples.length < 2) return;
    const svg = e.currentTarget as SVGSVGElement;
    const rect = svg.getBoundingClientRect();
    const relX = ((e.clientX - rect.left) / rect.width) * W;
    const clamped = Math.max(PAD_L, Math.min(PAD_L + plotW, relX));
    const ratio = (clamped - PAD_L) / plotW;
    hoverIdx = Math.round(ratio * (samples.length - 1));
  }

  const tooltipLeftPct = $derived.by(() => {
    if (!hoveredDownPt) return 0;
    const pct = (hoveredDownPt[0] / W) * 100;
    return pct > 62 ? Math.max(4, pct - 34) : Math.min(62, pct + 2);
  });
</script>

<div class="card stack" style="gap: 12px">
  <div class="row-between">
    <div>
      <h2 class="card-title">Live Proxy Throughput</h2>
      <p class="card-sub">Real-time transfer rate from xray-core gRPC counters · hover to inspect</p>
    </div>
    <div class="row" style="gap: 8px">
      <span class="badge accent tabular">↓ {fmtRate(latest.downBps)}</span>
      <span class="badge ok tabular">↑ {fmtRate(latest.upBps)}</span>
    </div>
  </div>

  {#if !available && samples.length === 0}
    <div class="empty-state" style="padding: 36px 16px">
      Waiting for xray-core stats stream to come online…
    </div>
  {:else}
    <div class="chart-wrap">
      {#if hoveredSample && hoveredDownPt}
        <div class="chart-tooltip tabular" style="left: {tooltipLeftPct}%">
          <span class="mono hint" style="font-size: 10.5px">{fmtSampleTime(hoveredSample.at)}</span>
          <span style="color: var(--accent); font-weight: 600">↓ {fmtRate(hoveredSample.downBps)}</span>
          <span style="color: var(--ok); font-weight: 600">↑ {fmtRate(hoveredSample.upBps)}</span>
        </div>
      {/if}

      <svg
        class="chart-svg"
        viewBox="0 0 {W} {H}"
        preserveAspectRatio="none"
        role="img"
        aria-label="Live throughput chart"
        onmousemove={handlePointerMove}
        onmouseleave={() => (hoverIdx = null)}
      >
        <defs>
          <linearGradient id="tk-down-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.32" />
            <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.01" />
          </linearGradient>
          <linearGradient id="tk-up-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--ok)" stop-opacity="0.22" />
            <stop offset="100%" stop-color="var(--ok)" stop-opacity="0.01" />
          </linearGradient>
        </defs>

        <!-- Horizontal gridlines & right-side scale labels -->
        {#each [0, 0.5, 1] as frac}
          {@const y = PAD_T + plotH * frac}
          {@const val = maxBps * (1 - frac)}
          <line
            x1={PAD_L}
            y1={y}
            x2={PAD_L + plotW}
            y2={y}
            stroke="var(--border)"
            stroke-dasharray={frac === 1 ? undefined : '3 4'}
            stroke-width="1"
          />
          <text
            x={PAD_L + plotW + 6}
            y={y + 3.5}
            font-family="var(--font-mono)"
            font-size="9.5"
            fill="var(--text-dim)"
          >
            {frac === 1 ? '0 B/s' : fmtRate(val)}
          </text>
        {/each}

        {#if downArea}
          <path d={downArea} fill="url(#tk-down-grad)" />
          <path d={downLine} fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" />
        {/if}

        {#if upArea}
          <path d={upArea} fill="url(#tk-up-grad)" />
          <path d={upLine} fill="none" stroke="var(--ok)" stroke-width="1.65" stroke-linecap="round" />
        {/if}

        <!-- Interactive hover crosshair & active points -->
        {#if hoveredDownPt && hoveredUpPt}
          <line
            x1={hoveredDownPt[0]}
            y1={PAD_T}
            x2={hoveredDownPt[0]}
            y2={PAD_T + plotH}
            stroke="var(--border-strong)"
            stroke-width="1"
            stroke-dasharray="2 2"
          />
          <circle cx={hoveredDownPt[0]} cy={hoveredDownPt[1]} r="4" fill="var(--accent)" stroke="var(--surface)" stroke-width="2" />
          <circle cx={hoveredUpPt[0]} cy={hoveredUpPt[1]} r="3.5" fill="var(--ok)" stroke="var(--surface)" stroke-width="2" />
        {/if}

        <!-- Time axis ticks -->
        <text x={PAD_L} y={H - 4} font-family="var(--font-mono)" font-size="9.5" fill="var(--text-dim)">
          {samples.length > 1 ? `-${Math.round((samples.length - 1) * 5)}s` : '-5s'}
        </text>
        <text
          x={PAD_L + plotW / 2}
          y={H - 4}
          text-anchor="middle"
          font-family="var(--font-mono)"
          font-size="9.5"
          fill="var(--text-dim)"
        >
          5s interval
        </text>
        <text x={PAD_L + plotW} y={H - 4} text-anchor="end" font-family="var(--font-mono)" font-size="9.5" fill="var(--text-dim)">
          now
        </text>
      </svg>
    </div>

    <div class="row-between hint tabular" style="padding-top: 6px; border-top: 1px solid var(--border)">
      <span>Peak ↓ <strong style="color: var(--text)">{fmtRate(peakDown)}</strong></span>
      <span>Window: {samples.length} sample{samples.length === 1 ? '' : 's'}</span>
    </div>
  {/if}
</div>
