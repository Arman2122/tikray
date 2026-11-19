# Performance & Hardware Tuning

`tikray` is engineered specifically for resource-constrained MikroTik ARM64 routers (down to 256–512 MB RAM) while scaling seamlessly up to multi-gigabit CCR2xxx appliances and x86_64 CHR VMs.

---

## 1. Hardware Sizing Guide

| Hardware Tier | Example MikroTik Models | RAM | Storage | Recommended Tuning |
|---|---|---|---|---|
| **Compact / Home** | hAP ax lite (w/ USB), L009 | 256–512 MB | USB 3.0 ext4 | Keep defaults (`48M + 24M + 128M`); keep subscriptions concise (< 200 servers) |
| **Mainstream Wi-Fi 6** | hAP ax², hAP ax³, Chateau 5G / LTE ax | 1 GB | USB 3.0 / internal ext4 | Ideal sweet spot; defaults run with huge headroom |
| **Power User / Prosumer** | RB5009UG+S+IN, RB5009UPr+S+IN | 1 GB | USB 3.0 ext4 | Consider raising `XRAY_GOMEMLIMIT=256MiB` for very high concurrency |
| **Enterprise & Virtual** | CCR2004, CCR2116, CCR2216, x86_64/ARM64 CHR | 4–16+ GB | NVMe / SSD | Raise `XRAY_GOMEMLIMIT=512MiB` if pushing multi-gigabit or thousands of concurrent sockets |

---

## 2. How tikray Maximizes Throughput on MikroTik

### Domestic & LAN FastTrack Offload
In `smart` mode (recommended), `tikray` syncs the domestic IPv4 address-list directly into RouterOS:
- Domestic ISP traffic and local LAN traffic **never cross the container bridge, never hit TUN, and never touch `xray-core`**.
- Those flows stay at native MikroTik kernel / FastTrack line rate with zero container CPU cost.

### Minimal Data-Plane Overhead
- `tikray-runner` is a **`FROM scratch`** container running only a static Go PID 1 supervisor + `xray-core` over native Linux TUN (`CAP_NET_ADMIN` + `/dev/net/tun`) — zero shell, zero Python/Node runtime, zero extra packet hops.
- Container memory budgets are cleanly isolated:
  - `tikray` control container: **`GOMEMLIMIT=48MiB`**
  - `tikray-runner` supervisor container: **`GOMEMLIMIT=24MiB`**
  - `xray-core` process: **`XRAY_GOMEMLIMIT=128MiB`** (explicitly decoupled from `tikray-runner`'s limit; `supervisor.go` strips the outer `GOMEMLIMIT` before spawning `xray-core` and leaves `GOGC` at default so `xray-core` avoids aggressive GC CPU spikes under heavy throughput).

### Transport Choices for Router CPUs
On ARM64 MikroTik CPUs (which include ARMv8 AES crypto extensions on modern models like hAP ax²/ax³/RB5009/CCR2xxx):
- **Fastest / lowest CPU:** `VLESS + REALITY + XTLS-Vision` (`flow=xtls-rprx-vision`, raw TCP) — eliminates double TLS encryption overhead inside the tunnel.
- **Best censorship resilience with strong performance:** `VLESS + REALITY + XHTTP` (`mode=auto` or `packet-up`, optionally tuned with `extra` XMUX).
- **Avoid heavy legacy transports:** Avoid unnecessary multi-layer WebSocket-over-TLS when REALITY/XHTTP is available, as extra framing increases per-packet CPU work on smaller routers.

---

## 3. Tuning Container Memory Limits

You can override memory budgets via RouterOS container env lists (`/container/envs`) without rebuilding images:

```routeros
# Example on RB5009 / CCR2004 (1 GB+ RAM): give xray-core more headroom
/container/envs/add name=tikray-runner key=XRAY_GOMEMLIMIT value=256MiB

# Example if managing very large subscriptions (500+ entries):
/container/envs/add name=tikray-ctl key=GOMEMLIMIT value=96MiB
```

Restart the modified container (or wait for the next image switch) to apply.

---

## 4. Storage Longevity & Flash Safety

- **Always use external USB 3.0 / NVMe ext4 storage** (`disk1` / `usb1`) for `/data` and `/container/config tmpdir`, especially on routers with small internal NAND flash.
- `tikray` is engineered to minimize disk writes during steady-state operation:
  - Healthy `tikray-watchdog` probes perform **zero** RouterOS state writes.
  - Config/state writes use atomic write-to-temp + `fsync` + `rename` only when desired state actually changes.
  - Live telemetry (`/v1/stats`) and the 200-item event ring buffer live purely in RAM.
