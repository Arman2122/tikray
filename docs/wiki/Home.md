# tikray Wiki

Welcome to the official **tikray** documentation hub — everything you need to deploy, tune, operate, and troubleshoot **xray-core** natively on **MikroTik RouterOS v7**.

> **Quick summary:** `tikray` pairs a hardened Go control plane (`tikray`, with an embedded 57 KB offline-first Web UI, HTTPS REST API, CLI, and native RouterOS reconciler) with a minimal `FROM scratch` data-plane supervisor (`tikray-runner`) that runs `xray-core` over TUN with deadline-backed trial rollbacks and zero-downtime hot server reloads.

---

## Start Here by Role

| If you are… | Read these guides |
|---|---|
| **Setting up a MikroTik router for the first time** | 1. [Installation Guide](Installation-Guide.md) → 2. [Protocols & Share Links](Protocols-and-Share-Links.md) → 3. [Traffic Steering & Policies](Traffic-Steering-and-Policies.md) |
| **Deploying behind censorship or air-gapped networks** | [Offline & Censored Networks](Offline-and-Censored-Networks.md) → [Protocols & Share Links](Protocols-and-Share-Links.md) |
| **Operating & upgrading production routers** | [Web UI & CLI Guide](Web-UI-and-CLI-Guide.md) → [Updates, Watchdog & Rollbacks](Updates-Watchdog-and-Rollbacks.md) → [Performance & Hardware Tuning](Performance-and-Hardware-Tuning.md) |
| **Recovering from a router or config issue** | [Troubleshooting & Emergency Recovery](Troubleshooting-and-Emergency-Recovery.md) → [FAQ](FAQ.md) |
| **Integrating automation or contributing code** | [Architecture Deep Dive](../architecture.md) · [HTTPS REST API v1](../api.md) · [Contributing Guide](../../CONTRIBUTING.md) |

---

## Complete Wiki Index

1. **[Installation Guide](Installation-Guide.md)** — Prerequisites, RouterOS `container` package, `device-mode`, ext4 storage, online installer, custom variables, and first-run setup.
2. **[Offline & Censored Networks](Offline-and-Censored-Networks.md)** — Air-gapped installs, signed `index.json` staging, browser Offline Inbox uploads, proxy fallback, and custom mirrors.
3. **[Protocols & Share Links](Protocols-and-Share-Links.md)** — VLESS, XTLS-Vision, Post-Quantum VLESS & REALITY (`pqv` / `mldsa65Verify`), XHTTP + `extra` JSON, TLS ECH (`ech`), certificate pinning (`pcs`/`vcn`), VMess, Trojan, SS-2022, raw JSON outbounds, and subscriptions.
4. **[Traffic Steering & Policies](Traffic-Steering-and-Policies.md)** — `direct` / `smart` / `full` modes, per-device & CIDR overrides, Kill Switch, IPv6 leak guard, RouterOS DHCP static lease conversion, domestic bypass, DNS, and existing NAT/FastTrack rules.
5. **[Web UI & CLI Guide](Web-UI-and-CLI-Guide.md)** — Complete tour of the embedded Svelte 5 UI (live charts, topology flow, `Ctrl+K` Command Palette, share-link inspector) plus every `tikray` CLI command and environment variable.
6. **[Updates, Watchdog & Rollbacks](Updates-Watchdog-and-Rollbacks.md)** — Four independent update lifecycles (`xray-core`, Geo, `tikray` blue/green, `tikray-runner`), hot reloads, native RouterOS watchdog, and encrypted backup/restore.
7. **[Performance & Hardware Tuning](Performance-and-Hardware-Tuning.md)** — Hardware tiers (hAP ax²/ax³, RB5009, L009, Chateau, CCR2xxx, CHR), `GOMEMLIMIT` memory budgets, FastTrack domestic offload, and flash longevity.
8. **[Troubleshooting & Emergency Recovery](Troubleshooting-and-Emergency-Recovery.md)** — `tikray-emergency-off`, admin password reset, bridge/NAT repair, `degraded` diagnostics, `untested` RouterOS `7.26+` notices, and `keep`/`purge` uninstall.
9. **[FAQ](FAQ.md)** — Answers to the most frequently asked operational, licensing, and security questions.

---

## Supported Baseline (v1.0.0)

- **MikroTik RouterOS:** `7.25.1` (`7.25.x` stable), `7.24.6` (`7.24.x` long-term), `7.23.8` (`7.23.x`), and forward-compatible `7.26+` canonical releases.
- **Architectures:** `arm64` and `amd64` (x86_64 CHR).
- **`xray-core`:** `v26.1.18` through `v26.11.9` (never bundled; downloaded and cryptographically verified at runtime or staged offline).
