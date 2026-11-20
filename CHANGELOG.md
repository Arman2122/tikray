# Changelog

All notable changes to **tikray** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-11-20

### Changed
- **`Arman2122/IR-Geo-DB` as the Built-In & Default `iran` Geo Publisher (`internal/artifacts`, `internal/service`, `cmd/tikray`, `web/`)**:
  - Switched the `iran` geo profile from `Chocolate4U/Iran-v2ray-rules` to [Arman2122/IR-Geo-DB](https://github.com/Arman2122/IR-Geo-DB) (rebuilt daily with RIPE-corrected Iranian IPv4 ranges, `geosite:ir`, `geoip:ir`, plus optional `geosite:ads`, `geosite:malware`, `geosite:phishing`, `geosite:cryptominers`, and `geoip:malware` categories).
  - Verifies `geoip.dat` and `geosite.dat` against the release's `SHA256SUMS` manifest and validates `vYYYY.MM.DD` release tags (e.g. `v2026.11.20`).
  - Made `iran` (`artifacts.DefaultGeoProfile`) the default geo profile for `GET /v1/geo`, `POST /v1/geo/update`, `tikray geo update latest` (when `--profile` is omitted), and the embedded Web UI (`Updates` view).

## [1.0.1] - 2026-11-20

### Added
- **Two-Line Fast Install Directly on MikroTik RouterOS v7 (Zero Go Required)**:
  - Every GitHub Release now publishes signed multi-arch container archives (`*.tar` + `*.tar.sig` + `publisher.pub`), pre-packaged chunk-verified installers for all supported RouterOS release lines (`install-7.25.1-{arm64,amd64}.rsc`, `install-7.24.6-{arm64,amd64}.rsc`, `install-7.23.8-{arm64,amd64}.rsc`), `uninstall.rsc`, and an auto-detecting `bootstrap.rsc` (`scripts/bootstrap.rsc.tmpl`).
  - Users can install directly from WinBox Terminal or RouterOS SSH by pasting two `/tool/fetch` + `/import` commands; `bootstrap.rsc` auto-detects architecture and RouterOS release line, checks prerequisites before downloading, stages archives onto `disk1`, and runs the 16 KiB SHA-512 verified installer.
- **Release Pipeline Hardening (`.github/workflows/release.yml`)**:
  - Always signs container archives (using `TIKRAY_RELEASE_COSIGN_KEY` when configured, or an ephemeral ECDSA P-256 keypair verified with `cosign verify-blob --offline` otherwise), packages all 6 RouterOS installers (`7.25.1`, `7.24.6`, `7.23.8` × `arm64`, `amd64`), renders tag-pinned `bootstrap.rsc`, and includes all artifacts in `SHA256SUMS`.

### Fixed
- **Documentation Container Tag**: Fixed `tikray setup-code` and `tikray admin reset` copy-paste examples across `README.md` and Wiki guides to match the actual RouterOS control container comment (`comment="tikray:tikray"`).
- **Image Archive & RouterOS CHR Acceptance Stability**:
  - Eliminated per-16 KiB chunk heap allocations in `internal/imagearchive/archive.go` (reusing a single buffer + SHA-512 hasher).
  - Switched `monitorForeignFlow` SSH reads to atomic `/ip/firewall/connection/print detail as-value` snapshots (immune to RouterOS 7.24.6 conntrack churn), tolerated trailing RouterOS console notices in `installOutput`, combined `readOwnerRules` into a single fresh SSH session to prevent login bursts, and widened QEMU TCG image staging/polling timeouts in CHR acceptance tests.

## [1.0.0] - 2026-11-19

First production open-source release of **tikray** for MikroTik RouterOS v7.

### Added
- **Future-Proof MikroTik RouterOS v7 Support**:
  - Lab-verified release lines: `7.25.1` (stable, `7.25.x`), `7.24.6` (long-term, `7.24.x`), and `7.23.8` (legacy long-term, `7.23.x`), plus forward-compatible acceptance of future canonical `7.26+` stable/long-term releases (`Profile.Verified() == false`, surfaced as a non-blocking `untested` badge in `Status.routeros` and Web UI) while still rejecting pre-releases (`beta`, `rc`, `testing`, `development`), `.0` patches, v6/v8, and pre-`7.23.8` builds.
  - Native POSIX ERE installer guards, live RouterOS version exposure in `/v1/status`, channel/feature detection (`SupportsVethIPPreserve`, `SupportsDynamicARPInspection`), and `xray-core` compatibility tested through **`v26.11.9`**.
- **Modern `xray-core` 26.x Share-Link Features (`internal/sharelink`)**:
  - Native support for `xhttp` `extra` JSON objects (XMUX, `downloadSettings`, `noGRPCHeader`, padding; 16 KiB cap, zero secret echo), post-quantum REALITY `pqv` (`mldsa65Verify`), and TLS ECH `ech` (`echConfigList`).
- **Per-Interface Wi-Fi, LAN Port, VLAN & Multi-WAN Steering (`internal/routeros`, `internal/store`, `internal/api`)**:
  - Per-interface routing policies (`PUT /v1/interfaces/{name}`, `DELETE /v1/interfaces/{name}`) for Wi-Fi SSIDs, dedicated Ethernet LAN ports, VLANs, and bridges with matching IPv6 leak guards and preserved FastTrack/L2 hardware switch offload.
  - Multi-WAN Internet-in uplink pinning for Xray outbound tunnels (`PUT /v1/network/wan`) via a dedicated `tikray-wan` FIB table (`check-gateway=ping`) with automatic failover to the primary active WAN.
  - Live RouterOS interface & WAN uplink discovery (`GET /v1/routeros/interfaces`) reading interface types, roles, bridge membership, subnets, traffic counters, and Wi-Fi SSIDs (never passphrases), paired with interactive RouterOS v7 setup recipes in the UI.
- **Embedded Svelte 5 Web UI (`web/`, `internal/ui/`)**:
  - Compiled into the `tikray` binary via `go:embed` (~86 KB gzipped, zero external fonts or CDNs, responsive Obsidian dark & light themes, strict CSP).
  - Full control-plane interface: First-run Setup & Login (with rate-limit countdown), Dashboard (4-column telemetry strip, KPI cards, interactive live 4-stage Data-Path Topology, real-time SVG Throughput chart with hover/touch scrubbing, Proxy-vs-Direct traffic split, warm HTTP 204 latency bars, Apply Now), `Ctrl+K` Command Palette, Servers & Subscriptions (v2rayN-style Visual Config & two-way JSON Editor with secret-preserving saves, warm HTTP 204 / TCP latency testing + auto-ping on connect, live share-link capability preview badges, bulk import, hot toggle, pin, refresh summaries), Network & Devices (Wi-Fi, Ports & WAN tab + RouterOS v7 CLI recipes, default & per-device policies, kill switch, RouterOS DHCP leases + Make Static), Routing & DNS (ordered rules, domestic bypass, DoH presets, probe URL), Updates (`xray-core` release picker dropdown + 4 independent lifecycle cards + offline inbox uploads), Live Events (auto-polling with `boot_id` restart detection), and Settings (encrypted backup export/restore, API tokens with one-time display, password rotation, bridge repair).
- **Passphrase-Encrypted Backup & Restore (`internal/backup`)**:
  - Portable `tikray-backup-v1` format using Argon2id (`19456 KiB, t=2, p=1`, bounded concurrency) + AES-256-GCM with format AAD.
  - `POST /v1/backup/export`, `POST /v1/backup/restore`, and `tikray backup export|restore` (passphrase via `TIKRAY_BACKUP_PASSPHRASE` or stdin; preserves managed router bridge subnet on restore).
- **Scoped Static DHCP Lease Conversion (`internal/routeros`)**:
  - `POST /v1/routeros/leases/static` and `tikray device make-static <ip>` convert a single bound dynamic lease on a managed LAN into a static RouterOS DHCP reservation with readback verification.
  - `GET /v1/routeros/leases` now reports `static: true` for static reservations.
- **Live Telemetry, Geo Inventory & Offline Inbox Uploads**:
  - `GET /v1/stats` and `tikray stats` expose allowlisted xray-core uptime, memory, goroutines, and per-tag uplink/downlink counters.
  - `GET /v1/geo` and `tikray geo status` report active geo slot, verified slots, prefix counts, and geo update history.
  - `POST /v1/inbox/core/{name}` and `POST /v1/inbox/geo/{profile}/{version}/{name}` provide symlink-safe, size-capped offline artifact uploads.
  - `Status.boot_id`, `X-Tikray-Boot-ID` header on `GET /v1/events`, `Status.version`, and `tikray version`.
- **Release & Upstream Automation**:
  - `.github/workflows/release.yml` for tagged multi-arch RouterOS container archives, SPDX SBOMs, Cosign signatures, and packaged installers.
  - `.github/workflows/xray-watch.yml` for scheduled upstream `XTLS/Xray-core` compatibility verification.
- **Complete Open-Source Documentation**:
  - Flagship `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/architecture.md`, `docs/api.md`, and GitHub issue/PR templates.

### Changed
- **MikroTik Memory Optimization & Hardening**: Added default `GOMEMLIMIT` bounds (`48MiB` for `tikray`, `24MiB` for `tikray-runner`, alongside `128MiB` for `xray-core`), HTTP/2 idle keepalive pings (`ReadIdleTimeout: 30s`, `PingTimeout: 10s`) on `internal/xray` h2c transport, and case-insensitive UUID credential redaction in `internal/service`.
- **CI**: Added Web UI type-check/build verification and `-race` test jobs in `.github/workflows/ci.yml`; updated CHR acceptance matrix in `.github/workflows/chr.yml` to RouterOS `7.25.1` and `7.24.6`.

### Foundation (Milestones M0–M3b)
- Two-container architecture (`tikray` + `tikray-runner`) with TUN data plane, trial/auto-rollback, hot outbound reloads (`xray api`), health observatory, subscription scheduler, admin auth/CSRF/tokens, pinned RouterOS native API-SSL reconciler, IPv6 leak guard, outage recovery, native watchdog, blue/green image updates, geo bundle transactions, `tikray-emergency-off`, and clean `keep`/`purge` uninstaller.
