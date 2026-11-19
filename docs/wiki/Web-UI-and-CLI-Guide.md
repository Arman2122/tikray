# Web UI & CLI Guide

Every management task in `tikray` works consistently across all three surfaces: the **Embedded Web UI**, the **`tikray` CLI**, and the **[HTTPS REST API v1](../api.md)**.

---

## 1. Embedded Web UI Tour

Access the Web UI at `https://<router-ip>` (printed at installation). It is compiled directly into the `tikray` binary (~57 KB gzipped), enforces strict CSP + `SameSite=Strict` + HMAC CSRF protection, and supports Dark & Light themes.

### Keyboard Shortcuts & Command Palette
- Press **`Ctrl+K`** (Windows/Linux) or **`⌘K`** (macOS) from anywhere to open the **Command Palette**:
  - Jump immediately to any page (`Dashboard`, `Servers`, `Devices`, `Routing`, `Updates`, `Events`, `Settings`).
  - Run quick actions (`Apply Config Now`, `Toggle Dark/Light Theme`, `Refresh All Subscriptions`).
  - Search and pin any enabled server directly without leaving your current screen.
- Press **`Escape`** to close any modal or the Command Palette.

### Page-by-Page Overview

| Page | Key Features |
|---|---|
| **Dashboard** | Status hero, **Interactive 4-Stage Topology Flow** (`LAN → RouterOS v7 → xray-core → Active Exit` with live RouterOS version and `untested` badge if on `7.26+`), **Live SVG Download/Upload Throughput Chart**, **Proxy-vs-Direct Traffic Split Bar**, server RTT latency bars, and **Apply Now**. |
| **Servers & Subs** | Add single/bulk share links with real-time **Client-Side Share-Link Inspector** (capability badges without echoing credentials), Raw JSON outbound editor, hot enable/disable, pin server, and scheduled subscription management with refresh diff summaries. |
| **Devices & Leases** | Visual Default Policy selector (`Direct` / `Smart` / `Full` + Kill Switch), per-device & CIDR override table, and live **RouterOS DHCP Leases** table with one-click **Make Static**. |
| **Routing & DNS** | Pinned server selector, ordered domain/IP custom rules, domestic bypass extras, block list, DoH presets, domestic DNS, and connectivity probe URL. |
| **Updates & Inbox** | Four independent lifecycle cards (**xray-core**, **Geo Data**, **`tikray` Control Image**, **`tikray-runner` Data Image**) with one-click Update & Rollback, plus browser **Offline Inbox Uploads** for air-gapped `.zip` and `.dat` staging. |
| **Live Events** | Auto-polling redacted control-plane audit stream (ring buffer up to 200 events) with `boot_id` restart detection. |
| **Settings & Backup** | RouterOS live version & bridge repair (when needed), **Encrypted Backup Export & Restore** (`tikray-backup-v1`), **Named API Tokens** (one-time display + revocation), and Admin Password rotation. |

---

## 2. Complete `tikray` CLI Reference

Run `tikray` directly inside the control container (`/container/shell [find comment="tikray:ctl"] cmd="tikray ..."`) or remotely from any Linux/macOS/WSL workstation.

### Remote CLI Setup (Certificate-Pinned)
Create a named API token in **Settings → API Tokens** (or via `tikray token create ci-monitor --expires 720h`), then export:

```sh
export TIKRAY_API="https://192.168.88.1:443"
export TIKRAY_API_TOKEN="tkr_<id>_<secret>"
export TIKRAY_API_FINGERPRINT="<sha256-hex-fingerprint-from-installer>"

tikray status
tikray stats --json
```

### All CLI Commands

| Category | Command | Description |
|---|---|---|
| **Service** | `tikray serve` | Run the control-plane daemon (`TIKRAY_LISTEN`, default `:443`) |
| | `tikray version` | Print `tikray` build version |
| **Observability** | `tikray status [--json]` | Revision, applied flag, active core, RouterOS status & server health |
| | `tikray stats [--json]` | Live `xray-core` uptime, heap memory, goroutines & per-tag traffic |
| | `tikray events [--after N]` | Print redacted control-plane event history |
| **Servers** | `tikray server add <link> \| --json FILE [--name N]` | Add server from share link or raw outbound JSON |
| | `tikray server list [--json]` | List public server summaries (zero credentials) |
| | `tikray server enable\|disable\|rm <id>` | Enable, disable, or delete server (hot-reloads when possible) |
| **Subscriptions** | `tikray sub add <url> [--name N] [--interval 24h]` | Add scheduled subscription feed |
| | `tikray sub list [--json]` | List subscriptions (URLs hidden) |
| | `tikray sub refresh\|rm <id>` | Fetch immediately or delete subscription + its servers |
| **Devices & Policy** | `tikray policy default <direct\|smart\|full> [--kill-switch]` | Set default policy for unlisted LAN clients |
| | `tikray device set <ip\|cidr> <direct\|smart\|full> [--kill-switch] [--name N]` | Add or update per-device/subnet override |
| | `tikray device rm <ip\|cidr>` | Remove device override |
| | `tikray device list [--json]` | List configured overrides |
| | `tikray device make-static <ip>` | Convert bound dynamic RouterOS DHCP lease to static |
| **Apply & Config** | `tikray apply` | Render & apply config (hot reload or deadline-backed trial) |
| | `tikray config render [--core VER]` | Print rendered `xray-core` JSON config (read-only) |
| **Updates** | `tikray core update <ver\|latest> [--config FILE] [--allow-unverified]` | Verify, trial & commit `xray-core` release |
| | `tikray core rollback` | Revert to previous committed `xray-core` slot |
| | `tikray core list [--json]` / `tikray core status` | Inspect installed core slots or raw runner status |
| | `tikray geo status [--json]` | Show active geo slot, domestic prefix count & history |
| | `tikray geo update <ver\|latest> [--profile NAME]` | Verify, trial & commit Geo bundle + RouterOS domestic CIDRs |
| | `tikray geo rollback` | Roll back Geo bundle and domestic routes |
| | `tikray image status\|update\|rollback <tikray\|runner> [ver]` | Manage blue/green control & runner container image switches |
| **Backups** | `tikray backup export --out FILE` | Export Argon2id + AES-256-GCM encrypted backup |
| | `tikray backup restore --in FILE` | Decrypt & atomically restore state (passphrase via `TIKRAY_BACKUP_PASSPHRASE` or stdin) |
| **Auth & Tokens** | `tikray setup-code` | Print one-time first-run setup code (`state/setup.code`) |
| | `tikray admin reset` | Reset admin password/sessions and generate a new setup code |
| | `tikray token create <name> [--expires 720h]` | Create named API token (printed once) |
| | `tikray token list [--json]` / `tikray token rm <id>` | List or revoke named API tokens |

---

## 3. Environment Variables

| Variable | Default | Used By | Purpose |
|---|---|---|---|
| `TIKRAY_DATA` | `/data` | `tikray`, `tikray-runner` | Persistent volume root |
| `TIKRAY_LISTEN` | `:443` | `tikray serve` | HTTPS listen address |
| `TIKRAY_HOT` | `on` | `tikray` | Set `0`/`false`/`off` to force full trial instead of hot outbound reload |
| `GOMEMLIMIT` | `48MiB` (`tikray`), `24MiB` (`runner`) | Containers | Go runtime soft memory cap |
| `XRAY_GOMEMLIMIT` | `128MiB` | `tikray-runner` | Dedicated Go memory limit passed to `xray-core` |
| `TIKRAY_BACKUP_PASSPHRASE` | *(prompt/stdin)* | `tikray backup` | Non-interactive backup passphrase (10–256 bytes) |
| `TIKRAY_API` / `TIKRAY_API_TOKEN` / `TIKRAY_API_FINGERPRINT` | Local `/data/state` | Remote CLI | Certificate-pinned remote daemon connection |
| `TIKRAY_MIRRORS` / `TIKRAY_INDEX_URLS` / `TIKRAY_INDEX_PUBKEY_FILE` | Upstream GitHub | `tikray` | Custom mirrors & ECDSA P-256 signed index overrides |
