# Frequently Asked Questions (FAQ)

### Why does tikray use two containers instead of one?
1. **Zero-downtime control updates:** Upgrading `tikray` (Web UI, API, reconciler) runs blue/green via the RouterOS watchdog while `tikray-runner` continues forwarding active LAN packets uninterrupted.
2. **Minimal data-plane attack surface:** `tikray-runner` is a `FROM scratch` image with no shell, no package manager, no RouterOS API credentials, and no public listening sockets.
3. **Independent lifecycles:** `xray-core` and Geo bundles live on `/data` and swap inside `tikray-runner` without rebuilding container images.

---

### Does tikray bundle `xray-core` binaries?
**No.** `tikray` is licensed under GPLv3, while `xray-core` is licensed under MPL-2.0 by Project X. `tikray` never embeds `xray-core` binaries in its git repository or container images; official releases are downloaded and cryptographically verified (`.dgst` SHA-256 or ECDSA P-256 signed `index.json`) at install/update time, or staged via the offline inbox.

---

### Does domestic traffic still use MikroTik FastTrack?
**Yes.** In `smart` mode, `tikray` synchronizes the domestic IPv4 address-list directly into RouterOS. Domestic and local LAN flows never cross the container bridge or touch `xray-core`, preserving native RouterOS forwarding speed and keeping router CPU usage low.

---

### What happens if I upgrade MikroTik RouterOS to `7.26` or newer?
Canonical stable/long-term RouterOS **`7.26+`** releases are accepted automatically on the modern `7.23+` adapter profile and surfaced with a non-blocking **`untested`** badge in `/v1/status` and the Web UI until verified in CHR CI. Pre-releases (`beta`, `rc`, `testing`, `development`), `.0` patches, v6/v8, and pre-`7.23.8` builds are refused to protect your router.

---

### What happens on an unexpected power cut?
- RouterOS starts saved firewall return-traffic guards before containers boot.
- All `tikray` state files are written atomically (`temp + fsync + rename`), and RouterOS policy checkpoints live in `/data/state/router-policy.json`.
- On boot, `tikray-watchdog` verifies both containers and `tikray` reconciles any missed state automatically.

---

### Why does tikray refuse `allowInsecure: true`?
Modern `xray-core` 26.x removed `allowInsecure` and refuses configs containing it, because disabling TLS certificate verification exposes tunnels to active MITM attacks. Instead, use **`pcs` (`pinnedPeerCertSha256`)** to pin the exact SHA-256 hash of a self-signed server certificate, or **`vcn` (`verifyPeerCertByName`)** to verify against a specific certificate hostname.

---

### Can I use multiple MikroTik LAN subnets or VLANs?
**Yes.** Add all managed LAN interfaces to the RouterOS interface list configured in `tikrayLanList` (default `LAN`). You can then assign policies globally (`default`), per VLAN subnet (`192.168.20.0/24`), or per individual device (`/32`).

---

### Does tikray work on 32-bit ARM routers (like hAP ac²)?
**No.** `tikray` v1.0 builds and tests **`arm64`** (hAP ax², hAP ax³, hAP ax lite, RB5009, L009, Chateau, CCR2004/2116/2216, ARM64 CRS/CHR) and **`amd64`** (x86_64 CHR). 32-bit ARM routers typically lack the RAM and storage needed to run `xray-core` + Geo databases reliably alongside RouterOS.

---

### How are my server UUIDs, passwords, and subscription URLs protected?
`tikray` enforces strict zero-secret redaction across the entire codebase (`internal/service/redact.go`, `internal/api/view.go`, `internal/api/secret.go`). Share links, server credentials (including case-insensitive UUIDs), subscription URLs, passwords, setup codes, API tokens, session IDs, CSRF tokens, backup passphrases, and RouterOS credentials are never returned by API views, CLI tables, logs, events, history files, or error messages.

---

### Can I migrate my setup to a different MikroTik router?
**Yes.** Export an encrypted backup via **Settings → Encrypted Backup** (or `tikray backup export --out backup.json`), install `tikray` on the new router, and restore the backup there. `tikray` automatically preserves the new router's managed bridge subnet during restore.

---

### How do I completely turn off tikray in an emergency?
Run `/system/script/run tikray-emergency-off` in the RouterOS terminal. It works even if both containers are stopped, immediately restores direct WAN internet for all devices (including kill-switched ones), and keeps your existing RouterOS firewall intact.
