# tikray Architecture

This document describes the runtime topology, reconciliation model, update lifecycles, and security boundaries of **tikray**. The authoritative design contract lives in [`docs/superpowers/specs/2026-10-24-tikray-design.md`](superpowers/specs/2026-10-24-tikray-design.md).

## 1. Two-Container Isolation

tikray splits control and packet forwarding into two containers sharing one `/data` mount over an isolated private `/29` bridge (`172.31.255.0/29` by default):

| Role | Address | Base Image | Responsibilities |
|---|---|---|---|
| **RouterOS Bridge** | `.1` | RouterOS v7 | Policy routing (`tikray` table), mangle/SRCNAT, IPv6 guard, DNS redirect, native API-SSL, container watchdog |
| **`tikray` (Control)** | `.2` | `busybox:1.37.0-musl` + static Go binary | Desired state store, config renderer, embedded Web UI, HTTPS API, CLI, subscription scheduler, health observatory, RouterOS reconciler |
| **`tikray-runner` (Data)** | `.3` | `FROM scratch` + static Go binary | PID 1 supervisor for `xray-core`, Linux TUN & container policy routing (`netlink`), deadline-backed trial/auto-rollback, local HTTP control API |

### Why two containers?

1. **Zero-downtime control upgrades** — `tikray` can be replaced blue/green by the RouterOS watchdog while `tikray-runner` continues forwarding LAN packets uninterrupted.
2. **Minimal data-plane attack surface** — `tikray-runner` has no shell, no package manager, no RouterOS API credentials, and no public listening sockets.
3. **Independent lifecycles** — `xray-core` binaries and `geo` bundles live on `/data` and swap inside `tikray-runner` without rebuilding container images.

## 2. Private Bridge & Return-Traffic Hardening

The dedicated bridge `tikray` uses `protocol-mode=none` (no STP delay on reboot), `arp=reply-only`, static ARP entries binding `.2` and `.3` to their container-side MACs, and disabled MAC learning / unknown-unicast flooding on both veth ports.

RouterOS forward firewall rules placed above permissive rules and FastTrack enforce:
- Return traffic leaving the runner with a source outside the private bridge may only reach enrolled LAN prefixes out the configured LAN interface list.
- All other destinations from the private bridge are dropped explicitly.

## 3. Traffic Steering & Reconciliation

`internal/routeros` communicates with RouterOS over a single certificate-pinned native API-SSL connection. Every read is projected (`=.proplist=...`) and scoped (`?...`); every mutation is bound to the session `Generation()` so a mid-flight reconnect invalidates stale row IDs.

1. **Pre-write Guard Staging (`Prepare`)** — Before a state edit tightens a device's policy or switches domestic geo ranges, tikray writes temporary hold rules and purges stale conntrack/FastTrack bindings so active flows cannot bypass the new policy or kill switch.
2. **Data-Plane Trial (`Apply` / Hot Reload)** —
   - If only `srv-*` outbounds changed and `TIKRAY_HOT` is enabled, `tikray` hot-swaps outbounds via `xray api` (`rmo`/`ado`), probes health, and calls runner `POST /v1/adopt` — zero connection drop.
   - Otherwise, `tikray` renders the version-gated xray JSON config (`internal/render`), asks `tikray-runner` to start a deadline-backed trial, verifies xray gRPC health + end-to-end SOCKS probe, and commits. If the probe fails or the deadline expires, `tikray-runner` reverts automatically.
3. **Post-Commit Reconciliation (`Reconcile`)** — Once the runner attests the committed selection, the RouterOS engine reconciles desired mangle, address-list, routing, NAT, DNS, and IPv6 guard rows, performs a final binding purge, verifies readback, releases hold guards, and persists its durable checkpoint (`state/router-policy.json`).
4. **Continuous Drift Protection** — Native `/listen` streams on managed menus plus a 30-second periodic sweep repair accidental external edits or post-outage drift automatically.
5. **Emergency Off** — `/system/script/run tikray-emergency-off` works natively on RouterOS even with both containers stopped, detaching steering/kill-switches cleanly and recording `tikray-emergency-state` until the control plane verifies re-arm.

## 4. Four Independent Update Lifecycles

| Component | Verification | Rollback Mechanism | Traffic Impact |
|---|---|---|---|
| **xray-core** | Upstream `.dgst` SHA-256 or ECDSA P-256 signed `index.json` (plus explicit `allow_unverified` for air-gapped inbox) | `tikray-runner` trial deadline auto-reverts to previous committed slot | Brief switch (~1–2 s) |
| **Geo Data** (`iran`, `v2fly`, `loyalsoldier`, `custom`) | Upstream SHA-256 digests + `O_NOFOLLOW` immutable slot verification | Journaled transaction rolls back both xray geo slot and RouterOS domestic IPv4 address-list | Seamless |
| **`tikray` Control Image** | `cosign verify-blob` + archive digest | RouterOS watchdog blue/green swap + health check revert | **Zero** |
| **`tikray-runner` Data Image** | `cosign verify-blob` + archive digest | RouterOS watchdog swap + gateway ping revert | Brief container restart |

## 5. Authentication, Cryptography & Secret Hygiene

- **Admin Auth (`internal/auth`)**: Argon2id (`19456 KiB, t=2, p=1`, bounded concurrency of 2), first-run 12-symbol Crockford base32 setup code in `state/setup.code` (`0600`), 32-byte random session IDs hashed with SHA-256, `Secure; HttpOnly; SameSite=Strict` cookies, HMAC-SHA256 `X-Tikray-CSRF` tokens, and IP/global rate limiting.
- **Encrypted Backups (`internal/backup`)**: `tikray-backup-v1` seals full `store.State` with Argon2id + AES-256-GCM (AAD=`tikray-backup-v1`), enforcing KDF parameter bounds on open so untrusted files cannot exhaust router RAM. Restoring on a managed router preserves the installed bridge subnet.
- **Embedded Web UI (`web/`, `internal/ui`)**: Svelte 5 + TypeScript compiled into `internal/ui/dist` and embedded via `go:embed`. Served only for browser `GET`/`HEAD` requests outside canonical `/v1/*` and `/healthz` with strict CSP, immutable hashed asset caching, and zero external requests.
- **Redaction (`internal/service/redact.go`)**: Every error, event, probe diagnostic, and API view strips share links, server credentials (including case-insensitive UUIDs), subscription URLs, tokens, passwords, and setup codes.
