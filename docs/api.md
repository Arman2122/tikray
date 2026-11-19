# tikray HTTPS REST API (v1)

`tikray serve` exposes a JSON HTTPS API (self-signed TLS certificate pinned by SHA-256 fingerprint) alongside the embedded Web UI.

## Authentication

All routes except `/healthz`, `GET /v1/auth/state`, `POST /v1/auth/setup`, and `POST /v1/auth/login` require authentication via one of:

1. **Browser Session Cookie** — `tikray_session` (`Secure; HttpOnly; SameSite=Strict`). Every non-`GET`/`HEAD` request using a cookie must also include `X-Tikray-CSRF: <token>` returned by setup, login, or `GET /v1/auth/session`.
2. **Root Bearer Token** — `Authorization: Bearer <token>` from `<data>/state/api.token` (used by local CLI commands).
3. **Named API Token** — `Authorization: Bearer tkr_<id>_<secret>` issued via `POST /v1/tokens`. Named tokens are forbidden (`403`) from password rotation, admin reset, encrypted backup export/restore, and offline inbox uploads.

## Concurrency & Security Headers

- Every authenticated response includes `ETag: "<revision>"`.
- State-mutating endpoints honour `If-Match: "<revision>"` and fail with `409 conflict` if the state has moved on.
- API responses carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
- Views never return secrets: server outbounds are projected to protocol/host/port only, subscription URLs are omitted, and all errors are redacted.

## Error Format

```json
{
  "error": "refused",
  "detail": "redacted human-readable explanation",
  "result": { "...optional artifacts.Result for apply/core/geo operations..." }
}
```

Common error codes: `bad_request` (400), `unauthorized` / `bad_credentials` / `bad_code` (401), `forbidden` / `csrf` / `bad_password` (403), `not_found` (404), `conflict` / `busy` / `already_claimed` / `setup_required` / `token_limit` / `image_pending` (409), `refused` / `bad_passphrase` (422), `rate_limited` (429 + `Retry-After`), `fetch_failed` (502), `runner_unavailable` / `unavailable` / `geo_pending` / `bootstrap_pending` (503).

---

## Endpoints

### Health & Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/healthz` | Public | Liveness probe returning `{"ok": true, "installation_id": "..."}` |
| `GET` | `/v1/auth/state` | Public | Returns `{"setup_required": bool, "signed_in": bool}` |
| `POST` | `/v1/auth/setup` | Public (rate-limited) | Claim admin with `{"code", "username", "password"}`; sets session cookie and returns `csrf_token` |
| `POST` | `/v1/auth/login` | Public (rate-limited) | Sign in with `{"username", "password"}`; sets session cookie and returns `csrf_token` |
| `GET` | `/v1/auth/session` | Session | Returns current `username`, `csrf_token`, and expiry |
| `POST` | `/v1/auth/logout` | Session | Ends session and clears cookie |
| `PUT` | `/v1/auth/password` | Session | Rotates admin password (`{"current", "new"}`) and revokes other sessions |
| `POST` | `/v1/auth/reset` | Root only | Resets admin and generates a new setup code |
| `GET` | `/v1/tokens` | Admin / Root | List named API token metadata (never secrets) |
| `POST` | `/v1/tokens` | Admin / Root | Create token `{"name", "expires_in"}`; returns secret once |
| `DELETE` | `/v1/tokens/{id}` | Admin / Root | Revoke a named API token |

### Status, Telemetry & Events

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/status` | Any | Revision, applied flag, `boot_id`, `version`, active core, RouterOS status, health observatory snapshot |
| `GET` | `/v1/stats` | Any | Live xray-core uptime, goroutines, heap memory, and allowlisted per-tag traffic counters |
| `GET` | `/v1/state` | Any | Full redacted configuration view (`servers`, `subscriptions`, `devices`, `default_policy`, `routing`, `dns`, `network`, `health`) |
| `GET` | `/v1/events?after=N` | Any | Redacted event ring buffer (up to 200 items); response includes `X-Tikray-Boot-ID` header for restart detection |
| `POST` | `/v1/apply` | Any | Force immediate config render & apply (hot reload or trial) |

### Servers & Subscriptions

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/servers` | Any | List public server summaries |
| `GET` | `/v1/servers/{id}/config` | Session / Root | Credential-sanitized server outbound configuration for visual & JSON editing (secrets replaced with `__tikray_saved__`) |
| `POST` | `/v1/servers` | Any | Add server via `{"link", "name"}` or `{"name", "outbound"}` |
| `POST` | `/v1/servers/ping` | Any | Run bounded concurrent TCP + warm HTTP 204 latency tests across all enabled servers |
| `POST` | `/v1/servers/{id}/ping` | Any | Measure on-demand TCP 1-RTT and warm HTTP 204 latency for one server |
| `PATCH` | `/v1/servers/{id}` | Any | Rename, enable/disable, or replace link/outbound |
| `DELETE` | `/v1/servers/{id}` | Any | Delete server (clears pin / rules referencing it) |
| `GET` | `/v1/subscriptions` | Any | List subscriptions (URLs hidden) |
| `POST` | `/v1/subscriptions` | Any | Add subscription `{"name", "url", "interval"}` |
| `PATCH` | `/v1/subscriptions/{id}` | Any | Update name, URL, disabled flag, or refresh interval |
| `DELETE` | `/v1/subscriptions/{id}` | Any | Remove subscription and its imported servers |
| `POST` | `/v1/subscriptions/{id}/refresh` | Any | Trigger immediate fetch & merge; returns added/updated/removed/kept/skipped summary |

### Devices, Policy, Routing, DNS & RouterOS

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/devices` | Any | List configured device/CIDR policy overrides |
| `PUT` | `/v1/devices/{address}` | Any | Add or replace policy for IP/CIDR (`address` URL-encoded when containing `/`) |
| `DELETE` | `/v1/devices/{address}` | Any | Remove device/CIDR override |
| `GET` | `/v1/routeros/leases` | Any | Read active bound LAN DHCP leases (`address`, `mac`, `name`, `static`) |
| `POST` | `/v1/routeros/leases/static` | Any | Convert a bound dynamic LAN DHCP lease to static (`{"address": "192.168.88.25"}`) |
| `GET` | `/v1/routeros/interfaces` | Any | Discover live MikroTik Wi-Fi radios/SSIDs, Ethernet LAN ports, bridges, VLANs, subnets, and Internet-in WAN uplinks |
| `PUT` | `/v1/interfaces/{name}` | Any | Set per-interface steering policy (`{"name", "policy": {"mode", "kill_switch"}}`) for Wi-Fi, LAN port, VLAN, or bridge |
| `DELETE` | `/v1/interfaces/{name}` | Any | Remove per-interface steering override (reverts interface to default LAN policy) |
| `PUT` | `/v1/network/wan` | Any | Pin or clear (`""` = Auto) the RouterOS WAN Internet-in uplink used for Xray outbound tunnels (`{"wan_interface": "pppoe-out1"}`) |
| `PUT` | `/v1/policy` | Any | Set default LAN policy `{"mode": "direct"|"smart"|"full", "kill_switch": bool}` |
| `PUT` | `/v1/routing` | Any | Replace pinned server, custom rules, domestic extras, and block list |
| `PUT` | `/v1/dns` | Any | Replace `remote` (DoH/IPv4) and optional `domestic` (IPv4) resolvers |
| `GET` | `/v1/health` | Any | Get connectivity probe configuration |
| `PUT` | `/v1/health` | Any | Update connectivity probe URL `{"probe_url": "https://..."}` |
| `PUT` | `/v1/network` | Any | Atomic bridge/overlap repair when `routeros.degraded == "bridge_repair"` |

### Updates & Offline Inbox

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/core` | Any | Active xray-core version, installed slots, and update history |
| `GET` | `/v1/core/releases` | Any | Cached recent compatible xray-core releases (with offline fallback to tested + installed slots) |
| `POST` | `/v1/core/update` | Any | Verify, trial, and commit xray-core (`{"version": "latest"|"26.11.9", "allow_unverified": bool}`) |
| `POST` | `/v1/core/rollback` | Any | Roll back xray-core to previous committed slot |
| `GET` | `/v1/geo` | Any | Active geo slot, profile, verified slots with domestic prefix counts, and geo history |
| `POST` | `/v1/geo/update` | Any | Verify, trial, and commit geo bundle (`{"profile", "version"}`) |
| `POST` | `/v1/geo/rollback` | Any | Roll back geo bundle and RouterOS domestic ranges |
| `GET` | `/v1/images/{component}` | Any | Status of `tikray` or `runner` container image |
| `POST` | `/v1/images/{component}/update` | Any | Queue verified container image update (`{"version"}`) via RouterOS watchdog |
| `POST` | `/v1/images/{component}/rollback` | Any | Queue rollback to previous container image archive |
| `POST` | `/v1/inbox/core/{name}` | Session / Root | Stream offline Xray zip (`Xray-linux-arm64-v8a.zip` or `Xray-linux-64.zip`, max 64 MiB) |
| `POST` | `/v1/inbox/geo/{profile}/{version}/{name}` | Session / Root | Stream offline geo asset (`geoip.dat`, `geosite.dat`, `dlc.dat`, or `domestic-v4.txt`) |

### Encrypted Backup & Restore

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/backup/export` | Session / Root | Encrypt full state with `{"passphrase"}` (10–256 bytes); returns `tikray-backup-v1` bundle |
| `POST` | `/v1/backup/restore` | Session / Root | Decrypt and atomically restore `{"passphrase", "bundle"}` (honours `If-Match`; preserves managed bridge subnet) |
