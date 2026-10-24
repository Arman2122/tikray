# tikray: xray-core on MikroTik RouterOS (design spec)

- **Status:** Draft for review
- **Date:** 2026-10-24
- **Scope:** v1.0

## 1. Summary

tikray makes xray-core a first-class, easy-to-install, safe-to-update client on
MikroTik RouterOS v7. A user pastes one command into the RouterOS terminal, opens
a web UI, adds servers (share links, subscriptions or raw JSON), picks which
devices use the proxy, and gets split routing, multi-server failover and an
optional kill switch.

RouterOS only installs MikroTik-signed packages, so tikray runs in **RouterOS
containers**. It is built around one rule: **xray-core, geo data and tikray
each have their own lifecycle.** Users can move to a new xray release the day
XTLS publishes it, without waiting for a tikray release, and updating tikray
never interrupts traffic.

## 2. Brief

| Topic | Decision |
|---|---|
| Audience | Open-source community, including non-experts |
| Role | xray **client** only: LAN traffic goes out through remote xray servers |
| Hardware (v1) | ARM64 RouterOS devices (hAP ax², hAP ax³, RB5009, CCR2004/2116, Chateau ax, ...) |
| RouterOS | Current **stable** and **long-term** v7 channels, both tested in CI |
| Networks | Must work on open **and** filtered networks (GitHub and registries may be blocked or slow) |
| Management | Web UI (English) + REST API + CLI |
| v1 traffic features | Split routing, per-device policy, multi-server failover, kill switch option |
| IPv6 (v1) | Leak guard only; full IPv6 proxying in v1.1 |
| Control-plane language | Go (see Appendix A for the measured Go vs Rust comparison) |
| License | GPL-3.0 |
| Container topology | Two containers: control plane + data plane |
| Traffic steering | Hybrid: RouterOS decides by IP, xray decides by domain |

### Goals

1. Install on a supported router with one pasted command and a guided web UI.
2. Update xray-core, geo data and tikray **independently**, with verification and
   automatic rollback.
3. Updates work with no direct internet access to GitHub or registries.
4. Domestic and bypassed traffic stays on RouterOS's fast path and never enters xray.
5. No silent leaks: kill switch, DNS handling and an IPv6 leak guard.
6. Never break or reorder the user's own RouterOS configuration.

### Non-goals (v1)

- xray **server** (inbound) mode on the router.
- ARM32, MIPS (no container support) and other non-ARM64 hardware. amd64 images
  exist only for CHR-based testing.
- Managing a fleet of routers centrally.
- Full IPv6 proxying (planned for v1.1).
- UI languages other than English.
- A native RouterOS `.npk` package (not possible for third parties).

## 3. Architecture

### 3.1 Independently released pieces

| # | Piece | Contents | Released by / cadence | Version scheme |
|---|---|---|---|---|
| 1 | `tikray` image | Control plane: Go binary with embedded web UI, REST API, CLI | tikray project, per release | `vX.Y.Z` |
| 2 | `tikray-runner` image | Data-plane runner binary (~2 MB, `scratch` base) | tikray project, rarely | `runner-vX.Y.Z` |
| 3 | xray-core binary | Official XTLS release, verified, stored in version slots | Upstream, user decides when | upstream version |
| 4 | Geo bundle | `geoip.dat` / `geosite.dat` for xray, plus domestic IPv4 ranges for RouterOS address lists | Rule-list publishers, daily/weekly | publisher tag or date |
| 5 | `install.rsc` / `uninstall.rsc` | RouterOS bootstrap and removal scripts | With each `tikray` release | same as `tikray` |

No image ever contains an xray binary or geo data.

### 3.2 Topology

```
RouterOS v7 (ARM64)
                                       bridge "tikray" (default 172.31.255.0/29)
  LAN ──► mangle / routing ──────────────────────────────┐   router = .1
                                                          ▼
  ┌──────────────────────────────────────┐   ┌──────────────────────────────────┐
  │ tikray  (control plane, .2)          │   │ tikray-runner  (data plane, .3)  │
  │  web UI · REST · CLI                 │   │  runner (PID 1)                  │
  │  store · render · artifacts · health │──►│   └─ xray (from /data/cores/...) │
  │  routeros reconciler (API-SSL)       │   │      TUN inbound, DNS, SOCKS     │
  └──────────────────────────────────────┘   └──────────────────────────────────┘
            │ RouterOS API (api-ssl)                    ▲ control API (token)
            ▼                                           │ gRPC (stats, observatory)
        RouterOS  ◄─────── watchdog scheduler script ───┘
```

### 3.3 `tikray-runner` (data plane)

The runner does only what is needed to carry traffic safely:

- **Network setup** inside its namespace via netlink (no iproute2 needed):
  enables forwarding and adds a policy route that sends packets arriving on `eth0`
  into xray's TUN interface. xray's own outbound traffic leaves through `eth0`
  using the main table.
- **Process supervision:** starts xray from the version named in
  `/data/run/active.json` and restarts it if it crashes.
- **Control API**, listening only on the bridge and protected by a token
  (`/data/run/runner.token`): `status`, `reload`, `restart`, `trial`, `commit`,
  and `xray-api` (runs `xray api <cmd>` with the active core binary, so JSON →
  protobuf conversion always matches the running version).
- **Trial protocol (A/B slots):**
  1. tikray writes `/data/run/candidate.json` (core version, geo version, config
     file, deadline) and calls `trial`.
  2. The runner runs `xray run -test` with the candidate. On failure it rejects
     the candidate without switching.
  3. Otherwise it stops the active xray and starts the candidate. If the candidate
     exits within 10 s, the runner reverts to `active.json`.
  4. If tikray does not call `commit` before the deadline (default 120 s), the
     runner reverts.
  5. On `commit`, `candidate.json` atomically replaces `active.json`.
  6. On boot, the runner always starts from `active.json`, never from a candidate.

  This means a crash or reboot at any point during an update cannot leave xray broken.
- Sets `GOMEMLIMIT` for xray (configurable) to cap memory growth.

### 3.4 `tikray` (control plane)

Go packages under `internal/`:

| Package | Responsibility |
|---|---|
| `store` | Desired state (servers, subscriptions, policies, devices, settings) in a versioned state file with atomic writes (see §6.4) |
| `render` | Desired state → xray JSON config; holds a feature/version table for xray |
| `routeros` | RouterOS API client (api-ssl, `/listen`), declarative reconciler, RouterOS version adapters |
| `artifacts` | Shared fetch → verify → slot → trial → commit/rollback pipeline for cores and geo bundles; self-update orchestration |
| `xray` | gRPC client for read-only calls (stats, observatory, balancer info) using vendored protos; mutations go through the runner's `xray-api` |
| `health` | Probes through the runner's SOCKS port, xray/runner liveness, outage detection |
| `sharelink` | Parses `vless://`, `vmess://`, `trojan://`, `ss://` into xray outbound JSON |
| `subscription` | Fetches subscriptions (through the fetch chain), decodes base64/plain lists, refreshes on a schedule |
| `api` | REST API with authentication; used by the UI and the CLI |
| `cli` | `tikray` CLI subcommands (remote via REST, or inside the container) |
| `ui` | Embedded static web UI (Svelte + Vite, built at release time) |

Servers can be added by share link, subscription, or **raw outbound JSON**. Raw
JSON lets power users run any protocol or transport xray supports, including
ones newer than tikray's share-link parsers.

**How tikray talks to xray:**
- **Config:** JSON, xray's stable public format. tikray never compiles xray
  code in, so it stays decoupled from any one xray version.
- **Hot changes** (adding/removing servers, rule edits): `xray api ado/rmo/adrules/rmrules`
  through the runner, using the running binary. Each hot change is also written
  to the rendered config so a restart gives the same result. If a hot change
  fails, tikray falls back to a full trial restart.
- **Monitoring:** gRPC (StatsService, ObservatoryService, balancer info).

### 3.5 Storage layout

One directory on the router's disk (USB or NVMe on 128 MB-flash models),
roughly 150 MB:

```
/data/
  state/                 tikray only: state.v<N>.json, TLS cert, secrets (0600)
  cores/<ver>/           xray binary + meta.json (source, sha256, installed-at)
  geo/<ver>/             geoip.dat, geosite.dat, domestic-v4.txt, meta.json
  run/                   active.json, candidate.json, config/<hash>.json, runner.token
  images/                tikray-<ver>.tar, tikray-runner-<ver>.tar (current + previous, for rollback)
  inbox/                 manual uploads (cores, geo bundles, images)
```

Mounts: `tikray` gets `/data` read-write. `tikray-runner` gets `/data/cores` and
`/data/geo` read-only and `/data/run` read-write.

### 3.6 Networking

- One bridge `tikray`, default subnet `172.31.255.0/29` (configurable at install
  time to avoid clashing with the LAN): router `.1`, `tikray` `.2`, runner `.3`.
- NAT masquerade for the container subnet out to the WAN.
- The firewall allows LAN → `tikray` web UI only. The runner's SOCKS, DNS and
  control ports are reachable only from `tikray` and the router. WAN can't reach
  anything on the bridge.

## 4. Lifecycles and updates

### 4.1 Pipeline (cores, geo bundles, tikray itself)

```
check → fetch (fallback chain) → verify → install into new slot
      → trial → health check → commit   (or automatic rollback)
```

### 4.2 Fetch fallback chain

Each source is tried in order until one returns a file that passes verification:

1. **Direct** from upstream (GitHub releases, container registry).
2. **Through the proxy**, using the runner's local SOCKS inbound (only when xray is healthy).
3. **User-configured mirrors** (URL templates with `{version}`, `{arch}`, `{file}`).
4. **Manual upload** via the web UI or `/data/inbox`. Works fully offline.

### 4.3 Verification

- **xray-core:** SHA-256 from upstream's `.dgst` file for that release. The
  `.dgst` is always fetched from upstream (direct or through the proxy), even when
  the binary came from a mirror.
- If upstream can't be reached at all, tikray checks the hash against the
  **signed hash index** that tikray CI publishes for each XTLS release (§8.3).
  The index only verifies binaries, it never delivers them, so users never wait
  for tikray when upstream is reachable.
- **Geo bundles:** the publisher's checksum files. Sources are selectable
  profiles (v2fly, Loyalsoldier, Iran-focused lists, custom URL).
- **tikray images:** cosign signature check before installation.
- **Manual uploads** with no known hash show an "unverified" warning and need an
  explicit confirmation.

### 4.4 Slots and retention

The current and previous versions of each piece are kept by default (the count is
configurable). Older slots are removed automatically after a successful commit.

### 4.5 xray-core update

1. Fetch and verify the selected version into `/data/cores/<ver>/`.
2. Render the config for that version (§4.9).
3. Runner trial (§3.3).
4. Health check: real traffic through the proxy (SOCKS probe to a configurable
   URL), plus gRPC responding.
5. Commit, or let the runner revert. The UI shows the result and keeps history.

A manual **Roll back** button switches to the previous slot through the same trial flow.

### 4.6 Geo bundle update

1. Fetch and verify into `/data/geo/<ver>/`.
2. Runner trial with the new `.dat` files.
3. Sync the RouterOS `tikray-domestic` address list **by diff** (add and remove only
   changed ranges) to keep it fast and limit flash writes.
4. Commit or roll back. On rollback the address list is re-synced to the previous bundle.

### 4.7 tikray self-update (blue/green)

1. Fetch the new image as a file (registry or the fetch chain) into
   `/data/images/`, then verify its signature.
2. The new version writes migrated state to a **new** file `state.v<N+1>.json` and
   leaves `state.v<N>.json` untouched (§6.4).
3. Write an update marker and replace the `tikray` container with the new image
   (same veth, mounts and env). Traffic is unaffected because the runner keeps running.
4. The **RouterOS watchdog** (§6.3) checks tikray's `/healthz`. If the new version
   is not healthy within the window (default 5 min), the watchdog restores the
   previous image file. The previous version automatically reads the state file
   version it understands, so it comes back as it was before the update.
   Settings changed after the update are lost on rollback, which the UI says
   before updating.

### 4.8 tikray-runner update

The runner is the data plane, so replacing its container interrupts proxied
traffic for a few seconds. tikray says so in the UI and offers to schedule it.

1. Fetch and verify the runner image file into `/data/images/`.
2. Write an update marker and replace the runner container (same veth and mounts).
   It starts xray from `active.json` as usual.
3. tikray health-checks traffic through the new runner. If it fails within the
   window, the watchdog (§6.3) restores the previous runner image.

Runner updates are rare because the runner holds no xray or geo code.

### 4.9 xray compatibility

- `render` keeps a table of xray features and the minimum version each needs,
  for example the TUN inbound (≥ 26.1.18, to be confirmed in M0).
- **Tested range** is maintained by CI (§8.2). Newer, untested xray versions are
  allowed and labelled "untested"; the trial and `xray run -test` catch real breakage.
- Versions too old for features the current config uses are refused with an
  explanation.

### 4.10 Update policy

Per piece: `manual`, `notify`, or `auto` (with a time window).

| Piece | Default |
|---|---|
| xray-core | notify |
| Geo bundle | auto, daily |
| tikray | notify |
| tikray-runner | notify (brief traffic interruption, see §4.8) |

## 5. Traffic, DNS and failure handling

### 5.1 Device policies

Devices are identified by IPv4 address. tikray shows names from DHCP leases and
can create static leases. MAC addresses from leases are used for the IPv6 leak
guard.

| Policy | Behavior |
|---|---|
| `direct` | Never touches xray |
| `smart` | Domestic and local traffic direct, everything else through the proxy |
| `full` | Everything except local/LAN traffic through the proxy |

Each `smart` or `full` policy can turn on the **kill switch**. When it's on and
the proxy is unavailable, proxied traffic is blocked instead of going direct.
Direct and domestic traffic keep working. A default policy covers devices not
listed explicitly.

### 5.2 RouterOS side (owned by the reconciler, tagged `tikray:`)

- **Address lists:**
  - `tikray-local`: private, reserved and LAN ranges, plus the container subnet.
  - `tikray-domestic`: domestic IPv4 ranges from the active geo bundle (diff-synced).
  - `tikray-src-<policy>-<open|closed>`: source addresses per policy.
- **Mangle** (in tikray's own chains, reached by one jump rule):
  - `smart` sources, destination not in `tikray-local` or `tikray-domestic` → mark
    connection, mark routing.
  - `full` sources, destination not in `tikray-local` → mark connection, mark routing.
  - Routing mark `tikray-open` or `tikray-closed` depending on the kill switch.
  - MSS clamp on marked connections for the tunnel MTU.
- **FastTrack:** one rule "accept tikray-marked connections", placed directly
  before the user's FastTrack rule. This is the only rule tikray places in a user chain.
- **Routing tables:**
  - `tikray-open`: default via the runner (`check-gateway=ping`, distance 1),
    fallback via the main WAN gateway (distance 2).
  - `tikray-closed`: default via the runner (`check-gateway=ping`, distance 1),
    fallback blackhole (distance 2).
- **No source NAT** into the container: xray sees each device's real IP.

### 5.3 Inside xray

- **TUN inbound** with sniffing (`tls`, `http`, `quic`) and `routeOnly: true`:
  the domain is used for routing, but the original destination IP is kept.
- **Rule order:**
  1. Block list (optional, e.g. ads).
  2. Sources in `full` policies → their balancer (skips domestic rules).
  3. Domestic domains (geosite) → `direct`.
  4. Domestic IPs (geoip) → `direct`, as a safety net.
  5. User custom rules (domain/IP → direct/proxy/block/specific server).
  6. Sources with kill switch → `proxy-closed`; everyone else → `proxy-open`.
- **Balancers:** `proxy-open` (fallback `direct`) and `proxy-closed` (fallback
  `block`) share the same server set. Health comes from xray's observatory
  (burst observatory). The default strategy is lowest latency, and the user can
  pin a server.
- **Outbounds:** one per server (rendered from share links, subscriptions or raw
  JSON), plus `direct` (freedom) and `block` (blackhole).

### 5.4 DNS

- Devices with the `direct` policy keep using RouterOS DNS as before, unchanged.
- For `smart` and `full` devices, the reconciler dst-NATs TCP/UDP 53 to the
  runner's DNS endpoint (xray DNS):
  - Domestic domains → domestic resolver (default: the router itself, so its
    normal upstream is used), direct.
  - Everything else → DoH through the proxy.
  - `queryStrategy: UseIPv4` for these devices while the IPv6 leak guard is active.
- Browsers that use their own DoH still route correctly, because routing uses
  sniffing, not DNS.
- xray's DoH upstream uses the `proxy-open` balancer. During a full outage, DNS
  for kill-switch devices may therefore resolve over direct DoH. That connection is
  encrypted, so query contents aren't exposed, and those devices' traffic stays
  blocked. The alternative, failing all non-domestic DNS for open-policy devices
  during an outage, would break the direct fallback they rely on.

### 5.5 IPv6 leak guard (v1)

- IPv6 forwarding from proxied devices (matched by MAC from DHCP leases, or by
  interface for subnet policies) is **rejected**, not dropped, so apps fall back
  to IPv4 immediately.
- xray DNS returns only A records to these devices.
- Full IPv6 proxying is planned for v1.1.

### 5.6 Failure handling

| Failure | Handled by | Result |
|---|---|---|
| One server down | xray balancer + observatory | Switches to a healthy server within seconds |
| All servers down | Balancer fallback | `proxy-open` → direct, `proxy-closed` → block |
| xray or runner dead | RouterOS `check-gateway` | Fallback route: WAN (open) or blackhole (closed); works without tikray |
| tikray dead | Nothing needed for traffic | Watchdog restarts it (§6.3) |
| Bad xray / geo update | Runner trial | Automatic revert |
| Bad tikray update | Watchdog | Previous image + state restored |

## 6. RouterOS integration

### 6.1 Install (`install.rsc`)

Run with one pasted command (`/tool fetch` + `/import`), or by uploading the
file through Winbox/WebFig when GitHub is blocked.

1. **Pre-flight checks** (fail with a clear message and next step):
   - RouterOS version in a supported channel.
   - Architecture is ARM64.
   - `container` package installed (instructions if missing).
   - Container device-mode on (starts `/system/device-mode/update container=yes`
     and tells the user to press the button or power-cycle).
   - Enough free disk (~150 MB) and RAM.
2. **Network:** bridge, veths, IPs, NAT, firewall rules (§3.6).
3. **Containers:** container config (tmp dir, registry), both containers with
   mounts, env, start-on-boot, and memory limits where the RouterOS version
   supports them.
4. **RouterOS user** `tikray` in group `tikray`: policies `read,write,api` only
   (no `policy`, `password`, `sensitive`), allowed address = the `tikray`
   container IP only, random password passed to the container.
5. **API-SSL:** enables `api-ssl` with a self-signed certificate if needed. It only
   *adds* the container IP to the service's allowed addresses and never removes
   the user's entries.
6. **Watchdog** scheduler script (§6.3).
7. **Finish:** prints the UI URL, the TLS fingerprint and a **one-time setup code**.

The installer only bootstraps. It creates no traffic rules; those belong to the
reconciler. It is idempotent and safe to re-run.

### 6.2 Reconciler

- **Declarative:** desired RouterOS objects are computed from settings. Actual
  objects are read where their comment starts with `tikray:`. Only the minimal
  diff is applied.
- **Ownership:** tikray never modifies objects it didn't create. Its rules live in
  its own chains, except the single FastTrack-accept rule (§5.2).
- **Safe ordering:** RouterOS has no transactions, so changes are ordered so every
  intermediate state is valid. Tables and routes are created before the marks
  that use them, and removed after those marks.
- **Triggers:** settings changes, startup, `/listen` events on tikray-owned
  objects (drift repair, shown as "drift corrected"), and a periodic full check.
- **Version adapters:** RouterOS version differences (for example the container
  networking change in 7.20.7) live in `internal/routeros/adapters`, selected by
  detected version, and are covered by the CI matrix.

### 6.3 Watchdog (RouterOS scheduler)

Runs every minute on RouterOS itself, independent of both containers:

- Checks `tikray` `/healthz` with `/tool fetch`.
- If a `tikray` update marker is present and health has failed past the update
  window → restores the previous `tikray` image from `/data/images/` and removes
  the marker.
- If a runner update marker is present and the runner gateway fails its ping past
  the update window → restores the previous runner image the same way.
- Otherwise, after N consecutive failures → restarts the failing container, with
  backoff.

### 6.4 State file versioning

- State lives in `state.v<N>.json`. A migration never edits an older file; it
  writes `state.v<N+1>.json`.
- On start, tikray loads the highest version it understands.
- Rollback to an older tikray therefore needs no restore step.
- Old state files are pruned together with old image slots.

### 6.5 Uninstall (`uninstall.rsc`)

Removes both containers and every RouterOS object tagged `tikray:` (rules, lists,
tables, routes, user, group, scheduler). Asks whether to keep `/data`.

## 7. Security

- **Web UI:** HTTPS with a self-signed certificate generated on first start
  (fingerprint shown by the installer). Reachable only from LAN.
- **First admin:** claimed with the one-time setup code from the installer.
- **Authentication:** argon2id password hashing, secure cookies, CSRF protection,
  login rate limiting.
- **Secrets:** server credentials and the RouterOS password are kept in the
  `0600` state directory. Backup exports are encrypted with a user passphrase.
- **Runner:** control API requires a token; SOCKS, DNS and control listen only on
  the bridge.
- **RouterOS access:** least-privilege user restricted to the container IP.
- **Supply chain:** CI-built images signed with cosign, SBOM published, xray and
  geo verified (§4.3). tikray does not bundle xray, so the GPL-3.0 tikray code and
  MPL-2.0 xray binaries stay separate works.

## 8. Testing, CI and releases

### 8.1 Unit tests

- `render`: golden JSON per scenario.
- `sharelink` / `subscription`: Go native fuzz tests plus fixtures.
- `routeros` reconciler: diff and ordering against a fake RouterOS.
- `artifacts`: corrupted files, wrong hashes, timeouts, dead mirrors,
  interrupted installs.
- `store`: migrations between state versions.
- Runner trial protocol: candidate failure, crash, missed deadline, reboot during trial.

### 8.2 xray compatibility matrix

- CI renders every golden scenario and runs `xray run -test` against the oldest
  supported, latest-1 and latest xray releases.
- A scheduled workflow watches XTLS releases: for each new version it runs the
  matrix, publishes the signed hash index entry, and opens a PR to extend the
  tested range (or an issue describing the break).

### 8.3 Signed hash index

- Generated by CI from upstream `.dgst` files and signed (cosign blob signature).
- Published on GitHub Pages with mirrors. Used only as a verification fallback (§4.3).

### 8.4 End-to-end on RouterOS CHR

- RouterOS CHR in QEMU, **stable** and **long-term** channels. x86 CHR runs on
  every PR (same logic, amd64 images); ARM64 CHR runs nightly.
- Setup: a LAN client network namespace → CHR → runner/xray → a test VLESS
  server inside CI → a target HTTP server.
- Scenarios:
  - install from scratch and re-install (idempotent);
  - `direct` / `smart` / `full` paths reach the right egress;
  - kill switch blocks and open policy falls back, for all-servers-down;
  - failover between two servers;
  - DNS paths and the IPv6 leak guard;
  - drift repair after deleting a tikray rule;
  - xray update, plus an update with a broken binary that must revert;
  - geo update and address-list diff;
  - tikray self-update and watchdog rollback;
  - uninstall leaves zero `tikray:` objects.

### 8.5 Hardware benchmark

hAP ax³ and RB5009 (self-hosted runner or manual): throughput (TCP/UDP, many
connections), RAM and CPU for xray and tikray. Run in M0 and before every release.

### 8.6 Releases

- `tikray`: tags `vX.Y.Z`. Each release publishes:
  - ARM64 (and amd64 for CHR) images to ghcr.io, mirrored to Docker Hub;
  - image `.tar` files attached to the GitHub release, for file-based install
    on RouterOS;
  - cosign signatures and SBOM;
  - `install.rsc` / `uninstall.rsc`.
- `tikray-runner`: tags `runner-vX.Y.Z`, same publishing steps, released only when
  the runner changes.

## 9. Repository layout

One Go monorepo, two release lines:

```
cmd/tikray/            control plane entrypoint
cmd/tikray-runner/     data-plane runner entrypoint
internal/
  store/ render/ routeros/ artifacts/ xray/ health/
  sharelink/ subscription/ api/ cli/ ui/
web/                   UI source (Svelte + Vite), built output embedded via go:embed
routeros/              install.rsc, uninstall.rsc, watchdog.rsc
deploy/                Dockerfiles (runner: scratch; tikray: minimal base with busybox
                       so /container/shell works for debugging)
test/e2e/              CHR-based end-to-end tests
docs/
```

## 10. Milestones

| Milestone | Outcome |
|---|---|
| **M0: data-path spike** | On RouterOS CHR ARM64 and real hardware, prove: xray TUN inbound inside a RouterOS container, mangle routing into it, no source NAT, sniffing with `routeOnly`, UDP/QUIC, DNS redirect. Measure throughput and RAM. If something blocks this path, we change the design before building on it. |
| **M1: runner + artifacts** | Runner with trial protocol; fetch chain, verification, slots; xray update and rollback end to end. |
| **M2: control-plane core** | `store`, `render`, `xray` client, `sharelink`, `subscription`, `health`, REST API, CLI. |
| **M3: RouterOS** | `install.rsc`, reconciler, version adapters, watchdog, uninstall, CHR e2e suite. |
| **M4: web UI** | Dashboard, servers and subscriptions, devices and policies, routing, updates (history and rollback), settings, logs. |
| **M5: v1.0** | Hardening, full e2e matrix, hardware benchmarks, docs, signed release. |

## 11. Risks

| Risk | Mitigation |
|---|---|
| xray TUN inbound doesn't behave as expected inside a RouterOS container | M0 spike first; fallback design is a TPROXY + `dokodemo-door` inbound set up by the runner via nftables netlink |
| xray throughput on ARM64 MikroTik CPUs is too low | Hybrid steering keeps domestic traffic off xray; M0 benchmark; tuning (sniffing scope, QUIC options) |
| RouterOS container or API behavior changes between versions | Version adapters + CI matrix on stable and long-term |
| Flash wear from address-list and file writes | Diff sync, external storage recommended, daily (not more often) geo checks |
| Upstream xray config deprecations | Compatibility matrix + scheduled upstream watch |
| Users on blocked networks can't fetch anything | Fetch chain ending in manual upload; installer available as a file |
| Device IP changes break per-device policies | Static DHCP lease creation in the UI; MAC used for IPv6 guard |

## Appendix A: Measured Go vs Rust (informing the language choice)

Measured on an x86-64 cloud machine (not MikroTik hardware). Equivalent minimal
control-plane servers (static page, JSON status API, background health loop),
50,000 requests at 50 concurrency.

| | Go | Go (`GOMEMLIMIT=16MiB`, `GOGC=50`) | Rust (axum/tokio) |
|---|---|---|---|
| Idle RSS | 7.5 MB | 7.6 MB | 3.3 MB |
| Peak RSS under load | 14.1–17.2 MB | 12.0–15.8 MB | 5.0–5.5 MB |
| Stripped binary | 5.4 MB (arm64) | — | 0.9 MB (amd64) |

xray-core 26.3.27, built from source, SOCKS inbound, VLESS/Reality + freedom
outbounds, 50,000 proxied requests with a new connection each:

| Routing rules | Idle RSS | Peak RSS |
|---|---|---|
| None | 28.2 MB | 63.5 MB |
| Small geosite set | 28.7 MB | 64.5 MB |
| Large geosite set (`geolocation-!cn`, ads) | 32.4 MB | 70.7 MB |
| Large set + `GOMEMLIMIT=40MiB` | 31.8 MB | 57.9 MB |

Conclusion: xray uses 4–8× more memory than either control plane. Rust saves
about 4–10 MB; tuning xray's memory limit saves about as much. Go was chosen for
contributor familiarity, ecosystem (share-link and subscription tooling) and
simpler builds. Geo data measured was the small v2fly list (2.3 MB); larger
community lists increase xray's share further.

## Appendix B: Sources

- Xray-core TUN inbound package docs: https://pkg.go.dev/github.com/0xCLWN/xray-core/proxy/tun
- Official xray-core image (GHCR): https://github.com/orgs/XTLS/packages/container/package/xray-core
- MikroTik forum, VLESS via containers: https://forum.mikrotik.com/t/vless-proxy-tunnel-on-mikrotik-via-containers/172770
- tun2socks-mikrotik image (RouterOS 7.20.7 container networking change): https://hub.docker.com/r/ppptran/tun2socks-mikrotik
