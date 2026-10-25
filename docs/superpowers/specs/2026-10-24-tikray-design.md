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
| xray-core | The newest release (minimum 26.1.18 for the TUN inbound) |
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
  enables forwarding and sets `rp_filter=0` through `/proc/sys`, then adds
  `iif <ingress> lookup 1001` and `default dev xray0 table 1001`, re-adding them
  whenever xray recreates `xray0`. xray's own outbound traffic leaves through the
  ingress link using the main table. The ingress link is found from the default
  route: in a RouterOS container it is named after the veth, not `eth0`. (All
  confirmed in M0 on CHR, with `privileged=no` and no `devices`.)
- **Health signal:** the runner answers ping only while xray is running and its
  routes are in place; otherwise it sets `icmp_echo_ignore_all`. RouterOS
  `check-gateway` and netwatch probe the runner with ping, so they see a dead
  xray, not only a dead container. Table 1001 also holds a low-priority
  `unreachable` default, so packets that arrive while `xray0` is gone are
  rejected instead of being sent back to the router, which would route them to
  the runner again (M0).
- **Process supervision:** starts xray from the version named in
  `/data/run/active.json` and restarts it if it crashes. Core binaries placed by
  RouterOS (`/tool fetch`, Winbox uploads) have no execute bit and RouterOS has no
  `chmod`, so the runner copies the active core into its own filesystem with mode
  0755 and runs that copy (M0).
- **Control API**, listening only on the runner's bridge address, port 8080, and
  protected by a bearer token (`/data/run/runner.token`): `status`, `reload`,
  `restart`, `trial`, `commit`, `abort`, and `xray-api` (runs `xray api <cmd>`
  with the active core binary, so JSON → protobuf conversion always matches the
  running version).
- **Trial protocol (A/B slots):**
  1. tikray writes `/data/run/candidate.json` (core version, geo version, config
     file, deadline) and calls `trial`.
  2. The runner runs `xray run -test` with the candidate. On failure it rejects
     the candidate without switching. It tests a copy of the candidate's config
     whose TUN devices are renamed (`xray-test<n>`): xray releases before 26.10
     open their TUN during `-test`, and the running xray already holds `xray0`
     ("device or resource busy", M1 lab). A config it can't rewrite (such as
     JSON with comments) is tested unchanged.
  3. Otherwise it stops the active xray and starts the candidate. If the candidate
     exits within 10 s, the runner reverts to `active.json`.
  4. If tikray does not call `commit` before the deadline (default 120 s), the
     runner reverts.
  5. On `commit`, `candidate.json` atomically replaces `active.json`.
  6. On boot, the runner always starts from `active.json`, never from a candidate.

  This means a crash or reboot at any point during an update cannot leave xray broken.
- Sets `GOMEMLIMIT` for xray to cap memory growth. The default is `128MiB`; the
  runner env `XRAY_GOMEMLIMIT` changes it, and `off` leaves it unset.

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
| `xraypolicy` | Knows which outbounds the newest xray refuses, so that `sharelink` and `store` refuse them when a server is added (§4.9) |
| `subscription` | Fetches subscriptions (through the fetch chain), decodes base64/plain lists, refreshes on a schedule |
| `api` | REST API with authentication; used by the UI and the CLI |
| `cli` | `tikray` CLI subcommands (remote via REST, or inside the container) |
| `ui` | Embedded static web UI (Svelte + Vite, built at release time) |

Servers can be added by share link, subscription, or **raw outbound JSON**. Raw
JSON lets power users run any protocol or transport xray supports, including
ones newer than tikray's share-link parsers.

M2 builds the control plane in two parts:
- **M2a**, the model and the config: `store`, `sharelink`, `xraypolicy`,
  `subscription` (decode, merge, fetch, without the schedule) and `render`,
  plus an apply that puts the rendered config on trial with the active core.
  Core updates and rollbacks render the config for the core they switch to
  (§4.5 step 2). It runs as the one-shot CLI inside the `tikray` container:
  `tikray config render`, `tikray apply`, `tikray core update|rollback`.
- **M2b**, the long-running service on top: the REST API and its
  authentication, the `xray` gRPC client, the `health` monitor, hot changes,
  subscription scheduling, and the CLI over REST.

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
`/data/geo` read-only and `/data/run` read-write. RouterOS mounts are
`/container/mounts/add list=<name> src= dst= mode=ro|rw` and containers reference
them with `mountlists=`; `mode=ro` is enforced (M0).

### 3.6 Networking

- One bridge `tikray`, default subnet `172.31.255.0/29` (configurable at install
  time to avoid clashing with the LAN): router `.1`, `tikray` `.2`, runner `.3`.
- The bridge is created with `protocol-mode=none`. With RouterOS's default RSTP
  a freshly started container's veth spends the forward delay blocked, so a
  just-started container couldn't reach the runner (M1 lab, 2/2 A/B each way).
- NAT masquerade for the container subnet out to the WAN.
- Every container sets `dns=` explicitly (the router's bridge address): RouterOS
  refuses to start a container without DNS ("no default dns servers") even when
  `/ip/dns` has servers (M0).
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
  explicit confirmation. A core installed that way needs it again on every
  later update to it; once its hash becomes known, the installed zip must match
  it.
- **Servers' TLS certificates** are always verified. xray 26.3.27 and later
  refuse `allowInsecure` once past 2026-06-01, and 26.1.18 skips the check
  with it (§4.9), so tikray keeps `allowInsecure: true` out of every
  `tlsSettings` xray reads for a server:
  - a share link that asks for `allowInsecure` (or `insecure`) is imported
    with verification on and a warning, unless it also pins with `pcs`; the
    parser never emits `allowInsecure`;
  - a raw-JSON server with `allowInsecure: true` in any `tlsSettings` under
    its `streamSettings`, at any depth (the stream's own, or a nested
    stream's such as xhttp's `extra.downloadSettings`), is refused when it is
    added, whatever its protocol or security, with the advice to pin the
    certificate with `pinnedPeerCertSha256`.

  A share link's `pcs` and `vcn` map to xray's `pinnedPeerCertSha256` and
  `verifyPeerCertByName`, so a self-signed server can be pinned.

### 4.4 Slots and retention

The current and previous versions of each piece are kept by default (the count is
configurable). Older slots are removed automatically after a successful commit.

### 4.5 xray-core update

1. Fetch and verify the selected version into `/data/cores/<ver>/`.
2. Render the config for that version (§4.9).
3. Runner trial (§3.3).
4. Health check: the running core reports the requested version
   (`xray version` says `Xray <ver> `, so a slot holding another release is
   never committed under its name); the runner's data-path signals hold
   (`routes_ok`: its routes into `xray0` are in place; `gateway_up`: it answers
   ping); real traffic through the proxy (SOCKS probe to a configurable URL);
   and gRPC responding. The probes alone pass without `xray0`, while a runner
   that doesn't answer ping sends fail-open devices direct.
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

- tikray targets the **newest xray-core release**. The lab and CI follow the newest
  XTLS release tag automatically; M0 ran on 26.10.21 (newest) and 26.3.27.
- `render` keeps a table of xray features and the minimum version each needs,
  for example the TUN inbound (≥ 26.1.18, confirmed in M0: the first release with
  `proxy/tun`). 26.10 renamed the TUN `MTU` key to `mtu`; render emits `mtu`.
- **Tested range** is maintained by CI (§8.2). Newer, untested xray versions are
  allowed and labelled "untested"; the trial and `xray run -test` catch real breakage.
- Versions too old for features the current config uses are refused with an
  explanation.
- Newer releases also refuse configs older ones ran, and one refused outbound
  fails the whole config, so one such server would make every later apply fail
  its `xray run -test`. tikray follows the newest release and refuses these
  servers when they are added, from a share link (a subscription skips the
  line, with the reason) or as raw JSON (`internal/xraypolicy`):
  - xray ≥ 26.3.27 refuses `tlsSettings.allowInsecure: true` after
    2026-06-01. A share link never brings it in (§4.3); a raw-JSON outbound
    of any protocol that holds it, in any `tlsSettings` under its
    `streamSettings`, is refused.
  - xray ≥ 26.7.11 refuses VLESS without TLS or VLESS encryption, and Trojan
    without TLS, to an address outside xray's private lists, and refuses
    Shadowsocks `none` (and `plain`). tikray also refuses 2022-blake3 keys
    that aren't padded base64 of the cipher's key length, the one form every
    supported release accepts.

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
  - **Packets addressed to the router are never marked:** the chain's first rule
    returns on `dst-address-type=local`. Replies of masqueraded (fallen-back)
    connections reach mangle prerouting before NAT is undone, with the WAN address
    as destination. Without this rule they get the routing mark and go back out
    the WAN, which breaks fail-open fallback (found in M0).
  - **Routing follows the connection mark alone**, so a connection keeps one path
    for its whole life. When a device changes policy, the reconciler removes that
    device's tracked connections, so the new policy applies at once instead of
    when old connections end. (An M0 variant that also matched the source list in
    `mark-routing` sent a moved device's open connections out the WAN without NAT.)
  - MSS clamp on marked connections for the tunnel MTU.
- **FastTrack:** one rule "accept tikray-marked connections", placed directly
  before the user's FastTrack rule. This is the only rule tikray places in a user chain.
  (In one M0 run on 7.25 without the rule, routing-marked connections were flagged
  but none of their packets were fast-pathed. One run isn't a guarantee, so the
  rule stays.)
- **Routing tables:**
  - `tikray-open`: default via the runner (`check-gateway=ping`, distance 1),
    fallback via the main WAN gateway (distance 2).
  - `tikray-closed`: default via the runner (`check-gateway=ping`, distance 1),
    fallback blackhole (distance 2).
- **Netwatch** `tikray:runner-watch` on the runner, which switches fail-open
  devices' DNS (§5.4).
- **No source NAT** into the container: xray sees each device's real IP.

### 5.3 Inside xray

- **TUN inbound** with sniffing (`tls`, `http`, `quic`) and `routeOnly: true`:
  the domain is used for routing, but the original destination IP is kept.
- **Service inbounds** listen on the runner's bridge address, and their rules
  come before every other rule:
  - `socks-in`, for tikray's SOCKS probes and proxied fetches, answers tikray's
    address only, through `proxy-closed`: a probe or fetch never passes by
    going direct. Anything else on it is blocked.
  - `api-in`, xray's gRPC API, answers only tikray's and the runner's own
    addresses. Anything else on it is blocked.
  - `dns-in` hands the devices' queries to xray's DNS (§5.4), whose own
    queries have their rules next.
- **Rule order** of the devices' traffic, from the TUN inbound:
  1. Block list (optional, e.g. ads).
  2. Sources in `full` policies → their balancer (skips domestic rules).
  3. Domestic domains (geosite) → `direct`.
  4. Domestic IPs (geoip) → `direct`, as a safety net.
  5. User custom rules (domain/IP → direct/proxy/block/specific server).
  6. Sources with kill switch → `proxy-closed`; everyone else → `proxy-open`.
- **Balancers:** `proxy-open` (fallback `direct`) and `proxy-closed` (fallback
  `block`) share the same server set. Health comes from xray's classic
  `observatory`, which probes every server at once, through the server, at the
  state's probe URL, as soon as xray starts and then every 10 s. (The burst
  observatory spreads its first samples over its whole interval, so a config
  just put on trial would run on the fallbacks for a while.) The strategy is
  lowest latency (`leastPing`), and the user can pin a server, which is then
  the balancers' only member. While the balancers have no member, because no
  server is enabled or the pinned one is disabled, the balancers and the
  observatory are left out and every rule names the fallback outbound itself.
- **Outbounds:** one per server (rendered from share links, subscriptions or raw
  JSON), plus `block` (blackhole), `direct` (freedom) and `dns-out`. `block`
  comes first: xray sends traffic that no rule matches to the first outbound,
  so that traffic is dropped, never sent direct. A server's outbound must be
  a proxy: one whose protocol xray reads as freedom, blackhole, dns or
  loopback, under any name it knows them by (`direct` and `block` included,
  in any case), is refused, since it would let proxied and kill-switch
  traffic out direct.
- **Share links:** a TLS link with no `sni` takes its server name from the
  first value of `host`, as v2rayN does, so that a CDN-fronted link to a bare
  IP address still handshakes with the right name. Reality takes `sni` only.

### 5.4 DNS

- Devices with the `direct` policy keep using RouterOS DNS as before, unchanged.
- For `smart` and `full` devices, the reconciler dst-NATs TCP/UDP 53 to the
  runner's DNS endpoint (xray DNS):
  - Domestic domains → domestic resolver (default: the router itself, so its
    normal upstream is used), direct. The domestic server is rendered with
    `skipFallback: true`: in xray a server with `domains` is otherwise also a
    fallback for every other domain, which sends non-domestic lookups direct (M0).
  - Everything else → the remote resolver through the proxy: DoH by default,
    or plain DNS to an IPv4 address.
  - The rule that sends the domestic resolver's queries direct matches its
    address and port 53 only, so a remote resolver on the same host, such as
    DoH on 443, still goes through the proxy. tikray refuses a plain-DNS
    remote at the domestic resolver's address, since the two could not be
    told apart.
  - `queryStrategy: UseIPv4` for these devices while the IPv6 leak guard is active.
  - `dns-out` answers A and AAAA queries with xray's DNS and rejects every
    other type (`nonIPQuery: reject`), so nothing is forwarded to the address
    `dns-in` must name. xray 26.9.30 and later warn that `nonIPQuery` is
    deprecated for `rules` (which 26.4.25 added); render keeps it while the
    oldest supported release, 26.1.18, lacks the replacement.
- **DNS follows the fallback.** The dst-NAT rules come in two sets, for fail-open
  and kill-switch sources. A RouterOS netwatch on the runner disables the
  fail-open set while the runner doesn't answer ping (§3.3), so fail-open devices
  move to the router's own DNS together with their routes. Kill-switch devices
  keep pointing at the runner and get no answers. This runs on RouterOS alone,
  without tikray. The router's DNS must accept LAN requests
  (`allow-remote-requests=yes`); the installer checks it. Lookups already tracked
  to the runner keep their NAT until their conntrack entry expires (M0).
- Browsers that use their own DoH still route correctly, because routing uses
  sniffing, not DNS.
- xray's DoH upstream uses the `proxy-open` balancer. During a full outage, DNS
  for kill-switch devices may therefore resolve over direct DoH. That connection is
  encrypted, so query contents aren't exposed, and those devices' traffic stays
  blocked. A plain-DNS remote sends those queries in clear. The alternative,
  failing all non-domestic DNS for open-policy devices during an outage, would
  break the direct fallback they rely on.

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
| xray or runner dead | Runner stops answering ping (§3.3); RouterOS `check-gateway` and netwatch | Fallback route: WAN (open) or blackhole (closed); fail-open devices' DNS moves to the router (§5.4); works without tikray |
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
   - Router DNS accepts LAN requests (`allow-remote-requests=yes`), needed for
     the DNS fallback (§5.4).
2. **Network:** bridge (`protocol-mode=none`), veths, IPs, NAT, firewall rules
   (§3.6).
3. **Containers:** container config (tmp dir, registry), both containers with
   mount lists, env lists, explicit `dns=`, start-on-boot, and memory limits
   (`memory-high`/`memory-max` exist on 7.25).
4. **RouterOS user** `tikray` in group `tikray`: policies `read,write,api` only
   (no `policy`, `password`, `sensitive`), allowed address = the `tikray`
   container IP only, random password passed to the container.
5. **API-SSL:** enables `api-ssl` with a self-signed certificate if needed (the
   template keeps `key-cert-sign`, or `/certificate/sign` fails with "CA not
   found"). It only *adds* the container IP to the service's allowed addresses and
   never removes the user's entries.
6. **Watchdog** scheduler script (§6.3).
7. **Finish:** prints the UI URL, the TLS fingerprint and a **one-time setup code**.

Script steps that need a value from an earlier step run inside one `{ }` block:
`/import` runs each top-level line on its own, so a `:local` is gone on the next
line (M0: this silently skipped the FastTrack exemption).

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
  networking change in 7.20.7, mounts' `list=`, `/disk/format` replacing
  `format-drive`) live in `internal/routeros/adapters`, selected by detected
  version, and are covered by the CI matrix.
- **One connection:** the API client keeps one connection open and backs off on a
  refused login. RouterOS throttles bursts of logins, and rejects a correct one
  right after a failed one (M0).

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
  `0600` state directory. The rendered xray configs hold the servers'
  credentials too, so they are `0600` in a `0700` `run/config/`; both images
  run as root. Backup exports are encrypted with a user passphrase.
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
  supported, latest-1 and latest xray releases, and runs the CHR end-to-end suite
  (§8.4) on the latest release. Config checks alone are not enough: xray 26.10
  changed a server-side `freedom` default (blocking private/reserved targets)
  that passed `-test` and only failed with real traffic (M0).
- A scheduled workflow watches XTLS releases: for each new version it runs the
  matrix, publishes the signed hash index entry, and opens a PR to extend the
  tested range (or an issue describing the break).

### 8.3 Signed hash index

- Generated by CI from upstream `.dgst` files and signed (cosign blob signature).
- Published on GitHub Pages with mirrors. Used only as a verification fallback (§4.3).

### 8.4 End-to-end on RouterOS CHR

- RouterOS CHR in QEMU, **stable** and **long-term** channels. x86 CHR runs on
  every PR (same logic, amd64 images); ARM64 CHR runs nightly.
- The `test/lab` harness from M0 is the base: fake LAN and internet in network
  namespaces, serial/SSH provisioning, device-mode confirmed by a power cycle, and
  a cached "ready" image per RouterOS version so each run skips the package install
  and device-mode reboots. Runners need KVM for practical boot times (TCG takes
  minutes per boot). ARM64 CHR needs QEMU's `-cpu cortex-a72`: on `-cpu max` its
  kernel hangs right after the EFI stub (M0). CHR's free license caps each
  interface at ~1 Mbps, so CI checks correctness only; throughput comes from §8.5.
- Setup: a LAN client network namespace → CHR → runner/xray → a test VLESS
  server inside CI → a target HTTP server.
- Scenarios:
  - install from scratch and re-install (idempotent);
  - `direct` / `smart` / `full` paths reach the right egress;
  - kill switch blocks and open policy falls back (routes and DNS), for
    all-servers-down, a stopped runner, xray dead inside a running runner, and
    the first minutes after a reboot;
  - a device changing policy mid-connection;
  - failover between two servers;
  - DNS paths and the IPv6 leak guard;
  - drift repair after deleting a tikray rule;
  - xray update, plus an update with a broken binary that must revert. Runs
    since M1 (`TestCoreLifecycle` in `test/e2e`, with the real images and a
    fake GitHub and mirror): bootstrap from an empty runner; an update to the
    newest release through the proxy while GitHub refuses direct requests; a
    core that `xray run -test` rejects (an unverified inbox upload) and one
    that crashes within 10 s, both reverted with traffic still proxied; an
    install from a mirror verified by the signed hash index while GitHub is
    down; rollback; pruning to two slots; a power cut during a trial, after
    which the runner boots from `active.json` and records `reboot`; and the
    runner's ping answer going down during a trial and back up after it;
  - configs rendered from the state. Runs since M2a (`TestConfigApply` in
    `test/e2e`, with a second VLESS server in the fake internet): a bootstrap
    rendered from the default state; a server from a share link put on trial
    with `tikray apply`; the smart split by sniffed HTTP Host, by domestic
    address (in xray, with the RouterOS list entry off) and in DNS; failover
    between the two servers; all servers down, open (direct) and with the
    kill switch (blocked); a raw server that `xray run -test` rejects, with the
    previous config kept; and a core update and rollback that render for
    their core;
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
    on RouterOS. They must be archives RouterOS can import: Docker's containerd
    image store produces archives RouterOS rejects ("no config found in
    manifest"), the classic store's `docker save` output works (M0). CI imports
    every release archive into CHR before publishing;
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
| **M0: data-path spike** | **Lab done:** all 22 checks pass on CHR x86_64 (stable 7.25, long-term 7.23.8) and ARM64 (stable 7.25) with the newest xray; the real-hardware benchmark is pending. See `docs/superpowers/findings/2026-10-24-m0-data-path.md`. On RouterOS CHR ARM64 and real hardware, prove: xray TUN inbound inside a RouterOS container, mangle routing into it, no source NAT, sniffing with `routeOnly`, UDP, DNS redirect, fallback. Measure throughput and RAM. If something blocks this path, we change the design before building on it. (QUIC sniffing moved to M3: no QUIC fixture in M0.) |
| **M1: runner + artifacts** | **Done:** the real `tikray-runner` and `tikray` images take xray-core through all nine lifecycle scenarios of `TestCoreLifecycle` (`test/e2e/core_lab_test.go`, §8.4) on CHR x86_64 (stable 7.25, long-term 7.23.8) and ARM64 (stable 7.25), with 26.1.18, 26.3.27 and the newest release, 26.10.21. Results: `test/e2e/results/`. Runner with trial protocol; fetch chain, verification, slots; xray update and rollback end to end. |
| **M2: control-plane core** | **M2a done** (§3.4): the desired state in versioned files (`store`), share links (`sharelink`), the outbound policy of the newest xray (`xraypolicy`), subscriptions without the schedule (`subscription`), the config renderer (`render`, its golden scenarios accepted by xray 26.1.18, 26.3.27, 26.9.30 and 26.10.21, §8.2), and `tikray config render` and `tikray apply`, with core updates and rollbacks rendering for their core. `TestConfigApply` (`test/e2e/config_lab_test.go`, §8.4) passes all eight checks on CHR x86_64 (stable 7.25, long-term 7.23.8) and ARM64 (stable 7.25) with the newest xray, 26.10.21, and 26.3.27; `TestCoreLifecycle` still passes all nine on rendered configs (x86_64, stable 7.25). Results: `test/e2e/results/*-m2a.json`, and `7.25-x86_64-m1.json` from that re-run. **M2b:** REST API and authentication, the `xray` client, `health`, hot changes, subscription scheduling, and the CLI over REST. |
| **M3: RouterOS** | `install.rsc`, reconciler, version adapters, watchdog, uninstall, CHR e2e suite. |
| **M4: web UI** | Dashboard, servers and subscriptions, devices and policies, routing, updates (history and rollback), settings, logs. |
| **M5: v1.0** | Hardening, full e2e matrix, hardware benchmarks, docs, signed release. |

## 11. Risks

| Risk | Mitigation |
|---|---|
| ~~xray TUN inbound doesn't behave as expected inside a RouterOS container~~ | Retired by M0: works on CHR 7.25 and 7.23.8 x86_64 and 7.25 ARM64, with xray 26.3.27 and 26.10.21, without `privileged` or `devices` |
| xray throughput on ARM64 MikroTik CPUs is too low | Hybrid steering keeps domestic traffic off xray; M0 benchmark; tuning (sniffing scope, QUIC options) |
| RouterOS container or API behavior changes between versions | Version adapters + CI matrix on stable and long-term |
| Flash wear from address-list and file writes | Diff sync, external storage recommended, daily (not more often) geo checks |
| Upstream xray config deprecations and default changes | Compatibility matrix + scheduled upstream watch, including the CHR end-to-end suite on each new release (§8.2) |
| RouterOS can't import an image archive format | CI imports every release archive into CHR (§8.6) |
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
