# M2a: state, share links and config rendering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** tikray keeps the user's desired state in a versioned state file, turns share links and subscriptions into servers, renders the xray config that implements the spec's policies, DNS and failover, and applies it through the runner's trial, end to end on RouterOS CHR.

**Architecture:** M2 is split in two plans. This one, M2a, builds the model and the config: `internal/store` (desired state, `state.v<N>.json`), `internal/sharelink`, `internal/subscription` (decode, merge, fetch), `internal/render` (state → xray JSON, with a feature table), and an `Apply` in `internal/artifacts` that trials a rendered config on the active core. Core updates and rollbacks also render for their target core (§4.5 step 2). The `tikray` CLI gains `config render` and `apply`. M2b, a separate plan written once M2a has landed, adds the long-running service on top: REST API and auth, the xray gRPC client, the health monitor, hot changes, subscription scheduling, and the CLI over REST.

**Tech Stack:** Go 1.24 (module `github.com/Arman2122/tikray`), stdlib only (`net/netip`, `encoding/json`, `crypto/rand`), and the existing `golang.org/x/net/proxy`. Lab: the M0/M1 `test/lab` and `test/e2e` harness.

**Spec:** `docs/superpowers/specs/2026-10-24-tikray-design.md` (§3.4, §3.5, §3.6, §4.5, §4.9, §5.1–5.4, §5.6, §6.4, §8.1, §8.2, §8.4). Findings: `docs/superpowers/findings/2026-10-24-m0-data-path.md`. M1 plan (the interfaces this builds on): `docs/superpowers/plans/2026-10-25-m1-runner-artifacts.md`.

## Global Constraints

- xray-core minimum **26.1.18** (TUN inbound). Render targets the newest release and emits the TUN key `mtu` (26.10 renamed `MTU`; xray parses keys case-insensitively, so older releases accept it).
- No image contains an xray binary or geo data (§3.1).
- Addresses come from the state's bridge subnet (default `172.31.255.0/29`): router `.1`, tikray `.2`, runner `.3`. Runner ports: control `8080`, SOCKS `1080`, xray gRPC API `10085`, DNS `53`.
- The runner's SOCKS, API and DNS inbounds listen only on the runner's bridge address (§3.6, §7). The xray API answers only tikray's and the runner's own addresses. SOCKS answers only tikray's.
- xray tags are fixed, and render, the CLI and M2b all use these names:
  - inbounds `tun-in`, `dns-in`, `socks-in`, `api-in`;
  - outbounds `block`, `direct`, `dns-out` and `srv-<id>`;
  - balancers `proxy-open` (fallback `direct`) and `proxy-closed` (fallback `block`);
  - the API tag `api` and the DNS tag `dns-internal`.
  The TUN device is `xray0`.
- §5.3 rule order and §5.4 DNS:
  - the domestic DNS server has `skipFallback: true`;
  - `queryStrategy` is `UseIPv4`;
  - remote DNS goes through `proxy-open`;
  - sniffing is `http`, `tls` and `quic` with `routeOnly: true`.
- **No rule ever routes a kill-switch source to `direct`**, except the domestic, custom-`direct` and DNS-domestic rules.
- **No rule is ever emitted with an empty matcher list.** A list that would be empty drops its rule: in xray, a rule without `source` matches every source.
- State lives in `/data/state` (dir `0700`), in `state.v<N>.json` files (mode `0600`), written atomically.
  - A migration never edits an older file (§6.4).
  - This tikray writes `Current = 1`. Until the first release, the v1 schema may change in place. After it, every change adds a version.
- Errors are prefixed with their package (`store: `, `render: `, `sharelink: `, `subscription: `), as in M1's packages.
- Commits use the repo's git identity, `Arman2122 <arman.seyri@gmail.com>`, and messages carry no trailers. Never push.

## Review Focus

1. **Empty matcher lists.** A device set that turns out empty, such as kill-switch-by-default with no open devices, must drop its rule and never emit `"source": []`, which xray reads as "everyone" (Task 7 `TestNoEmptyMatchers`).
2. **Kill-switch traffic going direct.** Check this:
   - when no server is enabled;
   - when the pinned server is disabled;
   - when the default policy is `full`;
   - when a custom rule targets a disabled server.
   (Task 7 `TestKillSwitchNeverDirect`, a property test over generated states.)
3. **Real-world share links.**
   - Percent-encoded paths such as `path=%2Fws%3Fed%3D2048`, names in Persian or with emoji, IPv6 hosts in brackets.
   - `type=raw`, an empty `security=`, vmess `port` as a string, and SIP002 user info with or without padding.
   Each must parse to the same outbound a correct client would build (Tasks 3–4 tables, and the fuzz test).
4. **Subscription refreshes.** A refresh must keep IDs and `disabled` flags for links that are unchanged, and leave manual servers and other subscriptions alone. A malformed line skips that line, not the whole subscription (Task 5).
5. **State files.** A corrupt highest state file is an error and is never replaced by defaults. A newer file, left by a tikray that was rolled back, is left alone (Task 2).

---

### Task 1: State model and validation

**Files:**
- Create: `internal/store/model.go`, `internal/store/validate.go`
- Test: `internal/store/model_test.go`

**Interfaces:**
- Produces (every later task uses these names):
  - `type Mode string` with `ModeDirect = "direct"`, `ModeSmart = "smart"`, `ModeFull = "full"`.
  - `type Policy struct{ Mode Mode \`json:"mode"\`; KillSwitch bool \`json:"kill_switch,omitempty"\` }`
  - `type Server struct{ ID, Name string; Disabled bool; Link, Subscription string; Outbound json.RawMessage }`. The JSON keys are `id`, `name`, `disabled,omitempty`, `link,omitempty`, `subscription,omitempty` and `outbound`, plus `func (s Server) Tag() string`, which returns `"srv-" + s.ID`.
  - `type Duration time.Duration`, which marshals as text (`"24h0m0s"`) and parses with `time.ParseDuration`.
  - `type Subscription struct{ ID, Name, URL string; Disabled bool; Interval Duration; LastFetch time.Time; LastError string }`. The JSON keys are `id`, `name`, `url`, `disabled,omitempty`, `interval`, `last_fetch,omitzero` and `last_error,omitempty`.
  - `type Device struct{ Address netip.Prefix; Name, MAC string; Policy Policy }`. The JSON keys are `address`, `name,omitempty`, `mac,omitempty` and `policy`. A single device is a `/32`.
  - `type Action string` with `ActionDirect = "direct"`, `ActionProxy = "proxy"`, `ActionBlock = "block"`, `ActionServer = "server"`.
  - `type Rule struct{ Domains, IPs []string; Action Action; Server string }`. The JSON keys are `domains,omitempty`, `ips,omitempty`, `action` and `server,omitempty`.
  - `type Domestic struct{ Domains, IPs []string }`: extra domestic matchers, used beside the geo bundle's.
  - `type Routing struct{ Pinned string; BlockList []string; Domestic Domestic; Rules []Rule }`. The JSON keys are `pinned,omitempty`, `block_list,omitempty`, `domestic` and `rules,omitempty`.
  - `type DNS struct{ Domestic netip.Addr; Remote string }`. The JSON keys are `domestic,omitzero` and `remote`. A zero `Domestic` means the router's bridge address.
  - `type Network struct{ Subnet netip.Prefix }` with methods `Router()`, `Tikray()` and `Runner()`, each returning a `netip.Addr`: the subnet's `.1`, `.2` and `.3`.
  - `type Health struct{ ProbeURL string }`, JSON key `probe_url`.
  - `type State struct{ Servers []Server; Subscriptions []Subscription; Devices []Device; DefaultPolicy Policy; Routing Routing; DNS DNS; Network Network; Health Health }`. The JSON keys are `servers`, `subscriptions`, `devices`, `default_policy`, `routing`, `dns`, `network` and `health`.
  - `func Default() State`:
    - default policy `direct`;
    - subnet `172.31.255.0/29`;
    - DNS remote `https://1.1.1.1/dns-query`;
    - probe URL `https://www.gstatic.com/generate_204`;
    - empty lists marshalled as `[]`, not `null`.
  - `func (s State) Clone() State`: a deep copy, so a later change to the clone never shows in s.
  - `func (s State) Validate() error`: every problem, joined with `errors.Join`, each prefixed with its path, such as `devices[1].address: `.
  - `func NewID() string`: 8 lowercase hex digits from `crypto/rand`.

- [ ] **Step 1: Write the failing tests** in `internal/store/model_test.go`:
  - `TestDefaultIsValid`: `Default().Validate()` is nil, and `Default()` marshals to exactly this JSON (two-space indent):
    ```json
    {"servers":[],"subscriptions":[],"devices":[],"default_policy":{"mode":"direct"},"routing":{"domestic":{}},"dns":{"remote":"https://1.1.1.1/dns-query"},"network":{"subnet":"172.31.255.0/29"},"health":{"probe_url":"https://www.gstatic.com/generate_204"}}
    ```
  - `TestNetworkAddresses`: `172.31.255.0/29` gives `.1`, `.2` and `.3`, and `10.9.8.0/28` gives `10.9.8.1`, `.2` and `.3`.
  - `TestCloneIsDeep`: changing a clone's server outbound bytes, device slice, rule domains or `Routing.Domestic.IPs` leaves the original equal to a fresh `Default()`-based fixture.
  - `TestValidateRejects` is a table. Each case starts from a valid state with one server `a1b2c3d4`, one subscription `00ff00ff` and one device. It changes one thing and asserts that the error contains the path. The cases are:
    - server ID `A1B2C3D4` (uppercase), `a1b2c3` (short) or a duplicate;
    - an empty name, or a name over 128 runes;
    - an outbound that is not a JSON object, or has no `protocol`;
    - an outbound with protocol `freedom`, `blackhole`, `dns` or `loopback`: these are not proxies, and one would carry kill-switch traffic direct;
    - an outbound with a `tag` key;
    - `Subscription` naming a missing subscription;
    - subscription URL `ftp://x`, a relative URL, or an interval under `1h`;
    - device address `fe80::1/128` (not IPv4) or `192.168.1.5/24` (not masked);
    - two overlapping devices (`192.168.1.0/24` and `192.168.1.7/32`);
    - mode `vpn`, or `direct` with the kill switch on (both for a device and for `default_policy`);
    - `pinned` naming a missing server;
    - an empty block-list entry, or one containing whitespace;
    - `regexp:(` (does not compile);
    - a domestic IP `300.1.1.1`;
    - a rule with neither domains nor IPs;
    - action `tunnel`;
    - `server` without action `server`, or action `server` naming a missing server;
    - DNS domestic `::1`;
    - DNS remote `http://x/dns-query` (not https), or `example.com` (neither a URL nor an IPv4);
    - subnet `172.31.255.0/30` (too small: it needs `.1`–`.3`) or `fd00::/64`;
    - probe URL `not a url`.
  - `TestValidateAccepts`:
    - matchers `domain:example.com`, `full:a.b`, `keyword:x`, `regexp:^a\.b$`, `geosite:category-ir` and plain `example`;
    - IPs `10.0.0.0/8`, `1.2.3.4` and `geoip:ir`;
    - DNS remote `203.0.113.53`.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/store/`. Expected: FAIL to compile (package missing).

- [ ] **Step 3: Implement** `model.go` (types, `Default`, `Clone`, `Network` methods, `NewID`, `Duration` text marshalling) and `validate.go` (`Validate`).
  - Domain matchers are valid when they are non-empty, contain no whitespace, and either carry one of the prefixes `domain:`, `full:`, `keyword:`, `regexp:` (which must compile with `regexp`), `geosite:` or `ext:`, or have no prefix (xray's substring match).
  - IP entries are a CIDR or an address (`netip`) of either family, or `geoip:<code>`.

- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/store/`. Expected: PASS.

- [ ] **Step 5: Commit**

  `git add internal/store && git commit -m "Add the desired-state model and its validation"`

### Task 2: Versioned state files

**Files:**
- Create: `internal/store/store.go`, `internal/store/migrate.go`
- Test: `internal/store/store_test.go`

**Interfaces:**
- Consumes: Task 1 `State`, `Default`, `Validate`, `Clone`.
- Produces:
  - `const Current = 1`
  - `var ErrConflict = errors.New("store: the state changed since it was read")`
  - `type Store struct{ ... }`
  - `func Open(dir string) (*Store, error)`
  - `func (s *Store) State() (State, uint64)`: a clone and its revision.
  - `func (s *Store) Update(rev uint64, fn func(*State) error) (State, uint64, error)`. A `rev` of 0 skips the check; any other value that isn't the current revision gives `ErrConflict`. fn changes a clone. The result must pass `Validate`; it is then written as revision+1 and swapped in. When fn or `Validate` fails, nothing is written and the error comes back as it was.
  - The file format is `{"version": <N>, "revision": <R>, "state": {...}}`, indented with two spaces and ending in a newline.
  - Unexported, for the tests: `openWith(dir string, current int, migrations map[int]migration) (*Store, error)` and `type migration func(json.RawMessage) (json.RawMessage, error)`. A migration turns the `state` of version N into that of N+1.

- [ ] **Step 1: Write the failing tests** in `internal/store/store_test.go`:
  - `TestOpenEmptyDir`: Open on a missing dir creates it with mode 0700 and gives `Default()` at revision 0. No file is written until the first Update.
  - `TestUpdateWritesAtomically`: Update adds a server. Then:
    - `state.v1.json` exists with mode 0600, `version` 1 and `revision` 1;
    - a second `Open` reads the same state;
    - no temp files are left in the dir.
  - `TestUpdateConflict`: Update with a stale revision returns `ErrConflict` and leaves the file unchanged.
  - `TestUpdateInvalidWritesNothing`: an fn that makes the state invalid returns the validation error. The file and `State()` are unchanged.
  - `TestUpdateFnError`: an fn error is returned unchanged, and nothing is written.
  - `TestCorruptFileIsAnError`: a `state.v1.json` holding `{` makes Open fail, and the file stays byte-for-byte the same. A file that parses but fails `Validate` also fails Open.
  - `TestMigrates`: `openWith(dir, 2, {1: addFieldMigration})` over a v1 file:
    - writes `state.v2.json`, keeping the revision;
    - leaves the v1 file byte-for-byte unchanged;
    - loads the migrated state.
  - `TestIgnoresNewer`: with `state.v1.json` and `state.v3.json` present, `openWith(dir, 2, {1: m})` migrates v1 to v2 and leaves `state.v3.json` unchanged. With `state.v2.json` also present, it loads v2 and migrates nothing.
  - `TestMissingMigration`: `openWith(dir, 3, {1: m})` over a v1 file errors, naming the missing step 2→3.
  - `TestIgnoresOtherFiles`: Open skips `state.v1.json.tmp-123`, `state.vX.json` and `notes.txt`.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/store/ -run 'Open|Update|Corrupt|Migrat|Ignore'`. Expected: FAIL to compile.

- [ ] **Step 3: Implement.**
  - Write a temp file in the same dir, then fsync, rename and fsync the dir. This is the same pattern as M1's `writeFileAtomic` in `internal/artifacts`; copy it, don't import it.
  - Only `state.v<N>.json` with N a positive decimal counts as a state file.
  - Open loads the highest N ≤ current. It migrates step by step up to current, writes `state.v<current>.json` if a migration ran, and validates the result.
  - The mutex is held across the write. One process writes the state; this is documented on `Store`.

- [ ] **Step 4: Run the tests**

  Run: `go test -race ./internal/store/`. Expected: PASS.

- [ ] **Step 5: Commit**

  `git add internal/store && git commit -m "Keep the state in versioned files with atomic writes"`

### Task 3: Share links: VLESS and Trojan

**Files:**
- Create: `internal/sharelink/sharelink.go`, `internal/sharelink/stream.go`, `internal/sharelink/vless.go`, `internal/sharelink/trojan.go`
- Test: `internal/sharelink/vless_test.go`, `internal/sharelink/trojan_test.go`

**Interfaces:**
- Produces:
  - `type Server struct{ Name string; Outbound json.RawMessage }`. `Outbound` is an xray outbound object without `tag`, marshalled from maps so its keys are sorted. (changed: it also has `Warnings []string`, notes for the user, nil when there are none; R3.)
  - `var ErrUnsupported = errors.New("sharelink: unsupported")`, wrapped by every refusal of a valid but unsupported link.
  - `func Parse(link string) (Server, error)` dispatches on the scheme, case-insensitively. This task wires up `vless` and `trojan`; Task 4 adds `vmess` and `ss`. Any other scheme gives `ErrUnsupported`.
  - Unexported, also used by Task 4: `type stream struct{ Network, Security, SNI, Fingerprint, ALPN, PublicKey, ShortID, SpiderX, Host, Path, ServiceName, Authority, Mode, HeaderType string; AllowInsecure bool }`, `func streamFromQuery(q url.Values, defaultSecurity string) stream`, `func (s stream) settings() (map[string]any, error)` and `func name(fragment, host string, port int) string`. (changed: the stream also has `PinnedCertSHA256` and `VerifyCertByName`, from `pcs` and `vcn`, and `warnings()` gives the insecure-link warning; R3.)
- Rules (xray 26 field names):
  - **Name:** the fragment, URL-decoded and trimmed, cut to 128 runes. Empty means `host:port`.
  - **Host and port:** the host may be an IPv6 literal in brackets; the address is written without them. The port must be 1–65535.
  - **`type`, the network:**
    - `tcp` (also `raw` or empty) → `"network":"tcp"`. `headerType=http` adds `tcpSettings.header {type: http, request: {path: [path or "/"], headers: {Host: [host]}}}`, and the `Host` key is left out when host is empty.
    - `ws` → `wsSettings {path (default "/"), host}`.
    - `grpc` → `grpcSettings {serviceName, authority, multiMode: mode=="multi"}`.
    - `httpupgrade` → `httpupgradeSettings {path, host}`.
    - `xhttp` (also `splithttp`) → `"network":"xhttp"` with `xhttpSettings {path, host, mode (default "auto")}`.
    - `kcp`, `quic`, `h2` and `http` → `ErrUnsupported`.
    - Empty string fields are left out of every settings object.
  - **`security`:**
    - `none` (or empty, unless the scheme's default applies): no TLS settings at all.
    - `tls` → `tlsSettings {serverName: sni, fingerprint: fp, alpn: split(alpn, ","), allowInsecure: true}`. `allowInsecure` appears only when `allowInsecure` or `insecure` is `1` or `true`.
      (changed: `allowInsecure` is never emitted, since xray ≥26.3.27 refuses the whole config with it once past 2026-06-01. `pcs` maps to `pinnedPeerCertSha256` and `vcn` to `verifyPeerCertByName`. A link asking for `allowInsecure`/`insecure` parses with verification on and a warning in `Server.Warnings`, with no warning when `pcs` is present; R3.)
      (changed: with no `sni`, `serverName` is the first comma-separated `host` value, as in v2rayN; Reality keeps `sni` only; R7.)
    - `reality` → `realitySettings {serverName: sni, fingerprint: fp or "chrome", publicKey: pbk, shortId: sid, spiderX: spx}`. pbk is required. The network must be tcp, grpc or xhttp.
    - Anything else gives an error.
  - **VLESS:** `vless://<id>@<host>:<port>?<query>#<name>` → `{"protocol":"vless","settings":{"vnext":[{"address":H,"port":P,"users":[{"id":ID,"encryption":E,"flow":F}]}]},"streamSettings":S}`.
    - E is the `encryption` parameter, `"none"` when empty, and passed through as it is (VLESS post-quantum encryption).
    - `flow` is left out when empty.
    - The id must be non-empty.
  - **Trojan:** `trojan://<password>@<host>:<port>?<query>#<name>` → `{"protocol":"trojan","settings":{"servers":[{"address":H,"port":P,"password":PW}]},"streamSettings":S}`.
    - The password is URL-decoded.
    - `security` defaults to `tls` when the parameter is absent.

- [ ] **Step 1: Write the failing table tests.** Each case is a link and its exact expected outbound JSON (compared after a canonical re-marshal), or the error it must wrap. The VLESS cases:
  - Reality and Vision: `vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#lab%20%F0%9F%9A%80`. It must give name `lab 🚀` and:
    ```json
    {"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"encryption":"none","flow":"xtls-rprx-vision","id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},"streamSettings":{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","serverName":"www.example.com","shortId":"6ba85179e30d4fc2"},"security":"reality"}}
    ```
  - WebSocket and TLS, with an encoded path: `...@[2001:db8::1]:8443?type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com&path=%2Fws%3Fed%3D2048&alpn=h2,http/1.1#` gives:
    - address `2001:db8::1`, name `[2001:db8::1]:8443`;
    - `wsSettings {"host":"cdn.example.com","path":"/ws?ed=2048"}`;
    - `tlsSettings.alpn ["h2","http/1.1"]`.
  - gRPC multi: `type=grpc&serviceName=gun&mode=multi&security=tls`.
  - xhttp: `type=xhttp&path=/x&mode=packet-up`, and `type=splithttp`, which gives network `xhttp`.
  - `type=raw&security=` gives network `tcp` and no `security` key.
  - Rejected: `type=kcp` (`ErrUnsupported`), reality without `pbk`, reality with `type=ws`, port `0` or `70000`, an empty id, and `security=foo`.
  The Trojan cases:
  - `trojan://p%40ss@example.com:443?sni=example.com#t` gives password `p@ss` and `security` `tls`.
  - `trojan://pw@1.2.3.4:443?security=none&type=ws&path=/t` gives no TLS settings.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/sharelink/`. Expected: FAIL to compile.

- [ ] **Step 3: Implement** `Parse` (dispatch), the stream helpers, VLESS and Trojan. Use `net/url`. The fragment is `u.Fragment` (already decoded); query values come from `u.Query()`.

- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/sharelink/`. Expected: PASS.

- [ ] **Step 5: Commit**

  `git add internal/sharelink && git commit -m "Parse VLESS and Trojan share links into xray outbounds"`

### Task 4: Share links: VMess, Shadowsocks and fuzzing

**Files:**
- Create: `internal/sharelink/vmess.go`, `internal/sharelink/ss.go`
- Modify: `internal/sharelink/sharelink.go` (dispatch `vmess`, `ss`)
- Test: `internal/sharelink/vmess_test.go`, `internal/sharelink/ss_test.go`, `internal/sharelink/fuzz_test.go`

**Interfaces:**
- Consumes: Task 3 `Server`, `ErrUnsupported`, `stream`, `name`.
- Produces: `Parse`, which now handles all four schemes.
- **VMess:** `vmess://<base64 of a JSON object>`. Standard or URL alphabet, padding optional.
  - The fields are `ps` (name), `add`, `port` (a number or a string), `id`, `aid`, `scy`, `net`, `type` (header type), `host`, `path`, `tls`, `sni`, `alpn`, `fp` and `allowInsecure`.
  - `aid` other than 0 or absent gives `ErrUnsupported`: xray dropped legacy alterId.
  - `scy` defaults to `auto`. It must be one of `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` or `zero`.
  - `tls` is `tls` or empty/`none`.
  - The output is `{"protocol":"vmess","settings":{"vnext":[{"address":A,"port":P,"users":[{"id":ID,"security":SCY}]}]},"streamSettings":S}`, where S comes from the same `stream`. (changed: the JSON's `allowInsecure` gives the same warning as in Task 3 and is never emitted; R3.)
  - The URL form `vmess://uuid@host:port?...` gives `ErrUnsupported`.
  - (changed: a `#name` after the base64 body parses, and names the server when `ps` is empty; a `?…` after the body is still refused; R6.)
- **Shadowsocks:**
  - SIP002, `ss://<userinfo>@<host>:<port>[/][?plugin=...]#name`. The userinfo is base64url (padding optional) of `method:password`, or the percent-encoded `method:password` that 2022 ciphers use.
  - Legacy: `ss://<base64 of method:password@host:port>#name`.
  - Any `plugin` parameter gives `ErrUnsupported`.
  - Methods allowed:
    - `aes-128-gcm`, `aes-256-gcm`;
    - `chacha20-poly1305`, also accepted as `chacha20-ietf-poly1305` (emitted as `chacha20-poly1305`);
    - `xchacha20-poly1305`, also accepted as `xchacha20-ietf-poly1305`;
    - `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`;
    - `none`.
    Any other method gives `ErrUnsupported`. (changed: since Task 8b, `none` and 2022 keys that xray refuses give `ErrUnsupported` too.)
  - The output is `{"protocol":"shadowsocks","settings":{"servers":[{"address":A,"port":P,"method":M,"password":PW}]}}`. (changed: SS links honour the shared stream parameters, `type`, `security` and the rest, by Task 3's rules with security `none` by default; `streamSettings` is added only when the stream asks for more than plain TCP without TLS, so plain links keep this exact output; R5.)

- [ ] **Step 1: Write the failing tests.**
  - VMess:
    - a ws+tls link whose JSON has `"port":"443"` (a string), `"aid":"0"` and `ps` `"سرور"` gives name `سرور`, port 443 and `security` `auto`;
    - a URL-alphabet unpadded body gives the same result;
    - `aid` 64 gives `ErrUnsupported`;
    - a body that is not JSON is an error.
  - Shadowsocks:
    - `ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#a` (SIP002, unpadded) gives method `aes-256-gcm`, password `pass`;
    - the same with padding;
    - `ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@h.example:443#b` (percent-encoded) gives password `YWJjZGVmZ2hpamtsbW5vcA==`;
    - the legacy `ss://YWVzLTEyOC1nY206cEBzc0Bob3N0LmV4YW1wbGU6ODM4OA==#c` gives password `p@ss`, host `host.example` and port 8388 (the last `@` splits);
    - `?plugin=obfs-local` gives `ErrUnsupported`;
    - method `rc4-md5` gives `ErrUnsupported`.
  - `FuzzParse` is seeded with every link in the Task 3 and 4 tables. It must never panic. When it returns no error:
    - `Outbound` unmarshals to an object with a non-empty string `protocol` and no `tag`;
    - `Name` is non-empty and at most 128 runes.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/sharelink/`. Expected: FAIL.

- [ ] **Step 3: Implement** VMess and Shadowsocks, and add both to `Parse`.

- [ ] **Step 4: Run the tests and a short fuzz**

  Run:
  - `go test ./internal/sharelink/`. Expected: PASS.
  - `go test ./internal/sharelink/ -run '^$' -fuzz FuzzParse -fuzztime 60s`. Expected: no failures. Commit any crasher the fuzzer finds as a seed in `testdata/fuzz`, with its fix.

- [ ] **Step 5: Commit**

  `git add internal/sharelink && git commit -m "Parse VMess and Shadowsocks share links and fuzz the parsers"`

### Task 5: Subscriptions: decode, merge and fetch

**Files:**
- Create: `internal/subscription/subscription.go`, `internal/subscription/fetch.go`
- Modify: `internal/artifacts/fetch.go`: export one constructor, `HTTPClient` (below)
- Test: `internal/subscription/subscription_test.go`, `internal/subscription/fetch_test.go`

**Interfaces:**
- Consumes:
  - Task 1 `store.Server`, `store.NewID`;
  - Task 4 `sharelink.Parse`, `sharelink.Server`;
  - M1's bounded transport in `internal/artifacts/fetch.go` (`newTransport`).
- Produces:
  - In `artifacts`: `func HTTPClient(socksAddr string, timeout time.Duration) *http.Client`. It uses `newTransport`'s bounds (dial 30 s, TLS 20 s, response headers 30 s). An empty `socksAddr` means direct. Otherwise it goes through SOCKS5 at that address, which resolves names (the same dialer `Proxy` uses).
  - `func Decode(body []byte) []string`: the share links in a body.
    - The body is base64 (standard or URL alphabet, padding optional, line breaks and spaces ignored) of a list, or the plain list itself.
    - Lines are trimmed. Blank lines and lines without `://` are dropped.
  - `type Entry struct{ Link string; Server sharelink.Server }`
  - `type Skipped struct{ Line, Err string }`. `Line` is cut to 80 runes.
  - `type Result struct{ Entries []Entry; Skipped []Skipped }`
  - `func Parse(body []byte) Result`: `Decode`, then `sharelink.Parse` on each link. Duplicate links keep the first.
  - `func Merge(servers []store.Server, subID string, entries []Entry) []store.Server`:
    - It replaces the servers whose `Subscription == subID` with entries, in subscription order. They go where the first old one was, or at the end.
    - A server whose `Link` is unchanged keeps its `ID` and `Disabled`, and takes the entry's `Name` and `Outbound`.
    - New links get `store.NewID()`, avoiding every ID already in `servers`.
    - Every other server is left exactly where it was.
    - `Merge` never touches `Routing`. A caller that removes a pinned server, or one a rule names, must fix those references before `store.Update` (M2b's refresh does).
  - `type Fetcher struct{ Direct, Proxy *http.Client; ProxyHealthy func(context.Context) bool; MaxBytes int64; UserAgent string }`. `MaxBytes` 0 means 8 MiB, and an empty `UserAgent` means `tikray`.
  - `func (f Fetcher) Fetch(ctx context.Context, rawURL string) (body []byte, via string, err error)`:
    - only `http` and `https` URLs;
    - a 2xx answer is required, and a body over `MaxBytes` is an error;
    - `via` is `direct` or `proxy`. It tries direct first, then the proxy when `Proxy` isn't nil and `ProxyHealthy` says yes;
    - when both fail, the error names both.

- [ ] **Step 1: Write the failing tests.**
  - `TestDecode`: the same three links decode the same from:
    - the plain list, with CRLF line ends;
    - standard base64 with padding;
    - URL-alphabet base64 without padding;
    - base64 wrapped at 76 columns.
    A `#comment` line and blank lines are dropped.
  - `TestParseSkipsBadLines`: a body with two good links, `vmess://!!!` and `http://x` gives 2 entries. The bad VMess line is in `Skipped` with its error, and the `http` line is skipped as an unsupported scheme.
  - `TestMergeKeepsIDs`: start with a manual server M, subscription `s1` servers A (disabled) and B, and subscription `s2` server C. Merge `s1` with B′ (B's link, new name), D and A. The result is:
    - M first;
    - then B with B's ID and the new name, D with a new unique ID, and A with A's ID, still disabled;
    - then C, unchanged.
  - `TestMergeEmptyRemoves`: merging an empty entry list removes that subscription's servers only.
  - `TestFetch` (httptest servers):
    - direct succeeds → `via` `direct`;
    - direct returns 500 and the proxy client succeeds (a second httptest server stands in for the proxy) → `via` `proxy`;
    - `ProxyHealthy` false → the direct error alone;
    - a body of `MaxBytes`+1 is an error;
    - `ftp://` is refused before any request;
    - the request carries `User-Agent: tikray`.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/subscription/`. Expected: FAIL to compile.

- [ ] **Step 3: Implement** `subscription.go`, `fetch.go` and `artifacts.HTTPClient`. Merge is a single ordered pass.

- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/subscription/ ./internal/artifacts/`. Expected: PASS.

- [ ] **Step 5: Commit**

  `git add internal/subscription internal/artifacts/fetch.go && git commit -m "Decode, merge and fetch subscriptions"`

### Task 6: Render: compatibility table, inbounds, outbounds and balancers

**Files:**
- Create: `internal/render/render.go`, `internal/render/compat.go`, `internal/render/xray.go` (the typed subset of xray's config that render writes)
- Test: `internal/render/render_test.go`, `internal/render/compat_test.go`

**Interfaces:**
- Consumes:
  - Task 1 `store.State` and its types;
  - M1 `xrayver.Version`, `xrayver.Parse`, `xrayver.MinTUN`.
- Produces:
  - `type Geo struct{ Version string; Site, IP []string }`: the active geo slot and its domestic matchers, such as `geosite:category-ir` and `geoip:ir`.
  - `type Input struct{ State store.State; Core xrayver.Version; Geo *Geo }`. A nil `Geo` means no geo data.
  - `func Render(in Input) ([]byte, error)`. The output is canonical: `json.MarshalIndent` with two-space indent, plus a trailing newline. The same input always gives the same bytes.
  - Tag constants: `TagTUN = "tun-in"`, `TagDNSIn = "dns-in"`, `TagSOCKS = "socks-in"`, `TagAPIIn = "api-in"`, `TagBlock = "block"`, `TagDirect = "direct"`, `TagDNSOut = "dns-out"`, `TagAPI = "api"`, `TagDNS = "dns-internal"`, `BalancerOpen = "proxy-open"`, `BalancerClosed = "proxy-closed"`, `ServerPrefix = "srv-"`.
  - Port constants: `SOCKSPort = 1080`, `APIPort = 10085`, `DNSPort = 53`.
  - `func ProxyAvailable(st store.State) bool`: whether the balancers have a member. That is any enabled server, or, when one is pinned, the pinned server being enabled.
  - Compatibility, in `compat.go`:
    - `type Feature struct{ Name string; Min xrayver.Version }`;
    - `var Features = []Feature{{"TUN inbound", xrayver.MinTUN}}`;
    - `func Check(v xrayver.Version) error`: an error naming the newest feature that v is older than;
    - `var Tested = [2]xrayver.Version{{26, 1, 18}, {26, 10, 21}}` and `func IsTested(v xrayver.Version) bool`, inclusive. The UI labels anything else "untested" (§4.9).
- What this task renders. Rules, DNS servers and the use of policies are Task 7's. This task leaves `routing.rules` holding only the service rules below.
  - **Inbounds, in this order:**
    - `tun-in`: `{"protocol":"tun","settings":{"name":"xray0","mtu":1500},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}}`.
    - `dns-in`: dokodemo-door on `<runner>:53`, `"settings":{"address":A,"port":53,"network":"tcp,udp"}`. A is the DNS remote when that is an IPv4 address, otherwise `1.1.1.1`. With `nonIPQuery: reject` nothing is forwarded to it; the field is just required.
    - `socks-in`: socks on `<runner>:1080`, `{"auth":"noauth","udp":false}`.
    - `api-in`: dokodemo-door on `<runner>:10085`, `{"address":"127.0.0.1"}`.
  - **Outbounds, in this order:**
    - `block` (blackhole) comes first: xray's default outbound is the first one, so traffic no rule catches is blocked, never sent direct;
    - `direct` (freedom);
    - `dns-out`: `{"protocol":"dns","settings":{"nonIPQuery":"reject"}}`;
    - then each enabled server's outbound with `"tag": "srv-<id>"` added, in state order.
  - **Top level:**
    - `log {"loglevel":"warning"}`;
    - `api {"tag":"api","services":["HandlerService","RoutingService","StatsService","ObservatoryService"]}`; (changed: `ObservatoryService` is listed only with the observatory, since xray refuses to start the service without one, "not all dependencies are resolved"; R9.)
    - `stats {}`;
    - `policy {"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}}`.
  - **When `ProxyAvailable`:**
    - `observatory {"subjectSelector":[SEL],"probeURL":<health.probe_url>,"probeInterval":"10s","enableConcurrency":true}`;
    - `routing.balancers`: `proxy-open` and `proxy-closed`, each `{"selector":[SEL],"strategy":{"type":"leastPing"}}`, with `fallbackTag` `direct` and `block` respectively.
    - SEL is `srv-` (the prefix of every enabled server), or the full tag `srv-<pinned>` when one is pinned. IDs have a fixed length, so that prefix matches no other server.
    When the balancers have no member, both are omitted along with the observatory. Every reference to `proxy-open` becomes `"outboundTag":"direct"`, and every reference to `proxy-closed` becomes `"outboundTag":"block"`. Task 7 routes through one helper that does this.
  - **Service rules, first in `routing.rules`:**
    1. `{"inboundTag":["api-in"],"source":["<tikray>/32","<runner>/32"],"outboundTag":"api"}`
    2. `{"inboundTag":["api-in"],"outboundTag":"block"}`
    3. `{"inboundTag":["dns-in"],"outboundTag":"dns-out"}`
    4. `{"inboundTag":["socks-in"],"source":["<tikray>/32"], → proxy-closed}`: tikray's probes and proxied fetches must never pass by going direct.
    5. `{"inboundTag":["socks-in"],"outboundTag":"block"}`
  - **Errors:**
    - `Check(in.Core)`;
    - `in.State.Validate()`;
    - any server outbound that isn't a JSON object.

- [ ] **Step 1: Write the failing tests.**
  - `TestCheck`: 26.1.17 is an error naming the TUN inbound; 26.1.18 and 27.0.0 pass.
  - `TestIsTested`: 26.1.18 and 26.10.21 are true; 26.1.17 and 26.10.22 are false.
  - `TestProxyAvailable` covers:
    - no servers;
    - one disabled server;
    - one enabled server;
    - pinned to a disabled server while another is enabled (false);
    - pinned to an enabled server.
  - `TestRenderSkeleton`:
    - Render `Default()` with one enabled VLESS server `a1b2c3d4` (the Task 3 Reality outbound), default policy `smart`, core 26.10.21 and no geo.
    - Unmarshal it and assert:
      - the inbound tags, in order;
      - the outbound tags, in order, with `block` first;
      - `srv-a1b2c3d4` equal to the server outbound plus its tag;
      - the observatory and balancers as above;
      - `routing.rules` starting with the five service rules, with `172.31.255.2/32` and `172.31.255.3/32`. Task 7 appends after them, so assert on that prefix, not on the length;
      - the three listen addresses `172.31.255.3`.
  - `TestRenderNoServers`: there is no observatory and no `balancers`, and socks rule 4 is `"outboundTag":"block"`.
  - `TestRenderPinned`: pinned to `a1b2c3d4` beside a second enabled server: SEL is `srv-a1b2c3d4` in the observatory and in both balancers.
  - `TestRenderDisabledServerOmitted`: a disabled server has no outbound.
  - `TestRenderDeterministic`: two renders of the same input are byte-identical.
  - `TestRenderSubnet`: subnet `10.9.8.0/29` moves every address (`10.9.8.2/32`, `10.9.8.3`).
  - `TestRenderRefusesOldCore`: 26.1.17 is an error.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/render/`. Expected: FAIL to compile.

- [ ] **Step 3: Implement.**
  - In `xray.go`, typed structs with `omitempty` model just the keys render writes.
  - Server outbounds go in as `json.RawMessage`, with the tag added by unmarshalling to `map[string]json.RawMessage`, setting `tag` and marshalling again (sorted keys).
  - `Render` builds the struct, then marshals.
  - One unexported helper picks the target of each balancer reference: `func (r *renderer) via(balancer string) rule`. It sets `balancerTag`, or the fallback `outboundTag` when the balancers are absent.

- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/render/`. Expected: PASS.

- [ ] **Step 5: Commit**

  `git add internal/render && git commit -m "Render xray's inbounds, outbounds and balancers from the state"`

### Task 7: Render: policies, routing rules and DNS

**Files:**
- Create: `internal/render/rules.go`, `internal/render/dns.go`
- Modify: `internal/render/render.go`: append the rules after the service rules, and add the DNS section
- Test: `internal/render/rules_test.go`, `internal/render/dns_test.go`

**Interfaces:**
- Consumes: Task 6 `Render`, `Input`, `Geo`, tags, and the `via` helper; Task 1 types.
- Produces: `Render` with `routing.rules` and `dns` complete. No new exported names.
- **The source sets:**
  - The explicit devices fall into five sets of CIDRs: `SO`/`SC` (smart, kill switch off/on), `FO`/`FC` (full, off/on), and direct devices, which are never used.
  - `D` is the default policy. It covers every address no device lists.
  - All traffic rules below carry `"inboundTag":["tun-in"]`.
  - A rule whose `source`, `domain` or `ip` list would be empty is not emitted.
- **The domestic matchers:**
  - `DD` (domains) is `Geo.Site`, when geo is set, followed by `Routing.Domestic.Domains`.
  - `DI` (IPs) is `Geo.IP` followed by `Routing.Domestic.IPs`.
  - A `geosite:` or `geoip:` matcher anywhere in the state while `Geo` is nil is an error, naming the field: xray would fail its `-test` without the `.dat` files.
- **The traffic rules, in order (§5.3):**
  1. **Block list:** `{"domain": BlockList, "outboundTag":"block"}`.
  2. **Full sources, which skip the domestic rules:** `{"source": FO} → via(proxy-open)`, then `{"source": FC} → via(proxy-closed)`.
  3. **Domestic domains → `direct`:**
     - when `D.Mode` is `full`, one rule `{"source": SO∪SC, "domain": DD}`, so the unlisted, who are full, skip it;
     - otherwise `{"domain": DD}`.
  4. **Domestic IPs → `direct`:** the same as 3, with `"ip": DI`.
  5. **Custom rules, in state order.** Full traffic skips them, as it skips the domestic rules: when `D.Mode` is `full`, every rule below also carries `"source": SO∪SC`, and when it has a source set of its own, the intersection of the two. A rule whose intersection is empty is dropped. Each rule's own matchers come from its `Domains` and `IPs`; a rule with both becomes two xray rules, one for its domains and one for its IPs, since an xray rule needs both to match.
     - `direct` → `outboundTag: "direct"`; `block` → `"block"`.
     - `server` → `"srv-<id>"`. While that server is disabled, the rule is skipped and its traffic falls through.
     - `proxy`:
       - when the unlisted are on the kill switch (`D.KillSwitch`), first `{matchers, "source": SO} → via(proxy-open)`, then `{matchers} → via(proxy-closed)`;
       - otherwise first `{matchers, "source": SC} → via(proxy-closed)`, then `{matchers} → via(proxy-open)`.
  6. **Final:**
     - when `D.Mode` is `direct`: `{"source": SC} → via(proxy-closed)`, `{"source": SO} → via(proxy-open)`, then `{"network":"tcp,udp","outboundTag":"direct"}`;
     - when `D.KillSwitch`: `{"source": SO∪FO} → via(proxy-open)`, then `{"network":"tcp,udp"} → via(proxy-closed)`;
     - otherwise: `{"source": SC∪FC} → via(proxy-closed)`, then `{"network":"tcp,udp"} → via(proxy-open)`.
     A full device is caught by rule 2 before it gets here; the final rules list it anyway, so their meaning doesn't depend on rule 2.
- **DNS (§5.4):**
  - `dns` is `{"tag":"dns-internal","queryStrategy":"UseIPv4","servers":[...]}`.
  - The domestic resolver R is `DNS.Domestic`, or the router's bridge address when that is zero.
  - When `DD` isn't empty, the first server is `{"address":R,"domains":DD,"skipFallback":true}`.
  - The last server is `DNS.Remote` as a string: a DoH URL, or an IPv4 address for plain DNS.
  - Two rules go right after the service rules, before the traffic rules:
    - `{"inboundTag":["dns-internal"],"ip":["R/32"],"outboundTag":"direct"}`, only when `DD` isn't empty; (changed: it also matches `"port":"53"`, so DoH to the same host still goes through `proxy-open`, and `store.Validate` refuses a plain-IPv4 `DNS.Remote` equal to R; R10.)
    - `{"inboundTag":["dns-internal"]} → via(proxy-open)`.
  - (changed: Render also refuses a `Geo` whose `Site` entry isn't `geosite:<code>` or whose `IP` entry isn't `geoip:<code>`: an empty or plain entry would match every domain or address; R11.)

- [ ] **Step 1: Write the failing tests.** The cases are table-driven, with assertions on the unmarshalled `routing.rules` and `dns`:
  - `TestRulesDefaultSmart`: default smart; no devices; one server; domestic extras `domain:domestic.test` and `203.0.113.20/32`; one block-list entry. The traffic rules are exactly:
    - block list;
    - domestic domain;
    - domestic IP;
    - final `proxy-open`.
    There is no source rule.
  - `TestRulesKillSwitchDefault`: default smart with the kill switch, and device `192.168.88.10/32` smart without it. The final rules are `{"source":["192.168.88.10/32"]} → proxy-open`, then catch-all → `proxy-closed`.
  - `TestRulesFullDefault`: default full, with smart devices `192.168.88.20/32` (open) and `.21/32` (kill switch). The domestic rules carry `"source":["192.168.88.20/32","192.168.88.21/32"]`. The final rules are `{"source":["192.168.88.21/32"]} → proxy-closed`, then catch-all → `proxy-open`.
  - `TestRulesFullDevices`: default smart, with full devices `.30/32` (open) and `.31/32` (kill switch). Rule 2's two rules come before the domestic rules.
  - `TestRulesCustom`: one rule of each action. `proxy` gives the two-rule pair. A `server` rule naming a disabled server is skipped. A rule with both domains and IPs gives two rules.
  - `TestRulesDirectDefault`: default direct, with devices SO and SC. The last rule is catch-all → `direct`, after two source rules.
  - `TestRulesNoServers`: default smart with the kill switch, and no servers. Every `via` became an outbound: final catch-all → `block`, and SO → `direct`.
  - `TestRulesGeo`: geo with `Site: ["geosite:category-ir"]` and `IP: ["geoip:ir"]` gives DD and DI starting with those. A state using `geosite:` with no geo is an error naming `routing.block_list[0]`.
  - `TestDNS`:
    - DD empty: one server, and only the `proxy-open` DNS rule;
    - DD set: the domestic server first, with `skipFallback`, and the `R/32` direct rule;
    - `DNS.Domestic` set: R is that address;
    - remote `203.0.113.53`: servers end with `"203.0.113.53"`, and the `dns-in` address is `203.0.113.53`.
  - `TestNoEmptyMatchers`: over every case above, and over 500 states from a seeded generator (random devices in all five sets, random default, random rules, 0–3 servers, some disabled, sometimes pinned), no rule anywhere has an empty `source`, `domain` or `ip` key present.
  - `TestKillSwitchNeverDirect`: for the same generated states, walk the rules in order with a probe connection:
    - its source is in SC, in FC, or (when `D.KillSwitch` is on) unlisted;
    - it arrives on `tun-in`, over tcp.
    The generator draws every domain matcher from `domain:g<N>.test` and every IP from `10.200.<N>.0/24`, so the probe's destination matches none of them, and the walker treats a rule with a `domain` or `ip` key as not matching. The first rule that matches the probe must never be `"outboundTag":"direct"`, nor `proxy-open`, whose fallback is `direct`.
    Add a test that the walker itself catches a deliberately broken final rule.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/render/`. Expected: FAIL.

- [ ] **Step 3: Implement** `rules.go` and `dns.go` as specified. The source sets are built once, sorted by address, with `netip.Prefix.String()`.

- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/render/`. Expected: PASS.

- [ ] **Step 5: Commit**

  `git add internal/render && git commit -m "Render the policies, routing rules and DNS"`

### Task 8: Golden scenarios and the xray compatibility matrix

**Files:**
- Create:
  - `internal/render/golden_test.go`;
  - `internal/render/testdata/<scenario>.state.json` and `<scenario>.xray.json`;
  - `test/compat/compat_test.go`, `test/compat/geodat.go`, `test/compat/doc.go`.
- Modify:
  - `test/lab/xray.go`: add `ReleaseTags`;
  - `.github/workflows/ci.yml`: a `compat` job.
- Test: the files above.

**Interfaces:**
- Consumes:
  - Task 7 `Render`;
  - M0's `lab.XrayBinaryVersion(ctx, cacheDir, version, goarch)`, `lab.CacheDir()`, `lab.ResolveXrayVersion`.
- Produces:
  - `func ReleaseTags(ctx context.Context) ([]string, error)` in `test/lab`: XTLS release tags (`vYY.M.D`), newest first, pre-release and `v1.*` tags skipped. It uses the same `git ls-remote` source as `latestReleaseTag`.
  - `test/compat` (build tag `compat`) runs `xray run -test` on every golden config.
  - `func writeGeoDat(dir string, sites, ips map[string][]string) error` (unexported) writes a minimal `geosite.dat` and `geoip.dat` (protobuf `GeoSiteList` / `GeoIPList`, encoded with `google.golang.org/protobuf/encoding/protowire`) holding the codes the golden configs name.
- Scenarios, each a `.state.json` whose geo and core are in a header field the test reads (`{"core":"26.10.21","geo":{...}|null,"state":{...}}`):
  - `empty`: defaults, no servers;
  - `smart-one-server`;
  - `pinned-two-servers`;
  - `kill-switch-default`;
  - `full-default`;
  - `full-devices`;
  - `custom-rules`;
  - `geo-domestic`: geo `geosite:category-ir`, `geoip:ir`;
  - `plain-dns`: remote `203.0.113.53`, domestic `203.0.113.54`;
  - `all-protocols`: one server per protocol and transport from the Task 3–4 tables.

- [ ] **Step 1: Write the golden test.** `TestGolden` renders each scenario and compares it with `<scenario>.xray.json`. With `-update`, it writes the files instead.

- [ ] **Step 2: Run it to see it fail**, then generate.

  Run: `go test ./internal/render/ -run TestGolden`. Expected: FAIL (no golden files).

  Run: `go test ./internal/render/ -run TestGolden -update`, then `go test ./internal/render/ -run TestGolden`. Expected: PASS.

  Read every generated file against Tasks 6 and 7 before committing. A golden file encodes the spec; it is reviewed, not just generated.

- [ ] **Step 3: Write `test/compat`.** `TestXrayAcceptsGolden`:
  - The versions are `26.1.18` (the oldest supported), latest−1 and latest, from `ReleaseTags`. `TIKRAY_COMPAT_VERSIONS`, a comma list, overrides them.
  - For each version, for each golden config:
    - write it and the geo `.dat` files to a temp dir;
    - run `<xray> run -test -c <file>` with `XRAY_LOCATION_ASSET=<dir>`;
    - fail with xray's output on a non-zero exit.
  - Releases before 26.10 open the TUN during `-test`, so the test needs root. As non-root it skips, and `TIKRAY_COMPAT_REQUIRED=1` turns that skip into a failure.
  - Configs run one at a time; they all name `xray0`.

- [ ] **Step 4: Run it** (this environment is root):

  Run: `go test -tags compat -count=1 -timeout 60m ./test/compat/...`. Expected: PASS for all three versions.

  If `nonIPQuery: "reject"` is refused by a version, add a `Features` entry with the first version that accepts it, render `"drop"` below it, add a golden scenario for the older core, and record a `Ruling:` line. Do the same for any other key a version refuses.

- [ ] **Step 5: Add the CI job.** Job `compat` in `ci.yml`:
  - checkout and setup-go;
  - `actions/cache` for `~/.cache/tikray-lab/xray`, keyed by `hashFiles('test/lab/xray.go')`;
  - run `sudo --preserve-env=PATH,HOME,GOPATH,GOMODCACHE,GOCACHE,TIKRAY_COMPAT_REQUIRED go test -tags compat -count=1 -timeout 60m ./test/compat/...` with `TIKRAY_COMPAT_REQUIRED: "1"`.

  Then run `go vet -tags compat ./...`. Expected: clean.

- [ ] **Step 6: Commit**

  `git add internal/render test/compat test/lab/xray.go .github/workflows/ci.yml && git commit -m "Pin render with golden scenarios and test them against xray releases"`

### Task 8b: Refuse outbounds the newest xray refuses

(changed: inserted during execution, by ruling R12, after Task 8's compat run found that xray-core 26.7.11 and newer refuse a whole config that holds one of these outbounds. Its brief is `.superpowers/sdd/2026-10-25-m2a-state-and-render/task-8b-brief.md`.)

- Create: `internal/xraypolicy` with `Check(outbound json.RawMessage) error`, `ErrRefused` and `PrivateAddress(host string) bool`. The private address and domain lists are copied from xray-core v26.10.21 (`common/geodata/consts.go`).
- Refused, as xray ≥26.7.11 refuses them: VLESS with encryption `none` and no stream security, or Trojan without TLS, to an address that isn't private; Shadowsocks `none` and `plain`. Also refused: 2022-blake3 passwords that aren't padded standard base64 keys of the cipher's length, and more than one key for chacha20-poly1305 (R13, R14). A shape the rules can't read is left to store validation and `xray run -test`.
- Wiring: `sharelink.Parse` returns a refusal wrapping both `ErrUnsupported` and `ErrRefused`, so a subscription skips the line with the reason; `store.Validate` reports it at `servers[<i>].outbound`. No refusal repeats an id, a password or a key.
- Commit: "Refuse outbounds the newest xray-core refuses".

### Task 9: Apply a rendered config through the trial

**Files:**
- Modify:
  - `internal/artifacts/core.go`: the `Render` field, `Apply`, rendering in `update` and `rollback`, and config pruning;
  - `internal/artifacts/history.go`: `Result.Kind`.
- Test: `internal/artifacts/apply_test.go`, plus additions to `internal/artifacts/core_test.go`.

**Interfaces:**
- Consumes:
  - M1 `CoreUpdater`, `trial`, `active`, `locked`, `readConfig`/`config.write` (content-addressed `config/<sha256>.json`), and the fake runner in `core_test.go`;
  - Task 6 `render.Check` (indirectly, through the renderer the caller passes).
- Produces:
  - `type Renderer func(core xrayver.Version, geo string) ([]byte, error)`.
  - `CoreUpdater.Render Renderer`. Nil keeps M1's behaviour.
  - When set, `Update` without `UpdateOptions.ConfigFile` renders for the target core and the active geo. `Rollback` renders for the core it rolls back to. A render error refuses the update, and no trial runs.
  - `func (u *CoreUpdater) Apply(ctx context.Context) (Result, error)`. Under the artifacts lock it:
    - refuses with "no active core: install one with tikray core update" when the runner has no active selection;
    - refuses when `Render` is nil;
    - renders for the active core and geo;
    - gives `OutcomeNoop` ("already active") when the config is the active one;
    - otherwise trials `{active core, active geo, new config}` through the same `trial`.
    The active core isn't verified again: it is the one running.
  - `Result.Kind string \`json:"kind,omitempty"\``: `"config"` for `Apply`, empty for updates and rollbacks. `committedVersions` keeps working, since `To` is still the active core.
  - After every committed trial, `run/config/` keeps the committed config and the 4 most recently modified others; the rest are removed. A removal failure is noted in `Result.Detail` and never undoes the commit.

- [ ] **Step 1: Write the failing tests** in `apply_test.go`, with M1's fake runner and a fake renderer that records its calls:
  - `TestApplyCommits`: the active core is 26.10.21. Apply renders for `(26.10.21, active geo)`. Then:
    - `candidate.json` holds the same core and `config/<sha256 of the render>.json`;
    - the outcome is committed, with `Kind` `config`;
    - the history line has `"kind":"config"`.
  - `TestApplyNoop`: the render equals the active config → `OutcomeNoop`, and no trial call.
  - `TestApplyNoActive` and `TestApplyNoRenderer`: refused, naming why.
  - `TestApplyRenderError`: refused with the render's error; no candidate is written.
  - `TestApplyLocked`: a held lock → `ErrLocked`.
  - `TestUpdateRendersForTarget`: Update to 26.3.27 without ConfigFile calls the renderer with 26.3.27, and the candidate's config is that render. With ConfigFile set, the renderer isn't called.
  - `TestRollbackRendersForTarget`: rollback to 26.3.27 renders for 26.3.27.
  - `TestPruneConfigs`: after a committed Apply with 7 older configs present, the committed config and the 4 newest others remain.

- [ ] **Step 2: Run them**

  Run: `go test ./internal/artifacts/ -run 'Apply|RendersFor|PruneConfigs'`. Expected: FAIL.

- [ ] **Step 3: Implement** as specified. The rendered bytes go through the same content-addressing as `readConfig`, so a render and a file with the same bytes name the same config.

- [ ] **Step 4: Run the package**

  Run: `go test -race ./internal/artifacts/`. Expected: PASS, including every M1 test unchanged.

- [ ] **Step 5: Commit**

  `git add internal/artifacts && git commit -m "Apply rendered configs through the runner's trial"`

### Task 10: CLI: render, apply, and rendered core updates

**Files:**
- Modify: `cmd/tikray/main.go` (commands, usage), `cmd/tikray/config.go` (state-derived defaults), `test/e2e/config/xray-client.json` (API listen address)
- Test: `cmd/tikray/main_test.go`, `cmd/tikray/config_test.go`

**Interfaces:**
- Consumes:
  - Task 2 `store.Open`;
  - Task 6/7 `render.Render`, `render.ProxyAvailable`, `render.APIPort`, `render.SOCKSPort`;
  - Task 9 `CoreUpdater.Render`, `Apply`;
  - M1's `cli`, `newUpdater`, `report`, `exitCode`.
- Produces:
  - `tikray config render [--core VER]`: the rendered config on stdout. The core defaults to the runner's active core; with no runner or no active core, `--core` is required.
  - `tikray apply`: `CoreUpdater.Apply`, reported and given exit codes like `core update`.
  - `tikray core update` and `tikray core rollback` render from the state unless `--config` is given (M1's behaviour then).
  - The state is `<data>/state`, opened read-only in practice: these commands never call `Update`. (changed: with `--config`, a state that can't be read no longer blocks the update: it warns and takes the runner's addresses from `store.Default()`; R16.)
  - The renderer passes a nil `Geo` when the geo name is empty. Any other name is refused with "geo bundles are not supported yet": nothing installs them before M3.
  - **Defaults:** `TIKRAY_RUNNER_URL`, `TIKRAY_SOCKS` and the new `TIKRAY_XRAY_API` default to `http://<runner>:8080`, `<runner>:1080` and `<runner>:10085`, where `<runner>` is the state's `Network.Runner()`. Set variables still win.
  - `XrayAPIProbe.Server` is the xray API address.
  - **Health:** for a rendered config, the SOCKS probe runs only when `render.ProxyAvailable(state)`. Without a server, `socks-in` goes to `block`, so the probe can only fail. The data path and xray API probes always run. With `--config`, all probes run, as in M1.
  - In `test/e2e/config/xray-client.json`, the `api` block's `listen` becomes `172.31.255.3:10085`, since the probe now asks the runner's address.
  - (changed: Task 10 also added `Lab.pushState`, moved forward from Task 12, and `TestCoreLifecycle` pushes a state that reproduces the fixture right after its `--config` bootstrap, since its later updates render from the state; R15.)

- [ ] **Step 1: Write the failing tests** in `cmd/tikray`, against M1's test helpers (fake runner, temp data dir):
  - `TestConfigRender`: a state file with one server and `--core 26.10.21` prints exactly `render.Render`'s bytes. With no `--core` and a fake runner whose active core is 26.3.27, it renders for 26.3.27.
  - `TestApplyCommand`: Apply against the fake runner exits 0 with outcome committed. A second run exits 0 with `noop`.
  - `TestCoreUpdateRenders`: `core update 26.10.21` with no `--config` writes the rendered config into the candidate.
  - `TestDefaultsFromState`: a state with subnet `10.9.8.0/29` and no env gives runner URL `http://10.9.8.3:8080`, SOCKS `10.9.8.3:1080` and xray API `10.9.8.3:10085`. Env values override.
  - `TestHealthFollowsServers`: `healthChecks(cfg, runner, false)` holds an `artifacts.XrayAPIProbe` and no `artifacts.SOCKSProbe`, and `healthChecks(cfg, runner, true)` holds both. The new unexported `func healthChecks(cfg Config, runner *runnerapi.Client, socks bool) []artifacts.HealthChecker` is what `newUpdater` wraps in `artifacts.AllOf`. `socks` is `render.ProxyAvailable(state)` for a rendered config, and true with `--config`.
  - The usage text lists `config render` and `apply`.

- [ ] **Step 2: Run them**

  Run: `go test ./cmd/tikray/`. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run every unit test**

  Run: `make test`. Expected: PASS.

- [ ] **Step 5: Commit**

  `git add cmd/tikray test/e2e/config/xray-client.json && git commit -m "Render and apply the state from the tikray CLI"`

### Task 11: Lab: a second VLESS server with switches

**Files:**
- Modify:
  - `test/lab/inet.go`: start two servers and return a handle;
  - `test/lab/network.go`: address `203.0.113.11`;
  - `test/lab/fixtures/labinet/handlers.go`: `.11` counts as a proxy source wherever `.10` does.
- Create: `test/lab/fixtures/xray-server-b.json` (a copy of `xray-server.json` that listens and sends from `203.0.113.11`, with the same user)
- Test: `test/lab/inet_lab_test.go`, `test/lab/fixtures/labinet/handlers_test.go`

**Interfaces:**
- Consumes: M0/M1 `StartInetWith`, `Network.Inet`, `XrayBinary`.
- Produces:
  - `type Inet struct{ ... }` with:
    - `func (i *Inet) Stop()`;
    - `func (i *Inet) SetServer(name string, up bool) error`, for `name` `a` (`203.0.113.10`) or `b` (`203.0.113.11`). It kills the server process, or starts it and waits for its port to accept;
    - `func StartInetLab(ctx context.Context, n *Network, o InetOptions) (*Inet, error)`.
  - `StartInetWith` keeps its signature and returns `i.Stop`, so M0's and M1's tests are unchanged.
  - Through server `b`, whoami answers `203.0.113.11`.

- [ ] **Step 1: Extend the tests.**
  - `TestInetFixtures` also checks whoami through server `b`'s SOCKS client config (`203.0.113.11`).
  - `SetServer("a", false)` makes `203.0.113.10:443` refuse connections; `SetServer("a", true)` makes it accept again.
  - `TestDNSAnswer` gets a `.11` row.

- [ ] **Step 2: Run them**

  Run: `go test ./test/lab/fixtures/labinet/` (expected FAIL on the new row), then implement and run `go test -tags lab -count=1 -run TestInetFixtures ./test/lab/` (root). Expected: PASS.

- [ ] **Step 3: Commit**

  `git add test/lab && git commit -m "Add a second VLESS server to the lab, with switches"`

### Task 12: End to end: rendered configs on CHR

**Files:**
- Create:
  - `test/e2e/config_lab_test.go` (tag `lab`);
  - `test/e2e/state/` fixtures, or states built in Go with `store` types;
  - `test/e2e/results/<ros>-<arch>-m2a.json`.
- Modify:
  - `test/e2e/lab.go`: use `StartInetLab`, and add a helper that pushes a state file to `/data/state/state.v1.json`; (changed: the helper, `pushState`, came with Task 10; `waitProxied` takes either server's egress and `proxiedVia` names the server, R17. Every lab state sets `health.probe_url` to the lab's target, `http://203.0.113.30/whoami`: the lab has no internet, so with the default probe URL the observatory finds every server down and the balancers fall back.)
  - the spec, §3.4, §5.3, §5.4 and §10.

**Interfaces:**
- Consumes:
  - Task 10 commands, Task 11 `Inet.SetServer`;
  - Task 1 types, to build states;
  - M1 `Deploy`, `runTikray`, `waitProxied`, `whoami`, and `poll`.
- Produces: `TestConfigApply`. It records its checks like `TestCoreLifecycle` does, and `make lab` runs it.
- **The checks, in order.** The state's device is the lab LAN client, smart, kill switch off, unless a check says otherwise. Servers come from share links: `vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?type=tcp&security=none#lab-a`, and the same at `.11` for `lab-b`. The domestic extras are `domain:domestic.test` and `203.0.113.20/32`. DNS: remote `203.0.113.53`, domestic `203.0.113.54`.
  1. `bootstrap_rendered`: from an empty runner with no state file, `tikray core update latest` commits a config rendered from defaults. The LAN client is direct (whoami `198.51.100.2`, the router's WAN address, as in M1).
  2. `apply_share_link`: push a state with `lab-a`, then `tikray apply` commits. whoami is `203.0.113.10`.
  3. `smart_split`:
     - `domestic.test` is direct, by HTTP Host, through sniffing;
     - `203.0.113.20` is direct;
     - `foreign.test` is proxied;
     - DNS answers for `domestic.test` come from the domestic resolver and for `foreign.test` from the proxied one. The M0 checks show the answers each resolver gives.
  4. `failover`: push `lab-a` and `lab-b`, then apply. Stop whichever server whoami shows; within 30 s whoami shows the other.
  5. `all_down_open`: both stopped → whoami is `198.51.100.2` within 30 s (`proxy-open` falls back direct).
  6. `all_down_kill_switch`: start `a` again, then turn on the device's kill switch and apply (committed: the SOCKS probe needs a live server, so this apply can't run while both are down). Stop both. For 30 s every whoami fails (blocked) and never shows `198.51.100.2`. Start `a` again: whoami is proxied within 30 s.
  7. `bad_raw_server`: a state adding a raw-JSON server whose VLESS `id` is 40 characters long and not a UUID gives an apply outcome of `rejected` (from `xray run -test`). The runner keeps the previous config, and whoami stays proxied.
  8. `older_core_renders`: `tikray core update 26.3.27` commits with a config rendered for 26.3.27, and traffic stays proxied. Then `tikray core rollback` commits back to the newest release.
- Run on CHR 7.25 x86_64, 7.23.8 x86_64 and 7.25 arm64, as M1 did, and commit each results file.
- **Spec update:**
  - §3.4 names the M2a/M2b split;
  - §5.3 records the classic `observatory` (it probes every server at once when xray starts, where the burst observatory spreads its first samples over its whole interval), `socks-in` through `proxy-closed`, the API source restriction, and `block` as the first outbound;
  - §5.4 records `nonIPQuery: reject`;
  - §10's M2 row gets M2a's outcome and the results.

- [ ] **Step 1: Write `TestConfigApply`** with the checks above. Use M1's result recording, and leave the lab running between checks.

- [ ] **Step 2: Run it on x86_64 stable**

  Run: `TIKRAY_LAB_ROS=stable go test -tags lab -p 1 -count=1 -timeout 240m -run TestConfigApply ./test/e2e/`. Expected: 8/8 pass. (changed: the variable `Deploy` reads is `TIKRAY_LAB_CHANNEL`, as in M0 and M1; `TIKRAY_LAB_ROS` is not read.)

  A check that fails is a finding: debug it with superpowers:systematic-debugging. Fix the code, not the check, unless the check contradicts the spec.

- [ ] **Step 3: Run it on long-term x86_64 and stable arm64**

  Run: the same with `TIKRAY_LAB_ROS=long-term`, and with `TIKRAY_LAB_ARCH=arm64`. Expected: 8/8 each.

- [ ] **Step 4: Re-run M1's suite**

  Run: `go test -tags lab -p 1 -count=1 -timeout 240m -run TestCoreLifecycle ./test/e2e/` on x86_64 stable. Expected: 9/9 (the fixture now has the API on the runner's address).

- [ ] **Step 5: Update the spec, and commit**

  `git add test/e2e docs/superpowers/specs && git commit -m "Test rendered configs end to end on CHR"`
