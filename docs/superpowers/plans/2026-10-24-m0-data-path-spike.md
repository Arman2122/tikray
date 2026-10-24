# M0: Data-Path Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove or disprove the spec's data-path assumptions on real RouterOS (CHR in QEMU, then real hardware) before any product code is written, and leave behind a reusable CHR lab harness for the M3 end-to-end suite.

**Architecture:** A Go lab harness (`test/lab`, **kept**) builds a host-side fake LAN and fake internet out of bridges and network namespaces, boots RouterOS CHR in QEMU between them, and drives it over the serial console and SSH. Throwaway prototypes (`spike/m0`, **deleted after M1**) stand in for the runner and the control plane. A `lab`-tagged Go test runs each assumption as a subtest and writes a JSON result file per RouterOS version and architecture. The findings report turns the results into go/no-go decisions and spec changes.

**Tech Stack:** Go 1.24+ (`GOTOOLCHAIN=auto` for building xray, which needs a newer Go), QEMU 8.2 (TCG; no KVM needed), iproute2, Docker (image build and `docker save` only), `golang.org/x/crypto/ssh`, `github.com/vishvananda/netlink`, `github.com/miekg/dns`, `github.com/go-routeros/routeros/v3`.

**Spec:** `docs/superpowers/specs/2026-10-24-tikray-design.md` (read §3.3, §3.6, §5.2–§5.6, §10, §11 before starting).

## Global Constraints

- Go module path: `github.com/Arman2122/tikray`. License: GPL-3.0.
- RouterOS channels under test: **stable** and **long-term**, resolved at run time from `https://upgrade.mikrotik.com/routeros/NEWESTa7.stable` and `…/NEWESTa7.long-term` (first field). At the time of writing these are 7.25 and 7.23.8.
- Architectures: `x86_64` CHR (every run) and `arm64` CHR (at least one full run on stable). Product target is ARM64; x86_64 is for fast lab runs only.
- xray for the lab: module `github.com/xtls/xray-core/main@v1.260327.0` (xray 26.3.27), built with `CGO_ENABLED=0 -trimpath -ldflags "-s -w"` for the needed `GOARCH`.
- Container bridge subnet `172.31.255.0/29`: router `172.31.255.1`, control container `172.31.255.2`, runner `172.31.255.3`.
- xray TUN interface name `xray0`, MTU `1500`. The runner owns all routing for it: policy rule `iif <ingress> lookup 1001` at priority `1001`, `default dev xray0` in table `1001`, `rp_filter=0`.
- RouterOS object names: bridge `tikray`; routing tables `tikray-open`, `tikray-closed`; address lists `tikray-local`, `tikray-domestic`, `tikray-src-smart-open`, `tikray-src-smart-closed`. Every object created by tikray code has a comment starting with `tikray:`. Lab-only scaffolding objects use `lab:`.
- **No source NAT** of LAN traffic into the container.
- Lab-tagged tests (`//go:build lab`) need root, QEMU and network access to `download.mikrotik.com`. Plain `go test ./...` must never need any of these.
- Everything under `spike/m0/` is throwaway and says so in `spike/m0/README.md`.

### Lab address plan (used by every task)

| Where | Address | Role |
|---|---|---|
| Host bridge `tklab-wan` | `198.51.100.1/24` | Host management access to CHR |
| CHR `ether1` | `198.51.100.2/24` | CHR "WAN" |
| netns `tklab-inet`, veth on `tklab-wan` | `198.51.100.254/24` | CHR default gateway ("ISP") |
| netns `tklab-inet`, `lo` | `203.0.113.10/32` | VLESS test server, and its egress source |
| netns `tklab-inet`, `lo` | `203.0.113.20/32` | "Domestic" target |
| netns `tklab-inet`, `lo` | `203.0.113.30/32` | "Foreign" target |
| netns `tklab-inet`, `lo` | `203.0.113.53/32`, `203.0.113.54/32` | DNS fixture (proxied resolver, domestic resolver) |
| Host bridge `tklab-lan` | (no host address) | LAN segment |
| CHR `ether2` | `192.168.88.1/24` | CHR LAN |
| netns `tklab-client`, veth on `tklab-lan` | `192.168.88.10/24`, default via `.1` | Proxied test device |
| Host route | `172.31.255.0/29 via 198.51.100.2` | Host reaches containers through CHR |
| Host route | `203.0.113.0/24 via 198.51.100.254` | Host reaches the fake internet directly (fixture checks) |

How a test tells which path a request took: the target servers report the source IP they see.
- `203.0.113.10`: the request went through the VLESS proxy.
- `198.51.100.2`: the request went direct (masqueraded by CHR).

## Review Focus

1. **RouterOS prompts differ between channels.** The first-login license prompt, the forced password change and prompt text can differ between long-term and stable. Provisioning must work on both, which is pinned by the channel table in Task 3's test.
2. **Device-mode needs a cold power cycle, not `/system/reboot`.** Pinned by Task 4's test, which asserts `container` is enabled only after `PowerCycle`.
3. **Large transfers can stall at TUN/veth MTU and MSS boundaries** even when small requests pass. Pinned by the `large_transfer` subtest in Task 8 (10 MiB download, SHA-256 match).
4. **After a router reboot, the runner must re-apply its routes** on container start-on-boot without anyone touching it. Pinned by the `reboot_persistence` subtest in Task 8.
5. **Fallback must recover, not just trigger.** When the runner comes back, new connections must return to the proxy. Pinned by the `fallback_recovery` subtest in Task 8.

---

### Task 1: Repository bootstrap and CHR artifact fetching

**Files:**
- Create: `go.mod`, `.gitignore`, `LICENSE`, `README.md`, `Makefile`, `scripts/lab-deps.sh`, `.github/workflows/ci.yml`
- Create: `test/lab/doc.go`, `test/lab/artifacts.go`
- Test: `test/lab/artifacts_test.go`

**Interfaces:**
- Produces:
  - `type Arch string` with `const ArchX86 Arch = "x86_64"` and `const ArchARM64 Arch = "arm64"`
  - `func ResolveChannel(ctx context.Context, baseURL, channel string) (version string, err error)`: `channel` is `"stable"` or `"long-term"`; `baseURL` defaults to `https://upgrade.mikrotik.com/routeros` when empty
  - `type Artifacts struct { DiskImage string; ContainerNPK string }` (absolute paths)
  - `func FetchCHR(ctx context.Context, baseURL, cacheDir, version string, arch Arch) (Artifacts, error)`: `baseURL` defaults to `https://download.mikrotik.com/routeros` when empty
  - `func CacheDir() string`: `$TIKRAY_LAB_CACHE`, else `$HOME/.cache/tikray-lab`

- [ ] **Step 1: Write the failing tests** in `test/lab/artifacts_test.go` (no build tag) against an `httptest.Server`:
  - `TestResolveChannel`: the server returns `"7.25 1792678320\n"` for `/NEWESTa7.stable`; assert `"7.25"`. Returns `"7.23.8 1791452776"` for `/NEWESTa7.long-term`; assert `"7.23.8"`. An unknown channel returns an error without making an HTTP request.
  - `TestFetchCHRx86`: the server serves `/7.25/chr-7.25.img.zip` (zip containing `chr-7.25.img`) and `/7.25/all_packages-x86-7.25.zip` (zip containing `container-7.25.npk`). Assert both returned paths exist under `cacheDir/7.25/x86_64/`. A second call makes **zero** HTTP requests (count hits in the handler).
  - `TestFetchCHRarm64`: same with `chr-7.25-arm64.img.zip` and `all_packages-arm64-7.25.zip`; assert files land under `cacheDir/7.25/arm64/`.
  - `TestFetchCHRPartialDownload`: the server closes the connection halfway through the image zip. Assert an error, and assert no file is left in the cache that a later call would mistake for complete (download to `*.part`, rename on success).
- [ ] **Step 2: Run** `go test ./test/lab/ -run 'TestResolveChannel|TestFetchCHR' -v`. Expected: FAIL (package or functions don't exist).
- [ ] **Step 3: Bootstrap the repo**
  - `go mod init github.com/Arman2122/tikray` with `go 1.24`.
  - `LICENSE`: full GPL-3.0 text from `https://www.gnu.org/licenses/gpl-3.0.txt`.
  - `README.md`: one paragraph stating what tikray is and linking the spec.
  - `.gitignore`: `/spike/m0/out/` and `*.part`. (Result files in `spike/m0/results/` are committed, so don't ignore them.)
  - `Makefile` targets:
    - `test` → `go vet ./... && go test ./...`;
    - `lab-deps` → `sudo scripts/lab-deps.sh`;
    - `lab` → `go test -tags lab -timeout 180m ./test/lab/... ./spike/m0/...`.
  - `scripts/lab-deps.sh`: idempotent `apt-get install -y qemu-system-x86 qemu-system-arm qemu-efi-aarch64 qemu-utils iproute2 iputils-ping curl dnsutils netcat-openbsd unzip`.
  - `.github/workflows/ci.yml`: on push and pull_request, set up Go and run `make test`.
- [ ] **Step 4: Implement** `ResolveChannel`, `FetchCHR` and `CacheDir` in `test/lab/artifacts.go`. Use `archive/zip` to extract only the needed member (`chr-<v>.img` / `chr-<v>-arm64.img`, `container-<v>.npk`). Downloads go to `*.part` and are renamed on success. The cache is keyed by version and arch.
- [ ] **Step 5: Run** `make test`. Expected: PASS.
- [ ] **Step 6: Commit** `git add -A && git commit -m "Bootstrap repo and add CHR artifact fetching for the lab harness"`.

---

### Task 2: Lab host network topology

**Files:**
- Create: `test/lab/network.go`
- Test: `test/lab/network_lab_test.go` (`//go:build lab`)

**Interfaces:**
- Produces:
  - `type Network struct{ /* unexported */ }`
  - `func SetupNetwork(ctx context.Context) (*Network, error)`: builds the full address plan above, including taps `tklab-tapw` (on `tklab-wan`) and `tklab-tapl` (on `tklab-lan`) for QEMU, and both host routes. If leftover `tklab-*` objects exist from a crashed run, it removes them first.
  - `func (n *Network) Teardown() error`: removes every `tklab-*` link and netns and both host routes; safe to call twice.
  - `func (n *Network) Inet(ctx context.Context, name string, args ...string) *exec.Cmd`: command run in netns `tklab-inet`.
  - `func (n *Network) Client(ctx context.Context, name string, args ...string) *exec.Cmd`: command run in netns `tklab-client`.
  - `const TapWAN = "tklab-tapw"`, `const TapLAN = "tklab-tapl"`

- [ ] **Step 1: Write the failing test** `TestNetworkSetupTeardown`:
  - After `SetupNetwork`, `n.Inet(ctx, "ping", "-c1", "-W2", "198.51.100.1")` succeeds.
  - `n.Inet(ctx, "ip", "-4", "addr", "show", "lo")` output contains `203.0.113.10`, `203.0.113.20`, `203.0.113.30`, `203.0.113.53` and `203.0.113.54`.
  - `n.Client(ctx, "ip", "route")` contains `default via 192.168.88.1`.
  - After `Teardown`, `ip -o link show` has no line containing `tklab-` and `ip netns list` has no `tklab-` entry. A second `Teardown` returns nil.
- [ ] **Step 2: Run** `sudo go test -tags lab ./test/lab -run TestNetworkSetupTeardown -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `test/lab/network.go` by shelling out to `ip` (iproute2), with each command's stderr included in returned errors. Enable `net.ipv4.ip_forward=1` inside `tklab-inet` so it can act as the ISP router. Don't install NAT; the fake internet never reaches the real one.
- [ ] **Step 4: Run** the test again. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -am "Add lab host network topology"` (plus `git add` for new files).

---

### Task 3: CHR VM lifecycle and provisioning

**Files:**
- Create: `test/lab/chr.go`, `test/lab/console.go`, `test/lab/ssh.go`
- Test: `test/lab/chr_lab_test.go` (`//go:build lab`)

**Interfaces:**
- Consumes: `Network`, `TapWAN`, `TapLAN` (Task 2); `Arch`, `Artifacts`, `FetchCHR`, `ResolveChannel`, `CacheDir` (Task 1).
- Produces:
  - `type BootOptions struct { Version string; Arch Arch; Artifacts Artifacts; WorkDir string; Password string; MemoryMB int; DataDiskMB int }` (defaults: `MemoryMB` 1024, `DataDiskMB` 2048)
  - `type CHR struct{ /* unexported */ }`
  - `func BootCHR(ctx context.Context, n *Network, opts BootOptions) (*CHR, error)`
  - `func (c *CHR) Run(ctx context.Context, cmd string) (string, error)`: SSH exec as user `admin+ct` (no colors or terminal detection) to `198.51.100.2`.
  - `func (c *CHR) Get(ctx context.Context, expr string) (string, error)`: runs `:put [<expr>]` and returns trimmed output.
  - `func (c *CHR) Push(ctx context.Context, localPath, dstPath string) error`: serves the file over HTTP on `198.51.100.1` (random port) and runs `/tool/fetch url=… dst-path=<dstPath>`, then checks the size with `/file/get`.
  - `func (c *CHR) Import(ctx context.Context, rscPath string) error`: `Push` to `tikray-tmp.rsc`, then `/import tikray-tmp.rsc verbose=yes`. Returns an error when the output contains `failure:` or `syntax error`.
  - `func (c *CHR) Reboot(ctx context.Context) error`: soft `/system/reboot`, waits for SSH.
  - `func (c *CHR) PowerCycle(ctx context.Context) error`: SIGKILLs QEMU, starts it again with the same disks, waits for SSH.
  - `func (c *CHR) Shutdown() error`

- [ ] **Step 1: Write the failing test** `TestBootCHR`, table-driven over channels `stable` and `long-term` (arch from `$TIKRAY_LAB_ARCH`, default `x86_64`):
  - `c.Get(ctx, "/system/resource/get version")` starts with the resolved version string.
  - `c.Get(ctx, "/system/resource/get architecture-name")` equals `x86_64` (or `arm64`).
  - `c.Get(ctx, "/ip/address/get [find interface=ether2] address")` equals `192.168.88.1/24`.
  - From `tklab-client`, `ping -c1 -W2 192.168.88.1` succeeds.
  - After `c.PowerCycle(ctx)`, the version check still passes (provisioning persisted).
- [ ] **Step 2: Run** `sudo go test -tags lab ./test/lab -run TestBootCHR -v -timeout 60m`. Expected: FAIL.
- [ ] **Step 3: Implement QEMU launch** in `chr.go`:
  - Copy the image to `WorkDir/system.qcow2` with `qemu-img convert -O qcow2`, and create `WorkDir/data.qcow2` of `DataDiskMB`.
  - x86_64: `qemu-system-x86_64 -m <MemoryMB> -smp 2 -nographic -drive file=system.qcow2,if=virtio -drive file=data.qcow2,if=virtio -netdev tap,id=wan,ifname=tklab-tapw,script=no,downscript=no -device virtio-net-pci,netdev=wan -netdev tap,id=lan,ifname=tklab-tapl,script=no,downscript=no -device virtio-net-pci,netdev=lan -serial unix:<WorkDir>/console.sock,server,nowait -monitor none`.
  - arm64: `qemu-system-aarch64 -M virt -cpu max` with `-bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd` and the same disks and NICs.
  - The first NIC must come up as `ether1`. Assert this in provisioning by checking the MAC of `ether1` against the MAC passed to QEMU (set explicit `mac=` values).
- [ ] **Step 4: Implement serial provisioning** in `console.go`. This is an expect loop with regex prompts kept in one table, so a prompt change is a one-line fix:
  - `Login:` → `admin+ct`
  - `Password:` → empty
  - `software license` question → `n`
  - `new password>` / `repeat new password>` → `Password`
  - prompt `] >` → done

  Then send:
  - `/ip/address/add address=198.51.100.2/24 interface=ether1 comment=lab:wan`
  - `/ip/address/add address=192.168.88.1/24 interface=ether2 comment=lab:lan`
  - `/ip/route/add gateway=198.51.100.254 comment=lab:default`
  - `/ip/service/set ssh disabled=no`

  On later boots, skip provisioning if SSH already answers.
- [ ] **Step 5: Implement SSH and file transfer** in `ssh.go` (`golang.org/x/crypto/ssh`, password auth, 30 s dial timeout with retries until the boot deadline: 5 min x86_64, 20 min arm64 under TCG).
- [ ] **Step 6: Run** the test. Expected: PASS on both channels. If a prompt differs between channels, add it to the prompt table and note the difference in a comment.
- [ ] **Step 7: Commit** `git commit -m "Add CHR VM lifecycle and provisioning to the lab harness"`.

---

### Task 4: Enable containers on CHR

**Files:**
- Modify: `test/lab/chr.go` (add method)
- Test: `test/lab/containers_lab_test.go` (`//go:build lab`)

**Interfaces:**
- Consumes: `CHR.Push`, `CHR.Run`, `CHR.Get`, `CHR.Reboot`, `CHR.PowerCycle` (Task 3); `Artifacts.ContainerNPK` (Task 1).
- Produces: `func (c *CHR) EnableContainers(ctx context.Context) error`. This is idempotent. It installs the container package, enables container device-mode, formats the data disk and sets `/container/config tmpdir=disk1/tikray/tmp`. It's also where the canonical data root `disk1/tikray/data` lives (`const DataRoot = "disk1/tikray/data"`).

- [ ] **Step 1: Write the failing test** `TestEnableContainers` (same channel table as Task 3):
  - After `EnableContainers`, `c.Get(ctx, "[:len [/system/package/find name=container]]")` is `1`.
  - `c.Get(ctx, "/system/device-mode/get container")` is `true` (or `yes`; accept both and record which in the test log).
  - `/disk/print` output shows `disk1` with an `ext4` file system.
  - `c.Run(ctx, "/container/print")` succeeds.
  - A second `EnableContainers` call returns nil without rebooting (measure: uptime keeps increasing).
- [ ] **Step 2: Run** `sudo go test -tags lab ./test/lab -run TestEnableContainers -v -timeout 90m`. Expected: FAIL.
- [ ] **Step 3: Implement** in this order:
  1. `Push` the npk to the root, then `Reboot`, then verify the package.
  2. Run `/system/device-mode/update container=yes`. The command blocks waiting for confirmation, so run it with a 10 s context and expect it to time out. Then `PowerCycle`.
  3. Run `/disk/format-drive disk1 file-system=ext4` (confirm the prompt if any). Then create `disk1/tikray/{tmp,images,containers,data/run,data/cores}` with `/file/add type=directory`, or record the working alternative if that command doesn't exist on a channel.
  4. Set `/container/config/set tmpdir=disk1/tikray/tmp`.
- [ ] **Step 4: Run** the test. Expected: PASS on both channels.
- [ ] **Step 5: Commit** `git commit -m "Enable containers on lab CHR"`.

---

### Task 5: Fake-internet fixtures

**Files:**
- Create: `test/lab/fixtures/labinet/main.go`, `test/lab/fixtures/labinet/handlers.go`, `test/lab/fixtures/xray-server.json`, `test/lab/xray.go`, `test/lab/inet.go`
- Test: `test/lab/fixtures/labinet/handlers_test.go` (no tag), `test/lab/inet_lab_test.go` (`//go:build lab`)

**Interfaces:**
- Produces:
  - `labinet` binary behavior (one process in `tklab-inet`):
    - HTTP `:80` and HTTPS `:443` on `203.0.113.20` and `203.0.113.30`. The self-signed cert covers `domestic.test` and `foreign.test`.
      - `GET /whoami` → body is the caller's IP only.
      - `GET /blob10m` → 10 MiB of deterministic bytes (`sha256` = `func BlobSHA256() string`).
    - UDP echo on `203.0.113.30:9000` → reply is the caller's IP.
    - DNS on `203.0.113.53:53` and `203.0.113.54:53`, UDP and TCP (`miekg/dns`).
  - `func DNSAnswer(qname string, src netip.Addr) (netip.Addr, bool)` in `handlers.go`:
    - for `domestic.test.` and `foreign.test.`: returns `203.0.113.30` when `src == 203.0.113.10` (the query came through the proxy);
    - otherwise returns `10.10.34.34` (the "poisoned" answer an ISP resolver gives);
    - `false` for any other name.
  - `func XrayBinary(ctx context.Context, cacheDir, goarch string) (string, error)` in `test/lab/xray.go`: builds `xray` from `github.com/xtls/xray-core/main@v1.260327.0` for `goarch` (with `GOTOOLCHAIN=auto`) and caches it at `<cacheDir>/xray/v1.260327.0/<goarch>/xray`, which it returns.  - `func StartInet(ctx context.Context, n *Network) (stop func(), err error)` in `test/lab/inet.go`: builds `labinet` and xray for the host arch and starts both in `tklab-inet`. xray uses `xray-server.json`:
    - VLESS inbound on `203.0.113.10:443`, `security: none`, client id `b831381d-6324-4d53-ad4f-8cda48b30811`;
    - `freedom` outbound with `sendThrough: "203.0.113.10"`.

- [ ] **Step 1: Write the failing unit tests** in `handlers_test.go`:
  - `TestDNSAnswer`:
    - `("foreign.test.", 203.0.113.10)` → `203.0.113.30, true`
    - `("foreign.test.", 198.51.100.2)` → `10.10.34.34, true`
    - `("domestic.test.", 198.51.100.2)` → `10.10.34.34, true`
    - `("example.com.", 203.0.113.10)` → `_, false`
  - `TestWhoami`: an `httptest` request with `RemoteAddr = "203.0.113.10:5555"` returns body `203.0.113.10`.
  - `TestBlob`: `/blob10m` body length is `10*1024*1024` and its sha256 equals `BlobSHA256()`.
- [ ] **Step 2: Run** `go test ./test/lab/fixtures/... -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `handlers.go` and `main.go` (flags only for listen addresses; the defaults are the values above).
- [ ] **Step 4: Run** the unit tests. Expected: PASS.
- [ ] **Step 5: Write the failing lab test** `TestInetFixtures`:
  - After `SetupNetwork` + `StartInet`, `curl -s http://203.0.113.30/whoami` from the **host** (routed via `198.51.100.254`) returns `198.51.100.1`.
  - `dig +short @203.0.113.53 foreign.test` from the host returns `10.10.34.34`.
  - `xray run -test -c test/lab/fixtures/xray-server.json` exits 0.
- [ ] **Step 6: Implement** `XrayBinary` and `StartInet`, then run `sudo go test -tags lab ./test/lab -run TestInetFixtures -v`. Expected: PASS.
- [ ] **Step 7: Commit** `git commit -m "Add fake-internet fixtures for the lab"`.

---

### Task 6: Throwaway runner and control prototypes, and container images

**Files:**
- Create: `spike/m0/README.md` (states: throwaway, delete after M1, links the plan)
- Create: `spike/m0/runnerproto/main.go`, `spike/m0/ctlproto/main.go`
- Create: `spike/m0/images/Dockerfile.runnerproto`, `spike/m0/images/Dockerfile.ctlproto`, `spike/m0/build-images.sh`
- Create: `spike/m0/config/xray-client.json`

**Interfaces:**
- Produces:
  - `runnerproto` (PID 1 in the runner container):
    1. Writes and logs the result of each sysctl: `net.ipv4.ip_forward=1`, `net.ipv4.conf.all.rp_filter=0`, `net.ipv4.conf.default.rp_filter=0`.
    2. Finds the **ingress link** as the link holding the default route (never hard-codes `eth0`).
    3. Starts `$XRAY_BIN run -c $XRAY_CONFIG` (defaults: `/data/cores/26.3.27/xray`, `/data/run/config.json`), restarting it in-process if it exits.
    4. Waits up to 10 s for link `xray0`, sets it up and sets its `rp_filter=0`.
    5. Adds `default dev xray0 table 1001` and rule `iif <ingress> lookup 1001 priority 1001` via netlink, and re-adds them whenever `xray0` reappears after a restart.
    6. Serves HTTP on `:8080`:
       - `GET /v0/status` → JSON `{"sysctl":{"<key>":"ok|<error>"},"ingress":"<link>","xray_pid":N,"xray_rss_kb":N,"routes_ok":bool,"xray_restarts":N}`
       - `GET /v0/file?path=<abs>` → file contents or 404
  - `ctlproto` (PID 1 in the control container), HTTP on `:8080`:
    - `POST /v0/write?path=<abs>` (body = content) → 204, or 500 with the error text.
    - `GET /v0/api-probe?user=<u>&pass=<p>` → connects to `172.31.255.1:8729` (TLS, skip verify; lab only) with `go-routeros/routeros/v3`, starts `/ip/firewall/address-list/listen`, and returns the first event as JSON within 60 s, or 504.
  - `spike/m0/build-images.sh <amd64|arm64>` → `spike/m0/out/runnerproto-<arch>.tar` and `spike/m0/out/ctlproto-<arch>.tar`. Static Go builds; `FROM scratch` + `COPY` only (no `RUN`, so no emulation is needed for arm64); `docker build --platform linux/<arch>`; `docker save`.
  - `spike/m0/config/xray-client.json`:
    - TUN inbound `{"protocol":"tun","tag":"tun-in","settings":{"name":"xray0","MTU":1500},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}}`.
    - `dokodemo-door` inbound `dns-in` on `0.0.0.0:53` (tcp,udp) to `203.0.113.53:53`.
    - Outbounds: `proxy` (VLESS to `203.0.113.10:443`, the fixture id, `security: none`), `direct` (freedom), `block` (blackhole), `dns-out` (dns).
    - DNS servers: `{"address":"203.0.113.54","domains":["domain:domestic.test"]}` then `"203.0.113.53"`.
    - Routing rules, in order:
      1. `inboundTag dns-in` → `dns-out`
      2. `ip 203.0.113.54` → `direct`
      3. `ip 203.0.113.53` → `proxy`
      4. `domain domain:domestic.test` → `direct`
      5. `ip 203.0.113.20` → `direct`
      6. `network tcp,udp` → `proxy`
    - Access log to `/data/run/access.log`.

- [ ] **Step 1: Write a failing check**: `bash spike/m0/build-images.sh amd64 && tar -tf spike/m0/out/runnerproto-amd64.tar | grep -q manifest.json`. Expected now: FAIL (script missing).
- [ ] **Step 2: Implement** both prototypes, the Dockerfiles, the build script and the client config. Validate the config with the lab xray: `"${TIKRAY_LAB_CACHE:-$HOME/.cache/tikray-lab}/xray/v1.260327.0/amd64/xray" run -test -c spike/m0/config/xray-client.json`. Expected: `Configuration OK.`
- [ ] **Step 3: Run** the check for `amd64` and `arm64`. Expected: both tars exist and contain `manifest.json`. Note: Docker's containerd image store writes OCI-layout archives. If RouterOS rejects them in Task 7, re-export with `docker save` after disabling the containerd store, or with `crane pull --format=tarball`, and record which format worked.
- [ ] **Step 4: Commit** `git commit -m "Add throwaway runner/control prototypes for the M0 spike"`.

---

### Task 7: RouterOS data-path setup and deployment

**Files:**
- Create: `spike/m0/routeros/lab-fasttrack.rsc`, `spike/m0/routeros/setup.rsc`, `spike/m0/deploy.go` (`//go:build lab`, package `m0`)
- Test: `spike/m0/deploy_lab_test.go` (`//go:build lab`)

**Interfaces:**
- Consumes: everything in `test/lab` (Tasks 1–5); image tars and config (Task 6).
- Produces:
  - `type Lab struct { Net *lab.Network; CHR *lab.CHR; Arch lab.Arch; Version string; StopInet func() }`
  - `func Deploy(ctx context.Context, t *testing.T) *Lab`: full bring-up (network, inet fixtures, CHR boot, containers enabled, files pushed, `lab-fasttrack.rsc`, then `setup.rsc`, both containers started), with `t.Cleanup` teardown. Reads `$TIKRAY_LAB_CHANNEL` (default `stable`) and `$TIKRAY_LAB_ARCH` (default `x86_64`).
  - `type RunnerStatus struct { Sysctl map[string]string; Ingress string; XrayPID int; XrayRSSKB int; RoutesOK bool; XrayRestarts int }`, decoded from the runnerproto `/v0/status` JSON (Task 6) with matching `json` tags
  - `func (l *Lab) RunnerStatus(ctx context.Context) (RunnerStatus, error)` (GET `http://172.31.255.3:8080/v0/status` from the host)
  - `func (l *Lab) ClientCurl(ctx context.Context, args ...string) (string, error)` (curl in `tklab-client`, 15 s max time)
  - `func (l *Lab) SetSourcePolicy(ctx context.Context, list string) error` (moves `192.168.88.10` between `tikray-src-smart-open` and `tikray-src-smart-closed`)

`lab-fasttrack.rsc` simulates a typical user config: `/ip/firewall/filter/add chain=forward action=fasttrack-connection connection-state=established,related comment=lab:fasttrack` and `…action=accept connection-state=established,related comment=lab:est`. It also adds LAN masquerade `chain=srcnat src-address=192.168.88.0/24 out-interface=ether1 action=masquerade comment=lab:nat-lan`.

`setup.rsc` must create exactly this (every object commented `tikray:<name>`):

```
/interface/bridge/add name=tikray
/interface/veth/add name=tikray-runner address=172.31.255.3/29 gateway=172.31.255.1
/interface/veth/add name=tikray-ctl address=172.31.255.2/29 gateway=172.31.255.1
/interface/bridge/port/add bridge=tikray interface=tikray-runner
/interface/bridge/port/add bridge=tikray interface=tikray-ctl
/ip/address/add address=172.31.255.1/29 interface=tikray
/ip/firewall/nat/add chain=srcnat src-address=172.31.255.0/29 out-interface=ether1 action=masquerade

/ip/firewall/address-list
  tikray-local: 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 224.0.0.0/4
  tikray-domestic: 203.0.113.20/32
  tikray-src-smart-open: 192.168.88.10

/routing/table/add name=tikray-open fib
/routing/table/add name=tikray-closed fib
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.255.3 routing-table=tikray-open   distance=1 check-gateway=ping
/ip/route/add dst-address=0.0.0.0/0 gateway=198.51.100.254 routing-table=tikray-open distance=2
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.255.3 routing-table=tikray-closed distance=1 check-gateway=ping
/ip/route/add dst-address=0.0.0.0/0 blackhole routing-table=tikray-closed distance=2

/ip/firewall/mangle (in this order)
  chain=prerouting action=jump jump-target=tikray-pre
  chain=tikray-pre dst-address-list=tikray-local action=return
  chain=tikray-pre dst-address-list=tikray-domestic action=return
  chain=tikray-pre src-address-list=tikray-src-smart-open   connection-mark=no-mark action=mark-connection new-connection-mark=tikray-open   passthrough=yes
  chain=tikray-pre src-address-list=tikray-src-smart-closed connection-mark=no-mark action=mark-connection new-connection-mark=tikray-closed passthrough=yes
  chain=tikray-pre connection-mark=tikray-open   action=mark-routing new-routing-mark=tikray-open   passthrough=no
  chain=tikray-pre connection-mark=tikray-closed action=mark-routing new-routing-mark=tikray-closed passthrough=no
  chain=forward protocol=tcp tcp-flags=syn connection-mark=tikray-open,tikray-closed action=change-mss new-mss=clamp-to-pmtu passthrough=yes   (one rule per mark if a list isn't accepted)

/ip/firewall/filter: accept connection-mark=tikray-open and connection-mark=tikray-closed, each placed before [find comment=lab:fasttrack]

/ip/firewall/nat (dstnat): src-address-list=tikray-src-smart-open|tikray-src-smart-closed, protocol=udp|tcp, dst-port=53 → action=dst-nat to-addresses=172.31.255.3 to-ports=53  (4 rules)

/user/group/add name=tikray policy=read,write,api
/user/add name=tikray group=tikray password=<lab password> address=172.31.255.2/32
certificate tikray-api (self-signed, signed on the router); /ip/service/set api-ssl certificate=tikray-api disabled=no

containers (from files pushed to disk1/tikray/images/):
  runner: file=runnerproto-<arch>.tar interface=tikray-runner root-dir=disk1/tikray/containers/runner
          mounts: disk1/tikray/data/run → /data/run, disk1/tikray/data/cores → /data/cores (read-only if the version supports it)
          start-on-boot=yes logging=yes
  ctl:    file=ctlproto-<arch>.tar interface=tikray-ctl root-dir=disk1/tikray/containers/ctl
          mounts: disk1/tikray/data/run → /data/run, disk1/tikray/data/cores → /data/cores (read-write)
          start-on-boot=yes logging=yes
```

Pushed files:
- the xray binary for the CHR arch → `disk1/tikray/data/cores/26.3.27/xray`;
- `xray-client.json` → `disk1/tikray/data/run/config.json`;
- the image tars → `disk1/tikray/images/`.

Wherever a channel's syntax differs (for example container mount or env parameter names), keep one `.rsc` per channel only if unavoidable, and record each difference in a comment at the top of `setup.rsc`.

- [ ] **Step 1: Write the failing test** `TestDeploy`:
  - After `Deploy`, `RunnerStatus` returns `xray_pid > 0`, `routes_ok == true` and `ingress != ""`.
  - `c.Get(ctx, "[:len [/ip/firewall/mangle/find where comment~\"^tikray:\"]]")` is `8` (or the per-mark MSS count, if split).
  - `/container/print` shows both containers running.
- [ ] **Step 2: Run** `sudo go test -tags lab ./spike/m0 -run TestDeploy -v -timeout 90m`. Expected: FAIL.
- [ ] **Step 3: Implement** `lab-fasttrack.rsc`, `setup.rsc` and `deploy.go`. Wait for container status `running` by polling `/container/get [find comment~"tikray:runner"] status` every 5 s for up to 10 min (image extraction under TCG is slow).
- [ ] **Step 4: Run** the test. Expected: PASS. If RouterOS rejects the image tar, apply the Task 6 Step 3 fallback and re-run.
- [ ] **Step 5: Commit** `git commit -m "Add RouterOS data-path setup and lab deployment for the M0 spike"`.

---

### Task 8: Assumption tests and results

**Files:**
- Create: `spike/m0/m0_lab_test.go` (`//go:build lab`), `spike/m0/results/.gitkeep`

**Interfaces:**
- Consumes: `Deploy`, `Lab.RunnerStatus`, `Lab.ClientCurl`, `Lab.SetSourcePolicy` (Task 7); `BlobSHA256` (Task 5).
- Produces: `spike/m0/results/<version>-<arch>.json`, an array of `{"id":"<subtest>","pass":bool,"detail":"<observed values>","seconds":N}` written in `t.Cleanup` even when subtests fail.

`TestAssumptions` calls `Deploy` once and runs these subtests in order. Each one records what it observed, not just pass/fail:

| Subtest | Action | Pass condition |
|---|---|---|
| `sysctl_in_container` | `RunnerStatus` | every `sysctl` value is `ok` (if not, record the errors: this decides whether the runner can rely on writing `/proc/sys`) |
| `exec_from_mount` | `RunnerStatus` | `xray_pid > 0` with `XRAY_BIN` on the `/data/cores` mount (no `noexec`) |
| `proxied_ip` | `ClientCurl http://203.0.113.30/whoami` | body `203.0.113.10` |
| `domestic_ip_direct` | `ClientCurl http://203.0.113.20/whoami` | body `198.51.100.2`, and `/data/run/access.log` (via `GET /v0/file`) has **no** line for `203.0.113.20` (it never entered xray) |
| `sniffed_domain_direct` | `ClientCurl -k --resolve domestic.test:443:203.0.113.30 https://domestic.test/whoami` | body `198.51.100.2` (entered xray, sent direct by its sniffed domain) |
| `sniffed_domain_proxied` | same with `foreign.test` | body `203.0.113.10` |
| `no_src_nat` | read `access.log` | the `foreign.test` line shows source `192.168.88.10` |
| `dns_proxied` | in `tklab-client`: `dig +short @192.168.88.1 foreign.test` | `203.0.113.30` |
| `dns_domestic_direct` | `dig +short @192.168.88.1 domestic.test` | `10.10.34.34` (queried direct, as designed) |
| `udp_proxied` | in `tklab-client`: `echo ping \| nc -u -w2 203.0.113.30 9000` | reply `203.0.113.10` |
| `large_transfer` | `ClientCurl -o - http://203.0.113.30/blob10m \| sha256sum` (60 s max time) | equals `BlobSHA256()`; record seconds |
| `no_fasttrack_marked` | after `large_transfer`, `/ip/firewall/connection/print where connection-mark=tikray-open` | no entry has the FastTrack flag; record the raw output |
| `fallback_open` | stop the runner container; poll `ClientCurl http://203.0.113.30/whoami` every 2 s | `198.51.100.2` within 60 s; record seconds |
| `fallback_recovery` | start the runner; poll | `203.0.113.10` within 120 s after the runner reports `routes_ok`; record seconds |
| `fallback_closed` | `SetSourcePolicy(ctx, "tikray-src-smart-closed")`; stop the runner; curl | request fails, and never returns `198.51.100.2`, for 60 s; then start the runner and restore `tikray-src-smart-open` |
| `shared_mount` | `POST` ctl `/v0/write?path=/data/run/hello.txt`, then runner `/v0/file?path=/data/run/hello.txt` | contents equal; then ctl writes `/data/cores/x` and the runner reads it (records whether read-only mounts were available and enforced) |
| `api_listen_restricted` | ctl `/v0/api-probe` with the `tikray` user; meanwhile `c.Run` adds address-list entry `tikray-probe 192.0.2.1` | probe returns an event containing `192.0.2.1`; also `c.Run` an SSH login as `tikray` fails (no `ssh` policy) |
| `memory` | `RunnerStatus` after `large_transfer` | record `xray_rss_kb` (no threshold) |
| `reboot_persistence` | `c.PowerCycle`; wait for the runner status `routes_ok` | `proxied_ip` passes again without any manual step |

- [ ] **Step 1: Write** `m0_lab_test.go` with the table above. Use `t.Run` for each subtest, and record into the results slice in each subtest's deferred function.
- [ ] **Step 2: Run** `sudo TIKRAY_LAB_CHANNEL=stable go test -tags lab ./spike/m0 -run TestAssumptions -v -timeout 180m`. Expected: a results file is written. Failures here are **findings**, not bugs to hide: never weaken a pass condition to get green. Fix only lab or prototype mistakes (for example a wrong command syntax), and record each one in the result's `detail`.
- [ ] **Step 3: Run** the same with `TIKRAY_LAB_CHANNEL=long-term`, and with `TIKRAY_LAB_ARCH=arm64` on stable.
- [ ] **Step 4: Commit** `git add spike/m0 && git commit -m "Add M0 assumption tests and results"`.

---

### Task 9: Real-hardware benchmark kit

**Files:**
- Create: `spike/m0/hw/README.md`, `spike/m0/hw/bench.rsc`, `spike/m0/hw/results-template.md`

**Interfaces:**
- Consumes: `runnerproto-arm64.tar`, `xray-client.json` (Task 6); `setup.rsc` (Task 7).

This is run by a person on a real hAP ax³ or RB5009, not in CI.

- [ ] **Step 1: Write** `spike/m0/hw/README.md`. It's a step-by-step procedure for a non-expert:
  - **Prerequisites:** a RouterOS stable or long-term device, a USB/NVMe disk, and one VLESS server (any VPS) with an `iperf3` server on the same VPS.
  - **Setup:** copying `runnerproto-arm64.tar` and the xray binary through Winbox Files, then editing `xray-client.json` (server address, id, security; Reality is allowed here).
  - Running `bench.rsc`, which applies `setup.rsc` with the user's LAN client IP and WAN gateway as script variables at the top.
  - **Measurements**, each 3 runs, recorded in `results-template.md`:
    - `iperf3 -c <vps> -t 30` and `-R`, direct (client in no list) vs. proxied;
    - `-P 8` parallel;
    - `/system/resource/print` CPU during the test;
    - runner `xray_rss_kb` from `/v0/status`.
  - **Revert:** an `uninstall` block in `bench.rsc` that removes every object with comment `~"^tikray:"`.
- [ ] **Step 2: Check** that `bench.rsc` and `setup.rsc` share their tikray object definitions (`bench.rsc` uses `/import setup.rsc` after setting variables) so the hardware run tests exactly what the lab tested.
- [ ] **Step 3: Commit** `git commit -m "Add M0 real-hardware benchmark kit"`.

---

### Task 10: Findings report and spec update

**Files:**
- Create: `docs/superpowers/findings/2026-10-24-m0-data-path.md`
- Modify: `docs/superpowers/specs/2026-10-24-tikray-design.md` (only where findings require it)

- [ ] **Step 1: Write the findings report**:
  - One table per RouterOS version and arch: subtest, pass/fail, observed detail and seconds, generated from the `results/*.json` files (paste them; no script needed).
  - The minimum xray version for the TUN inbound, found with `git log --diff-filter=A --format='%h %ad %s' -- proxy/tun/` in the xray module source, mapped to its release tag.
  - Channel differences found in Tasks 3, 4 and 7 (prompts, command syntax, image archive format, mount options).
  - Hardware results, if available, or "pending" with a link to the kit.
  - Coverage gaps carried forward: QUIC sniffing isn't exercised in M0 because there's no QUIC fixture (plain UDP is covered by `udp_proxied`). It moves to the M3 end-to-end suite.
- [ ] **Step 2: Write the decisions section**, one line per spec assumption: **confirmed**, **changed** (what and why) or **blocked** (fallback chosen). Mandatory decision points:
  - If `proxied_ip` or `sniffed_*` fail because of TUN, switch the spec to the §11 fallback (TPROXY + `dokodemo-door` via nftables) and say so.
  - If `sysctl_in_container` fails, record how the runner gets forwarding and `rp_filter` instead.
  - If `shared_mount` shows read-only mounts aren't available, change §3.5 to match.
  - If `api_listen_restricted` fails, decide between REST and polling for drift repair (§6.2).
- [ ] **Step 3: Update the spec** for every **changed** or **blocked** line, keeping section numbers stable.
- [ ] **Step 4: Commit** `git add docs && git commit -m "Add M0 findings and update spec"`.

---

## After this plan

The M1 plan (runner + artifact pipeline) is written after Task 10, starting from the findings. `spike/m0/` is deleted in M1 once the real runner covers the same assumptions. `test/lab/` stays and becomes the base of the M3 end-to-end suite.
