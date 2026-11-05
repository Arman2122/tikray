# tikray handoff

Everything a new developer or AI assistant needs to continue tikray. Read this page first. Then read the spec, then the M2c plan and the M2c ledger.

Written 2026-11-05, when work moved off the original cloud session. The handed-off state is commit `79f8582` on branch `claude/serene-goldberg-1as8mu`. At that commit, `make test` passes: `go vet` is clean and all 21 test packages pass.

## What tikray is

tikray is an xray-core **client** for MikroTik RouterOS v7. It connects a router to existing VLESS, VMess, Trojan and Shadowsocks servers; it does not create accounts. It runs as two RouterOS containers:

- **tikray** is the control plane. It holds the desired state, renders the xray config, and serves the HTTPS API and CLI. The web UI comes in M4, the RouterOS reconciler in M3.
- **tikray-runner** is the data plane. It is PID 1 of its container and supervises xray. It applies every config through a trial with automatic rollback.

Steering is hybrid: domestic traffic goes direct and the rest goes through xray. xray-core, geo data and tikray update independently, with verification and rollback. Supported targets are ARM64 and amd64/CHR.

- **Language and license:** Go 1.24 (`go.mod`), GPL-3.0.
- **Spec, the binding authority:** [`docs/superpowers/specs/2026-10-24-tikray-design.md`](../superpowers/specs/2026-10-24-tikray-design.md). §10 lists the milestones.

## Status

| Milestone | State | Where |
|---|---|---|
| M0: data-path spike | Done in the lab (22/22 checks on CHR 7.25 x86_64, 7.23.8 x86_64 and 7.25 arm64). The **real-hardware benchmark is still pending**: it needs a physical MikroTik. | `spike/m0`, [findings](../superpowers/findings/2026-10-24-m0-data-path.md) |
| M1: runner and artifacts | Done, merged (PR #3) | |
| M2a: state model and render | Done, merged (PR #4) | |
| M2b: the service (`tikray serve`, HTTPS API, health, subscriptions) | Done, merged (PR #5) | |
| **M2c: human sign-in and hot server changes** | **In progress: Tasks 1–9 complete; whole-branch fixes under final validation** | this branch |
| M3: RouterOS (installer, reconciler, version adapters, watchdog, uninstall, CHR e2e) | Not started | |
| M4: web UI | Not started | |
| M5: v1.0 (hardening, full e2e matrix, hardware benchmarks, docs, signed release) | Not started | |

Roughly half of the total effort is done.

## M2c: where it stopped

- **Plan:** [`docs/superpowers/plans/2026-10-26-m2c-auth-hot.md`](../superpowers/plans/2026-10-26-m2c-auth-hot.md).
- **Ledger:** [`m2c/ledger.md`](m2c/ledger.md). It is the record of everything decided. Each `Ruling:` line binds later work the way the plan does.

| Task | What | Commits | State |
|---|---|---|---|
| 1 | Admin account, setup code, `auth.json` (`internal/auth`) | da3281f | done, reviewed |
| 2 | Sessions, API tokens, CSRF, rate limiter | 7759500, b38f307 | done, reviewed |
| 3 | API authentication and `/v1/auth/*`, `/v1/tokens` routes | 366442d, ec155bd, 63cb096 | done, reviewed |
| 4 | `serve` setup hint; `tikray setup-code`, `admin reset`, `token` CLI | e4ef857 | done, reviewed |
| 5 | Runner `POST /v1/adopt` | 6278b16 | done, reviewed |
| 6 | Hot server changes through `xray api` (rmo/ado), with a trial fallback and a crash-safe pending marker | fdf5577, 55e3ad1, c103901, 791ce92 | done, reviewed (2 fix rounds) |
| 7 | Compat test of hot changes against real xray releases | fb76752, 79f8582, 5a5c2cd | done, reviewed |
| 8 | Re-test servers saved untested; batched first-refresh tests | b3038ab | done, reviewed |
| 9 | End-to-end `TestAuth` and `TestHot` on CHR (3 platforms), spec update | 4ad5f3c | done on all three CHRs |
| — | Final whole-branch review and fix wave | see the M2c ledger | validating reviewed images |

### Next steps, in order

All nine tasks are implemented and tested. In WSL2 Ubuntu, QEMU's TCG ran
`TestAuth` (6/6) and `TestHot` (4/4) on CHR 7.25 x86_64, 7.23.8 x86_64
and 7.25 arm64. The root-token `TestService` rerun on 7.25 x86_64 passed
8/8. The [results](../../test/e2e/results/) and [ledger](m2c/ledger.md)
record the runs and the fixes needed to reproduce them.

1. **Final whole-branch review** of `main..HEAD`.
   - Use the plan's Review Focus section and the ledger's `Ruling:` lines.
   - Decide each `minor (deferred)` line in the ledger: fix it or keep deferring it.
   - Then do one fix wave, each fix test-first.
2. **Update draft PR #6** to `main`, get CI green, and ask the owner before merging.

### Key M2c facts

These are the fixed values; the full list is in [`m2c/context.md`](m2c/context.md).

- **Passwords:**
  - argon2id m=19456 KiB, t=2, p=1, 16-byte salt, 32-byte key, PHC string; at most 2 hashes at once.
  - Passwords are 10–256 bytes.
- **Setup code:** 12 Crockford base32 symbols, shown `XXXX-XXXX-XXXX`, in `state/setup.code` (0600). Only `tikray setup-code` shows it.
- **Sessions:**
  - 32 random bytes, stored as SHA-256; idle 12 h, absolute 7 days, at most 20.
  - Cookie `tikray_session`, with `Secure; HttpOnly; SameSite=Strict; Path=/`.
- **CSRF:** header `X-Tikray-CSRF`, value = base64url(HMAC-SHA256(csrf_key, session id)). Required on cookie requests that aren't GET or HEAD.
- **API tokens:** `tkr_<8hex>_<43 b64url>`, at most 50.
- **Rate limit** on setup and sign-in failures: per IP 5, refilling 1 per 60 s (IPv6 keyed by /64); global 100, refilling 1 per 9 s; 429 with `Retry-After`.
- **Root token:** `state/api.token` (M2b) keeps every right. It is the only credential for `POST /v1/auth/reset`.
- **Hot changes:**
  - Only when the render differs from the active config in `srv-` outbounds alone.
  - The steps are test → baseline → rmo → ado → probe → runner adopt.
  - Any failure falls back to a normal trial.
  - The marker `run/hot/pending` makes the next apply heal a crash mid-change.
  - `TIKRAY_HOT=off` disables hot changes.

## Carries to later milestones

These come from PR #5 and the ledgers. Each needs doing in the milestone named.

- **M3:**
  - The installer must leave the tikray container's `cmd` unset, or set it to `serve`. RouterOS ignores `cmd=""`; use `/container/unset … cmd`.
  - The installer must bootstrap the xray core before adding any server or subscription.
  - Add a `ReadTimeout` to the runner's HTTP server, together with the firewall work.
  - The e2e bridge uses `protocol-mode=none`. With the default RSTP, a freshly started container can't reach the runner. `install.rsc` must do the same.
  - Set the containers' restart policy: a failing control-API listener stops xray.
  - Check that devices and `network.subnet` don't overlap the bridge subnet, loopback or multicast.
- **M4:**
  - Events need a boot id, because `Seq` restarts at 1 after a restart.
  - The UI signs in with M2c's cookie and CSRF scheme.
- **All the deferred minors and older rulings** are in [`decisions/`](decisions/), one file per milestone (M0, M1, M2a, M2b), and in the M2c ledger.

## Rules the owner set (binding on whoever continues)

- **Commit author:**
  - Every commit is authored `Arman2122 <arman.seyri@gmail.com>`.
  - Commits carry no `Co-Authored-By`, `Claude-Session` or other trailers.
  - No AI model names appear in commits, PRs or code.
- **History:** never force-push or rewrite pushed history without asking.
- **Merging:** never merge a PR without asking the owner.
- **Secrets** never appear in logs, errors, events, history, API responses, test output or results files. Secrets are:
  - share links, server ids and passwords, subscription URLs;
  - the root token, admin passwords and hashes, the setup code;
  - session ids, CSRF tokens, API tokens, the CSRF key.
- **Decide like a professional, and write decisions down.** Any deviation from the plan gets a line in the ledger: `Ruling: <what> — <why> — <cost if wrong>`.
- **The design bar is high** ("really well designed"):
  - stdlib first;
  - errors carry their package prefix (`auth: …`);
  - comments explain why;
  - every change is test-first.

## How the work has been run

Each milestone follows the same steps:
1. The spec section is turned into a plan in `docs/superpowers/plans/`, with Global Constraints, Review Focus, and tasks with exact interfaces.
2. Each task is implemented test-first.
3. A fresh reviewer checks each task against its brief. Fix rounds repeat until it is approved.
4. Rulings and deferred minors go to the ledger.
5. After the last task, a whole-branch review drives one fix wave.
6. The branch goes up as a PR, with evidence (test results, `test/e2e/results/*.json`). The owner merges it.

You don't need any particular tool for this; any assistant can follow it. Claude Code users with the superpowers plugin get it as skills: `writing-plans`, `subagent-driven-development` and `executing-plans`. Those skills keep their working files in the git-ignored `.superpowers/sdd/<plan>/`. The files in `m2c/` here are a copy of that workspace.

The copied files mention absolute paths such as `/home/user/tikray/.claude/worktrees/m2c-auth` and `/tmp/claude-0/...`. Those belonged to the original cloud machine; read them relative to the repository root. Branch `m2c-auth` in those files is now `claude/serene-goldberg-1as8mu`. The "Bash tool refuses loops" rule in `context.md` was specific to that machine.

## Setting up a machine

tikray builds and tests **only on Linux**. It runs in RouterOS's Linux containers and uses Linux system calls (`flock`, netlink), so `go test` doesn't compile on plain Windows or macOS. On Windows, use **WSL2 with Ubuntu**.

On Linux or WSL2 Ubuntu, from the repository root:

```
scripts/dev-setup.sh         # installs make, git, gcc and Go (if missing), then runs make test
scripts/dev-setup.sh --lab   # also installs the RouterOS lab's tools (QEMU and the rest) and Docker
```

Some countries can't reach Google's Go servers (go.dev, proxy.golang.org).
- The script installs Ubuntu's own Go package first.
- When proxy.golang.org is unreachable, it sets `GOPROXY=https://goproxy.io,direct` with `go env -w`.
- `go.sum` and Go's checksum database, reached through the mirror, still verify every module and toolchain download.

The owner's Windows checkout is `C:\Users\Arman\Desktop\hakir\Projects\tikray`. In WSL that same folder is `/mnt/c/Users/Arman/Desktop/hakir/Projects/tikray`.
- Clone it from inside WSL (`git clone -b claude/serene-goldberg-1as8mu https://github.com/Arman2122/tikray.git`).
- An editor or AI tool running on Windows edits the files in place, but must run every build or test command through WSL, e.g.:
  ```
  wsl -e bash -lc "cd /mnt/c/Users/Arman/Desktop/hakir/Projects/tikray && make test"
  ```
- `.gitattributes` keeps every file on Unix line endings, even in a checkout made by Git for Windows. The scripts and the byte-compared test files break with CRLF.
- Builds on `/mnt/c` are slower than in WSL's own filesystem, but they work.

## Testing

| What | Command | Needs |
|---|---|---|
| Unit tests and vet | `make test` | Go 1.24 |
| Race | `go test -race ./cmd/... ./internal/...` | Go |
| Compat against real xray releases | `sudo --preserve-env=PATH,HOME,GOPATH,GOMODCACHE,GOCACHE go test -tags compat -count=1 ./test/compat/...` | Network (downloads releases into `~/.cache/tikray-lab/xray`), root for TUN on releases before 26.10. `TIKRAY_COMPAT_VERSIONS` overrides the versions. |
| Images | `make images` | Docker with the **classic** image store (`{"features":{"containerd-snapshotter":false}}`); RouterOS can't import containerd archives |
| Lab, end to end on RouterOS CHR | `make lab-deps`, then e.g. `TIKRAY_LAB_CHANNEL=stable go test -tags lab -p 1 -count=1 -v -timeout 240m -run 'TestService' ./test/e2e/` | Linux host or WSL2 Ubuntu, root, QEMU, Docker. No KVM: CHR runs under QEMU's TCG emulation, x86_64 in minutes and arm64 slower. `TIKRAY_LAB_ARCH` picks the architecture. |

To repeat an exact RouterOS run after the channel moves, set
`TIKRAY_LAB_CHANNEL` to the version, for example `7.25` or `7.23.8`. After
`make images`, set `TIKRAY_LAB_IMAGES` to the absolute path of `out/` so each
suite uses those archives with dockerd stopped. Leave it unset to build at
deploy time. The build uses Buildx and checks the image platform before export.

How the lab works:
- **What it builds:** `test/lab` fetches CHR images and builds a fake LAN and a fake internet from bridges and network namespaces. CHR boots in QEMU between them.
- **Addresses:** the bridge is 172.31.255.0/29, with the router at .1, tikray at .2 and the runner at .3. The runner listens on control :8080, SOCKS 1080 and the xray API 10085.
- **The fake internet:** `labinet` serves VLESS servers lab-a and lab-b (listen on 10.77.113.10 and .11, exit through 203.0.113.10 and .11), plus whoami and subscriptions at 203.0.113.30:80.
- **Results:** they are written to `test/e2e/results/<ros>-<arch>-<suite>.json`. A filtered run writes `-partial.json`, which is git-ignored.

Lab habits that saved time:
- Run lab tests in the background with a log file and bounded waits.
- Kill leftover QEMU processes by PID, never with `pkill -f`.
- Start dockerd for an image build and stop it afterwards.

CI (`.github/workflows/ci.yml`) runs `make test`, the compat suite on the oldest and the newest two xray releases, and the image builds on every push and PR. The lab doesn't run in CI.

## Code map

| Path | What |
|---|---|
| `cmd/tikray` | Control plane: `tikray serve` and the CLI |
| `cmd/tikray-runner` | Data-plane runner: PID 1 of its container |
| `internal/store` | Desired state: servers, subscriptions, devices, policies, routing, DNS, health; validation |
| `internal/render` | State → xray config (inbounds, outbounds, balancers, rules, DNS); `Features` gates by xray version |
| `internal/sharelink` | vless/trojan/vmess/ss links → outbounds |
| `internal/subscription` | Parse, merge with stable IDs, and fetch (direct or through the proxy) |
| `internal/xraypolicy` | Outbounds the newest xray refuses |
| `internal/xrayver` | xray release versions and assets |
| `internal/artifacts` | Core fetch, verification, slots, update and rollback; config apply (trial or hot) |
| `internal/runner`, `internal/runner/netsetup` | Runner: supervisor, trial protocol, state files, container networking |
| `internal/runnerapi` | Runner wire types and client |
| `internal/service` | `serve`'s core: state owner, apply loop, mutations, subscriptions, events |
| `internal/health` | Runner, observatory, balancer and SOCKS-probe health |
| `internal/xray` | Minimal gRPC (h2c) client for xray's stats, observatory and routing |
| `internal/api`, `internal/apiclient` | HTTPS API (pinned self-signed certificate) and its client |
| `internal/auth` | Admin, setup code, sessions, tokens, CSRF, rate limiter |
| `internal/atomicfile` | Crash-safe file replacement |
| `deploy/` | Dockerfiles (runner, and tikray on pinned `busybox:1.37.0-musl`) |
| `test/lab`, `test/e2e`, `test/compat` | RouterOS lab harness, end-to-end suites, xray release compat |
| `spike/m0` | The M0 data-path spike |

## Files in this folder

- `README.md`: this page.
- `m2c/ledger.md`: the M2c execution ledger, holding the pre-flight table, every ruling, deferred minors and progress lines.
- `m2c/context.md`: M2c global constraints and fixed values.
- `m2c/reviewer-instructions.md`: what a task reviewer checks and how it reports.
- `m2c/task-7-*`, `m2c/task-8-brief.md`, `m2c/task-9-*`: the briefs, carries and report for the tasks left.
- `decisions/m0..m2b-decisions.md`: each finished milestone's rulings, carries and deferred minors.
