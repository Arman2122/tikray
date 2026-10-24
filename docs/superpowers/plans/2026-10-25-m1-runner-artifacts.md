# M1: runner and artifacts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the real `tikray-runner` (data plane with the trial protocol) and the artifacts pipeline (fetch chain, verification, slots), so that an xray-core update and rollback work end to end on RouterOS CHR.

**Architecture:** The runner is PID 1 in its container. It sets up routing (ported from M0's `runnerproto`), supervises xray from `/data/run/active.json` and runs the A/B trial protocol behind a token-protected HTTP API. The control-plane side is a library (`internal/artifacts`) plus a minimal `tikray` CLI. The CLI fetches a release through the fallback chain, verifies it, installs it into a slot, asks the runner to trial it, health-checks through the runner's SOCKS inbound, and then commits it or lets the trial revert. M2 wraps the same library in the REST API and UI.

**Tech Stack:** Go 1.24 (module `github.com/Arman2122/tikray`), `github.com/vishvananda/netlink`, `golang.org/x/net/proxy` (SOCKS5), stdlib `crypto/ecdsa` for the hash-index signature, `archive/zip`. Images are `FROM scratch`, saved with the classic Docker image store. The lab is the M0 `test/lab` harness.

**Spec:** `docs/superpowers/specs/2026-10-24-tikray-design.md` (§3.3, §3.5, §4.1–4.5, §4.9, §7, §8.1–8.4). Findings that bind this plan: `docs/superpowers/findings/2026-10-24-m0-data-path.md`.

## Global Constraints

- xray-core minimum **26.1.18** (first release with the TUN inbound); the lab and CI follow the newest XTLS release tag.
- No image contains an xray binary or geo data (§3.1).
- Storage layout §3.5: `/data/cores/<ver>/` (xray + `meta.json`), `/data/geo/<ver>/`, `/data/run/` (`active.json`, `candidate.json`, `config/<hash>.json`, `runner.token`), `/data/state/` (tikray only, `0600` secrets), `/data/inbox/`.
- The runner gets `/data/cores` and `/data/geo` read-only and `/data/run` read-write; `tikray` gets `/data` read-write.
- Files RouterOS places have no execute bit: the runner always runs a staged copy (mode 0755) of the core, never the file on the mount (M0).
- The runner's control API, SOCKS and DNS listen only on the bridge; the control API requires the token (§7).
- Trial protocol exactly as §3.3: `xray run -test` first; an exit within **10 s** reverts; no commit before the deadline (default **120 s**) reverts; commit replaces `active.json` atomically; boot always starts from `active.json`.
- The runner answers ping only while xray runs with its routes in place, and table 1001 holds a low-priority `unreachable` default (M0 fix pass).
- Verification §4.3: SHA-256 from upstream's `.dgst`, which is always fetched from upstream (direct or through the proxy), even when the binary came from a mirror. The signed hash index is only a fallback. Manual files with no known hash need explicit confirmation.
- Fetch chain order §4.2: direct → through the proxy (only while xray is healthy) → mirrors (`{version}`, `{arch}`, `{file}` templates) → `/data/inbox`.
- Images: `FROM scratch` + `COPY` only, archives from `docker save` with the classic store (`"containerd-snapshotter": false`); containers need explicit `dns=` (M0).
- ARM64 is the product target; amd64 images exist for CHR tests only. ARM64 CHR runs on QEMU `-cpu cortex-a72` (M0).
- Commits are authored `Arman2122 <arman.seyri@gmail.com>` with no `Co-Authored-By` or other trailers.

## Review Focus

1. **Version strings from users and files** (`v26.10.21`, `26.10.21`, `latest`, `../../etc`, empty): normalized or refused before any path is built from them. Pinned in Task 1 (`TestParseRejects`) and Task 2 (`TestSelectionValidate`).
2. **A reboot, runner restart or crash between the steps of a commit** (`active.json` renamed but `candidate.json` not yet removed): the runner boots into the committed selection and doesn't report a failed trial. Pinned in Task 5 (`TestBootAfterCommitCrash`).
3. **The router's clock jumping during a trial** (RouterOS often boots unsynced and NTP corrects it later): the deadline is converted into a monotonic timer once, at trial start, so a jump neither reverts early nor never reverts. Pinned in Task 5 (`TestDeadlineIsMonotonic`).
4. **Garbage or oversized downloads** (a mirror returning an HTML error page with status 200, an endless body, a zip without `xray`, a zip whose `xray` is a symlink or a path like `../xray`): capped, rejected, and never installed. Pinned in Task 8 (`TestChainSizeCap`) and Task 10 (`TestInstallRejects`).
5. **Two updates at once** (CLI twice, later the M2 scheduler plus a user): the second waits for or refuses the artifacts lock, and the runner refuses a second trial with 409. Pinned in Task 5 (`TestTrialBusy`) and Task 11 (`TestUpdateLocked`).

---

## File structure

```
internal/xrayver/            version parsing, comparison, release asset names
internal/runnerapi/          wire types shared by runner and control plane, HTTP client
internal/runner/             state files, token, supervisor, trial protocol, HTTP server
internal/runner/netsetup/    linux-only routing and gateway signal (from M0 runnerproto)
internal/runner/testdata/fakexray/   fake xray used by unit tests (mode set by -ldflags)
internal/artifacts/          fetch chain, verification, core slots, update orchestration, history
cmd/tikray-runner/           runner entrypoint
cmd/tikray/                  minimal CLI: core update|rollback|list|status (M2 adds the daemon)
deploy/runner.Dockerfile, deploy/tikray.Dockerfile
scripts/build-images.sh      both images for amd64|arm64 → out/<name>-<arch>.tar
test/e2e/                    CHR end-to-end test of the core lifecycle (build tag lab)
test/lab/fixtures/labinet/   + releases handler (fake GitHub releases and a mirror)
```

Rulings this plan makes where the spec is silent (an executor carries them; add them to the spec in the task that owns them):
- Wire types live in a new package `internal/runnerapi`, so the runner and the control plane share one definition (§9 lists no package for it).
- The runner API also gets `abort`, so a failed health check ends a trial at once instead of waiting out the 120 s deadline (§3.3 lists status, reload, restart, trial, commit, xray-api).
- The control API listens on `<runner bridge address>:8080`, plain HTTP with a bearer token (the bridge is private; M0 used the same port).
- `GOMEMLIMIT` for xray defaults to `128MiB` (runner env `XRAY_GOMEMLIMIT`; `off` leaves it unset). M0 measured xray at about 29 MB RSS.
- In M1 the `tikray` image is `FROM scratch` with a CA bundle; the busybox base (§9) comes with the M3 installer, which is what needs `/container/shell`.
- The hash index signature is a cosign *key-pair* blob signature (base64 ASN.1 ECDSA P-256 over SHA-256 of the file), verified with the standard library. The release key and the publishing workflow come in M5; M1 takes the public key from configuration.
- Geo bundles use the same slot layout and the runner already honours `geo` in a selection; geo *sources* and the address-list sync belong to M3 (they need the reconciler).

---

### Task 1: xray versions and release assets

**Files:**
- Create: `internal/xrayver/xrayver.go`
- Test: `internal/xrayver/xrayver_test.go`

**Interfaces:**
- Produces:
  - `type Version struct{ Major, Minor, Patch int }`
  - `func Parse(s string) (Version, error)`: accepts `26.10.21` and `v26.10.21`; refuses anything else (including `latest`, which callers resolve first).
  - `func (v Version) String() string`, which returns `26.10.21` and is the slot directory name.
  - `func (v Version) Tag() string`, which returns `v26.10.21`.
  - `func (v Version) Less(o Version) bool`
  - `var MinTUN = Version{26, 1, 18}`
  - `func AssetName(goarch string) (string, error)`: `arm64` → `Xray-linux-arm64-v8a.zip`, `amd64` → `Xray-linux-64.zip`; any other value is an error.

- [ ] **Step 1: Write the failing tests**

```go
func TestParse(t *testing.T) {
	for in, want := range map[string]string{"26.10.21": "26.10.21", "v26.1.18": "26.1.18", "v26.3.27": "26.3.27"} {
		v, err := Parse(in)
		if err != nil || v.String() != want || v.Tag() != "v"+want {
			t.Errorf("Parse(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
}
func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "latest", "26.10", "26.10.21.1", "../../etc", "26.10.21/../x", "v26.x.1", " 26.10.21", "-1.2.3"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}
func TestLessAndMin(t *testing.T) {
	a, _ := Parse("26.3.27")
	b, _ := Parse("26.10.21")
	if !a.Less(b) || b.Less(a) || MinTUN.String() != "26.1.18" {
		t.Error("ordering is numeric per field, MinTUN is 26.1.18")
	}
}
func TestAssetName(t *testing.T) {
	if n, _ := AssetName("arm64"); n != "Xray-linux-arm64-v8a.zip" {
		t.Error(n)
	}
	if n, _ := AssetName("amd64"); n != "Xray-linux-64.zip" {
		t.Error(n)
	}
	if _, err := AssetName("mips"); err == nil {
		t.Error("mips accepted")
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/xrayver`. Expected: FAIL (package doesn't compile: `Parse` undefined).
- [ ] **Step 3: Implement** `internal/xrayver/xrayver.go` with the signatures above (one regexp `^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).
- [ ] **Step 4: Run** `go test ./internal/xrayver`. Expected: `ok`.
- [ ] **Step 5: Commit** `git add internal/xrayver && git commit -m "Add xray version parsing and release asset names"`

### Task 2: Runner wire types and client

**Files:**
- Create: `internal/runnerapi/types.go`, `internal/runnerapi/client.go`
- Test: `internal/runnerapi/types_test.go`, `internal/runnerapi/client_test.go`

**Interfaces:**
- Consumes: `xrayver.Parse` (Task 1).
- Produces:
  - `type Selection struct { Core string `json:"core"`; Geo string `json:"geo,omitempty"`; Config string `json:"config"` }`. `Core` is a version directory under `/data/cores`, `Geo` one under `/data/geo` (empty = none), and `Config` is `config/<64 lowercase hex>.json`, relative to `/data/run`.
  - `func (s Selection) Validate() error`: `Core` must parse with `xrayver.Parse` and be in its `String()` form; `Geo` must match `^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$` and must not contain `..`; `Config` must match `^config/[0-9a-f]{64}\.json$`.
  - `type Candidate struct { Selection; Deadline time.Time `json:"deadline"` }`
  - `type TrialResult struct { Candidate Candidate `json:"candidate"`; Outcome string `json:"outcome"`; Detail string `json:"detail,omitempty"`; At time.Time `json:"at"` }`. The outcomes are the constants `OutcomeCommitted = "committed"`, `OutcomeRejected = "rejected"` (`-test` failed), `OutcomeExited = "exited"` (the candidate exited during the trial), `OutcomeDeadline = "deadline"`, `OutcomeAborted = "aborted"` and `OutcomeReboot = "reboot"` (the runner started while a trial was open).
  - `type Status struct { State string `json:"state"`; Active *Selection `json:"active,omitempty"`; Candidate *Candidate `json:"candidate,omitempty"`; XrayPID int `json:"xray_pid"`; XrayVersion string `json:"xray_version,omitempty"`; RoutesOK bool `json:"routes_ok"`; GatewayUp bool `json:"gateway_up"`; LastTrial *TrialResult `json:"last_trial,omitempty"` }`. The states are the constants `StateEmpty = "empty"` (no active selection), `StateRunning = "running"`, `StateRestarting = "restarting"` (backoff after a crash) and `StateTrial = "trial"`.
  - `type XrayAPIRequest struct { Args []string `json:"args"` }` and `type XrayAPIResponse struct { ExitCode int `json:"exit_code"`; Stdout string `json:"stdout"`; Stderr string `json:"stderr"` }`
  - `type TestFailedError struct{ Output string }` (from `Trial` when `xray run -test` fails), `var ErrBusy`, `var ErrNoTrial`.
  - `type Client struct { BaseURL string; Token string; HTTP *http.Client }` with the methods `Status(ctx) (Status, error)`, `Trial(ctx) error`, `Commit(ctx) error`, `Abort(ctx) error`, `Restart(ctx) error`, `Reload(ctx) error` and `XrayAPI(ctx, args ...string) (XrayAPIResponse, error)`. They map 409 → `ErrBusy` or `ErrNoTrial` by the response body's `error` code, 422 → `*TestFailedError`, and any other non-2xx to an error with the body.
  - The routes are fixed here and used by Task 6: `GET /v1/status`, and `POST` to `/v1/trial`, `/v1/commit`, `/v1/abort`, `/v1/restart`, `/v1/reload` and `/v1/xray-api`. Every route needs `Authorization: Bearer <token>`. Error bodies are `{"error":"busy"|"no_trial"|"test_failed"|"bad_request"|"unauthorized", "detail": "..."}`.

- [ ] **Step 1: Write the failing tests**

```go
func TestSelectionValidate(t *testing.T) {
	ok := Selection{Core: "26.10.21", Config: "config/" + strings.Repeat("a", 64) + ".json"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Selection{
		{Core: "v26.10.21", Config: ok.Config}, {Core: "../26.10.21", Config: ok.Config},
		{Core: "26.10.21", Config: "../active.json"}, {Core: "26.10.21", Config: "config/x.json"},
		{Core: "26.10.21", Geo: "..", Config: ok.Config}, {Core: "26.10.21", Geo: "a/b", Config: ok.Config},
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}
func TestClientMapsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/trial":
			w.WriteHeader(422)
			w.Write([]byte(`{"error":"test_failed","detail":"failed to load config"}`))
		case "/v1/commit":
			w.WriteHeader(409)
			w.Write([]byte(`{"error":"no_trial"}`))
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	var tf *TestFailedError
	if err := c.Trial(context.Background()); !errors.As(err, &tf) || tf.Output != "failed to load config" {
		t.Errorf("Trial: %v", err)
	}
	if err := c.Commit(context.Background()); !errors.Is(err, ErrNoTrial) {
		t.Errorf("Commit: %v", err)
	}
	c.Token = "wrong"
	if _, err := c.Status(context.Background()); err == nil {
		t.Error("bad token accepted")
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/runnerapi`. Expected: FAIL (types undefined).
- [ ] **Step 3: Implement** the types and the client (`encoding/json`, 10 s default timeout when `HTTP` is nil).
- [ ] **Step 4: Run** `go test ./internal/runnerapi`. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add the runner API types and client"`

### Task 3: Runner state files and token

**Files:**
- Create: `internal/runner/state.go`
- Test: `internal/runner/state_test.go`

**Interfaces:**
- Consumes: `runnerapi.Selection`, `Candidate`, `TrialResult` (Task 2).
- Produces: `type Dirs struct{ Data string }` with the path methods `Run()`, `Cores()`, `Geo()`, `Active()`, `CandidateFile()`, `LastTrial()`, `Token()`, `CoreBinary(ver string)`, `GeoDir(ver string)` and `ConfigPath(rel string)`.
  - `func ReadActive(d Dirs) (*runnerapi.Selection, error)`: `nil, nil` when the file is missing.
  - `func WriteActive(d Dirs, s runnerapi.Selection) error`
  - `func ReadCandidate(d Dirs) (*runnerapi.Candidate, error)`
  - `func RemoveCandidate(d Dirs) error`
  - `func WriteLastTrial(d Dirs, r runnerapi.TrialResult) error`
  - `func ReadLastTrial(d Dirs) (*runnerapi.TrialResult, error)`
  - `func LoadOrCreateToken(d Dirs) (string, error)`: 32 random bytes as hex, mode 0600; it reuses an existing non-empty file.
  - `func writeAtomic(path string, data []byte, mode os.FileMode) error`: a temp file in the same directory, then `fsync`, `rename` and an `fsync` of the directory. Every write above goes through it.
  - Read functions validate what they read (`Selection.Validate`) and return an error for invalid content instead of acting on it.

- [ ] **Step 1: Write the failing tests:** `TestActiveRoundTrip` (write, read, equal; missing → `nil, nil`), `TestReadActiveRejectsInvalid` (a file with `"core":"../x"` → error), `TestWriteAtomicLeavesNoTemp` (after 20 writes the directory holds only the target file), and `TestTokenStable`:

```go
func TestTokenStable(t *testing.T) {
	d := Dirs{Data: t.TempDir()}
	os.MkdirAll(d.Run(), 0o755)
	a, err := LoadOrCreateToken(d)
	b, _ := LoadOrCreateToken(d)
	fi, _ := os.Stat(d.Token())
	if err != nil || len(a) != 64 || a != b || fi.Mode().Perm() != 0o600 {
		t.Errorf("token %q %q mode %v err %v", a, b, fi.Mode(), err)
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/runner -run 'Active|Atomic|Token'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `state.go`.
- [ ] **Step 4: Run** the same command. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add the runner's state files and token"`

### Task 4: Supervisor (stage, run, test, version)

**Files:**
- Create: `internal/runner/supervisor.go`, `internal/runner/testdata/fakexray/main.go`, `internal/runner/fake_test.go` (builds the fakes once per test binary)
- Test: `internal/runner/supervisor_test.go`

**Interfaces:**
- Consumes: `Dirs` (Task 3), `runnerapi.Selection`.
- Produces:
  - `type SupervisorConfig struct { Dirs Dirs; StageDir string; GoMemLimit string; StopGrace time.Duration; Log io.Writer }`. `StageDir` is `/run/xray` in the container. `GoMemLimit` set to `""` leaves GOMEMLIMIT unset. `StopGrace` defaults to 5 s.
  - `type Exit struct { Selection runnerapi.Selection; Err error; Ran time.Duration }`
  - `func NewSupervisor(c SupervisorConfig) *Supervisor`
  - `(*Supervisor) Stage(sel) (path string, err error)`: copies `cores/<ver>/xray` to `<StageDir>/<ver>/xray` with mode 0755 and reuses an existing staged copy of the same size.
  - `(*Supervisor) Test(ctx, sel) (output string, err error)`: runs `xray run -test -c <config>` with the staged binary.
  - `(*Supervisor) Start(sel) error`: stops the running process first (SIGTERM, then SIGKILL after `StopGrace`), then starts `xray run -c <config>`.
  - `(*Supervisor) Stop() error`
  - `(*Supervisor) Exits() <-chan Exit`: every exit that `Stop` or `Start` didn't ask for.
  - `(*Supervisor) PID() int`
  - `(*Supervisor) Version(sel) (string, error)`: the first line of `xray version`.
  - Every xray process gets `XRAY_LOCATION_ASSET=<geo dir>` when `sel.Geo` is set, `GOMEMLIMIT` when configured, and stdout/stderr to `Log`.
- The fake xray (`testdata/fakexray`, built with `-ldflags "-X main.mode=<mode>"`) handles three calls:
  - `version` prints `Xray 99.0.0 (fake <mode>)`.
  - `run -test -c F`: in mode `badconfig` it prints `Failed to start: failed to load config` and exits 23; otherwise it prints `Configuration OK.` and exits 0.
  - `run -c F` first prints `env GOMEMLIMIT=<v> XRAY_LOCATION_ASSET=<v>`. In mode `ok` it then serves until SIGTERM and exits 0, in mode `exit2s` it exits 1 after 2 s, and in mode `exit15s` it exits 1 after 15 s.
  - `fake_test.go` builds the modes `ok`, `badconfig`, `exit2s` and `exit15s` into `t.TempDir()`-style shared dirs in `TestMain`. A helper `installFake(t, d Dirs, ver, mode string)` copies one into `cores/<ver>/xray` with mode **0644**, which mirrors RouterOS's missing execute bit.

- [ ] **Step 1: Write the failing tests:**
  - `TestStageRunsWithoutExecBit`: installs the fake `ok` core at 0644, then `Start` must succeed and `PID() > 0`. The log must contain `env GOMEMLIMIT=128MiB` when `GoMemLimit: "128MiB"`.
  - `TestTestReportsFailure`: on a `badconfig` core, `Test` returns an error and output containing `failed to load config`.
  - `TestUnexpectedExitReported`: on an `exit2s` core, `Exits()` delivers one `Exit` with `Ran` between 1.5 s and 5 s.
  - `TestStopIsNotAnExit`: `Start` then `Stop` delivers nothing on `Exits()` within 1 s.
  - `TestGeoEnv`: with `sel.Geo = "g1"` and `geo/g1/` present, the log shows `XRAY_LOCATION_ASSET=<data>/geo/g1`.
- [ ] **Step 2: Run** `go test ./internal/runner -run 'Stage|TestTest|Exit|Geo'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `supervisor.go` (`os/exec`, one goroutine per process waiting on `cmd.Wait`, an `expected` flag set by `Stop`/`Start` to tell requested exits apart).
- [ ] **Step 4: Run** the same command. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add the runner's xray supervisor"`

### Task 5: Trial protocol

**Files:**
- Create: `internal/runner/runner.go`
- Test: `internal/runner/runner_test.go`

**Interfaces:**
- Consumes: Tasks 3–4, `runnerapi` constants and errors.
- Produces: `type Config struct { Supervisor SupervisorConfig; EarlyExit time.Duration; MaxTrial time.Duration; BackoffMin, BackoffMax time.Duration; Now func() time.Time }`. The defaults are `EarlyExit` 10 s (§3.3), `MaxTrial` 1 h (a cap on a candidate's deadline) and backoff from 1 s to 30 s (doubling, reset after 60 s up).
  - `func New(c Config) *Runner`
  - `(*Runner) Boot() error`: resolves an open trial (below), then starts `active.json` if there is one; otherwise the state is `empty`.
  - `(*Runner) Status() runnerapi.Status`. `RoutesOK` and `GatewayUp` are set by Task 7 through `(*Runner) SetNet(routesOK, gatewayUp bool)`.
  - `(*Runner) Healthy() bool`, which is true when xray runs (`PID() > 0`) in state `running` or `trial`.
  - `(*Runner) Trial(ctx) error` reads `candidate.json`. It returns `ErrBusy` when a trial is already running, a validation error for a bad candidate or a deadline not in the future, and `*runnerapi.TestFailedError` when `-test` fails (outcome `rejected`; the active process keeps running untouched). Otherwise it starts the candidate and returns once the candidate is running (state `trial`).
  - `(*Runner) Commit() error`: `ErrNoTrial` outside a trial.
  - `(*Runner) Abort() error`: `ErrNoTrial` outside a trial.
  - `(*Runner) Restart(ctx) error` and `(*Runner) Reload(ctx) error`. `Reload` re-reads `active.json` and starts it.
- Required behaviour:
  - At trial start, the deadline becomes `timer := time.NewTimer(min(cand.Deadline.Sub(Now()), MaxTrial))`. It is never compared against the wall clock again.
  - Any exit of the candidate during the trial reverts (outcome `exited`). The 10 s `EarlyExit` is the minimum time the control plane must wait before health-checking (Task 11 waits for it), not a limit on reverting.
  - Revert means: stop the candidate, remove `candidate.json`, start `active.json` (or go `empty` if there is none), and write `last-trial.json` with the outcome.
  - Commit means: `WriteActive(candidate.Selection)`, then `RemoveCandidate`, then `last-trial.json` with outcome `committed`. The candidate process keeps running and becomes the active one; there is no restart.
  - At boot, a `candidate.json` whose selection equals `active.json`'s is the remnant of a commit interrupted after the rename: remove it silently. Any other `candidate.json` gets outcome `reboot` and is removed. Boot then starts `active.json`.
  - Crashes outside a trial are restarted with backoff (state `restarting` while waiting).

- [ ] **Step 1: Write the failing tests** (fake cores from Task 4, `EarlyExit: 200 * time.Millisecond`, backoff 50 ms to 200 ms):
  - `TestBootEmpty`: no `active.json` → state `empty`, `PID() == 0`.
  - `TestTrialCommit`: active `26.1.18` (`ok`), candidate `26.10.21` (`ok`, deadline +5 s). After `Trial` the state is `trial` and the candidate is running. After `Commit` the state is `running`, `ReadActive` gives `26.10.21`, `candidate.json` is gone, the last trial is `committed`, and the PID is unchanged by the commit.
  - `TestTrialRejected`: candidate `badconfig` → `*TestFailedError`; the active PID is unchanged, the state is `running` and the last trial is `rejected`.
  - `TestTrialExitReverts`: candidate `exit2s` → within 4 s the state is `running` on `26.1.18` and the last trial is `exited`.
  - `TestTrialLateExitReverts`: candidate `exit15s` with a 30 s deadline → after the exit (about 15 s, past `EarlyExit`), it reverts with `exited`.
  - `TestTrialDeadlineReverts`: deadline +500 ms and no commit → within 2 s it reverts with `deadline`.
  - `TestDeadlineIsMonotonic`: `Now` returns a time 1 h *behind* the real clock while the candidate's deadline is `Now()+500ms`. It must revert within 2 s, which proves the timer came from the duration and not from a later wall-clock comparison. The reverse case: `Now` jumps 1 h *ahead* after `Trial` returns; there must be no revert within 300 ms.
  - `TestTrialBusy`: a second `Trial` during a trial → `ErrBusy`.
  - `TestAbort`: `Abort` during a trial → revert with `aborted`; `Abort` outside a trial → `ErrNoTrial`.
  - `TestBootDuringTrial`: write `active.json` and a different `candidate.json`, then `Boot` → active running, candidate file gone, last trial `reboot`.
  - `TestBootAfterCommitCrash`: `active.json` and `candidate.json` with the same selection, then `Boot` → active running, candidate gone, and `last-trial.json` unchanged (absent in this test).
  - `TestCrashRestartsWithBackoff`: active `exit2s` → the PID changes after a restart and the state passes through `restarting`.
  - `TestTrialFromEmpty`: no active, candidate `exit2s` → revert to state `empty` with outcome `exited`.
- [ ] **Step 2: Run** `go test ./internal/runner -run 'Boot|Trial|Deadline|Abort|Crash'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `runner.go`: one goroutine owns the state and serializes `Trial`, `Commit`, `Abort`, exits, timer and backoff events over channels. Callers block on a reply channel.
- [ ] **Step 4: Run** the same command, then `go test -race ./internal/runner`. Expected: `ok` both times.
- [ ] **Step 5: Commit** `git commit -m "Add the runner's trial protocol"`

### Task 6: Runner control API

**Files:**
- Create: `internal/runner/server.go`
- Test: `internal/runner/server_test.go`
- Modify: `docs/superpowers/specs/2026-10-24-tikray-design.md` §3.3 (add `abort` to the API list and "listens on the bridge address, port 8080")

**Interfaces:**
- Consumes: `*Runner` (Task 5), the routes and error bodies from Task 2.
- Produces: `func NewServer(r *Runner, token string, xrayAPI func(ctx context.Context, args []string) runnerapi.XrayAPIResponse) http.Handler`. `xrayAPI` runs `<staged active core> api <args...>` with a 10 s timeout. Task 7 wires it to the supervisor; tests pass a stub.
  - Token compare is `subtle.ConstantTimeCompare`. A bad or missing token gets 401 and the body `{"error":"unauthorized"}`.
  - `/v1/xray-api` refuses an empty `args` with 400 `bad_request`, and returns 503 `{"error":"no_xray"}` when no xray is running (the client maps 503 to a plain error).

- [ ] **Step 1: Write the failing tests** with `httptest` and a real `*Runner` on fake cores:
  - `TestServerAuth`: every route without the token → 401.
  - `TestServerTrialFlow`: drives the client from Task 2 against the server: `Trial` → `Status().State == "trial"` → `Commit` → `"running"`.
  - `TestServerTestFailed`: a `badconfig` candidate → the client gets `*TestFailedError` containing `failed to load config`.
  - `TestServerXrayAPI`: the stub returns `{ExitCode:0, Stdout:"ok"}` and the client receives the same.
- [ ] **Step 2: Run** `go test ./internal/runner -run Server`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `server.go` with `http.ServeMux` method patterns (`"POST /v1/trial"`, Go 1.22+).
- [ ] **Step 4: Run** the same command. Expected: `ok`.
- [ ] **Step 5: Commit** spec edit and code: `git commit -m "Add the runner's control API"`

### Task 7: Network setup, runner binary and images

**Files:**
- Create: `internal/runner/netsetup/netsetup_linux.go`, `internal/runner/netsetup/decide.go` (pure, all platforms)
- Test: `internal/runner/netsetup/decide_test.go`
- Create: `cmd/tikray-runner/main.go`, `deploy/runner.Dockerfile`, `deploy/tikray.Dockerfile`, `scripts/build-images.sh`
- Modify: `.github/workflows/ci.yml` (image job), `Makefile` (`images` target)

**Interfaces:**
- Consumes: `runner.New`, `NewServer`, `LoadOrCreateToken`, `(*Runner).SetNet` and `Healthy`.
- Produces:
  - `decide.go` holds `const TunName = "xray0"`, `TunTable = 1001` and `UnreachablePriority = 100`, plus `func GatewaySysctl(healthy, routesOK bool) string`, which returns `"0"` only when both are true and `"1"` otherwise. The value goes to `/proc/sys/net/ipv4/icmp_echo_ignore_all`.
  - `netsetup_linux.go` holds `func Sysctls() map[string]error` (`ip_forward=1`, `conf.all.rp_filter=0`, `conf.default.rp_filter=0`) and `func Ingress() (netlink.Link, error)` (the link of the IPv4 default route).
  - It also holds `func Keep(ctx context.Context, ingress netlink.Link, healthy func() bool, report func(routesOK, gatewayUp bool))`. Once a second it keeps the `unreachable` default (priority 100) in table 1001; while `xray0` exists, it also keeps `default dev xray0 table 1001` and `iif <ingress> lookup 1001`. It writes the gateway sysctl and calls `report`. This ports `spike/m0/runnerproto` with its M0 fixes.
  - `cmd/tikray-runner` runs, in order: sysctls → ingress → `LoadOrCreateToken` → `New(...).Boot()` → `Keep` → `http.ListenAndServe(<first IPv4 of ingress>:8080, NewServer(...))`. The env is `TIKRAY_DATA` (default `/data`) and `XRAY_GOMEMLIMIT` (default `128MiB`, `off` = unset).
  - `scripts/build-images.sh <amd64|arm64> [outdir=out]` builds both static binaries (`CGO_ENABLED=0 -trimpath -ldflags "-s -w"`) and writes `out/tikray-runner-<arch>.tar` and `out/tikray-<arch>.tar`. The tikray image also gets `/etc/ssl/certs/ca-certificates.crt` copied from the build host. The script refuses to run when `docker info` reports the containerd snapshotter, naming the `daemon.json` fix (from `spike/m0/build-images.sh`).

- [ ] **Step 1: Write the failing test** `TestGatewaySysctl` (the four combinations; only `(true,true)` → `"0"`).
- [ ] **Step 2: Run** `go test ./internal/runner/netsetup`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `decide.go`, `netsetup_linux.go`, `cmd/tikray-runner/main.go`, the Dockerfiles and the script.
- [ ] **Step 4: Run** `go test ./internal/runner/netsetup && GOOS=linux GOARCH=arm64 go build ./cmd/... && bash scripts/build-images.sh arm64 && tar -xOf out/tikray-runner-arm64.tar manifest.json | grep -q '"Layers"' && echo IMAGES_OK`. Expected: `ok` and `IMAGES_OK`.
- [ ] **Step 5: Add the CI job** `images` in `ci.yml`: write `{"features":{"containerd-snapshotter":false}}` to `/etc/docker/daemon.json`, restart docker, run the script for `amd64` and `arm64`, and run the same manifest check. Push and confirm the job is green.
- [ ] **Step 6: Commit** `git commit -m "Add the runner binary, network setup and images"`

### Task 8: Fetch chain

**Files:**
- Create: `internal/artifacts/fetch.go`
- Test: `internal/artifacts/fetch_test.go`

**Interfaces:**
- Consumes: `xrayver.Version`.
- Produces:
  - `type Request struct { Version xrayver.Version; File string; Arch string }`
  - `type Source interface { Name() string; Fetch(ctx context.Context, r Request, w io.Writer) error }`
  - `func Direct(repo string, hc *http.Client) Source`: `GET {repo}/releases/download/{tag}/{file}`, where `repo` defaults to `https://github.com/XTLS/Xray-core`. Its name is `direct`.
  - `func Proxy(socksAddr, repo string, healthy func(context.Context) bool) Source`: the same URL through SOCKS5 (`golang.org/x/net/proxy`). It fails at once with `errProxyUnavailable` when `healthy` returns false. Its name is `proxy`.
  - `func Mirror(template string, hc *http.Client) Source`: the template replaces `{version}` (`26.10.21`), `{arch}` (GOARCH) and `{file}`. Its name is `mirror <host>`.
  - `func Inbox(dir string) Source`: the file `<dir>/<file>`. Its name is `inbox`.
  - `type Chain struct { Sources []Source; MaxBytes int64; Timeout time.Duration }`. The defaults are 200 MiB and 10 min per attempt.
  - `func (c Chain) Fetch(ctx context.Context, r Request, dst string, check func(path string) error) (source string, err error)`. Each source writes `dst + ".part"`. More than `MaxBytes` fails that attempt. `check` runs on the part file. The first attempt that passes is renamed to `dst`. On total failure the error lists every `source: reason`, and no `dst` or `.part` is left.
  - `func Latest(ctx context.Context, sources ...Source) (xrayver.Version, error)`: for `direct` and `proxy` sources only, `GET {repo}/releases/latest` without following redirects, then parses the `Location` path's last element (`/tag/v26.10.21`).
  - Non-2xx status codes are errors. A 200 HTML page is caught by `check`.

- [ ] **Step 1: Write the failing tests** against `httptest` servers:
  - `TestChainOrderAndFallback`: direct returns 503 and the mirror serves the file → source `mirror 127.0.0.1:…`; the inbox is never read.
  - `TestChainCheckRejects`: the first source serves `<html>` with 200 and `check` rejects it, so the second source is used.
  - `TestChainSizeCap`: a source streams forever; with `MaxBytes: 1<<20` the attempt fails, the next source is tried, and no `.part` remains.
  - `TestChainAllFail`: the error mentions every source name; `dst` doesn't exist.
  - `TestChainTimeout`: a source that sends headers and then stalls fails after `Timeout: 200 * time.Millisecond`, and the next source is used.
  - `TestProxySkippedWhenUnhealthy`: with `healthy` false, the SOCKS address is never dialed (use a listener that fails the test on accept).
  - `TestMirrorTemplate`: `http://m/x/v{version}/{arch}/{file}` → `/x/v26.10.21/arm64/Xray-linux-arm64-v8a.zip`.
  - `TestLatest`: a 302 to `/XTLS/Xray-core/releases/tag/v26.10.21` → `26.10.21`; a 302 to `/tag/nightly` → error.
- [ ] **Step 2: Run** `go test ./internal/artifacts -run 'Chain|Proxy|Mirror|Latest'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `fetch.go`. Add `golang.org/x/net` as a direct dependency (`go mod tidy`).
- [ ] **Step 4: Run** the same command. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add the artifact fetch chain"`

### Task 9: Verification

**Files:**
- Create: `internal/artifacts/verify.go`
- Test: `internal/artifacts/verify_test.go`

**Interfaces:**
- Consumes: `Chain`, `Source`, `Request` (Task 8).
- Produces:
  - `func ParseDgst(r io.Reader) (string, error)`: returns the lowercase hex of the `SHA2-256=` or `SHA256=` line. These are the two forms XTLS's `openssl dgst | sed` step writes, depending on the OpenSSL version. A missing line or a value that isn't 64 hex characters is an error.
  - `func FileSHA256(path string) (string, error)`
  - `type Index struct { Version int `json:"version"`; Files map[string]map[string]string `json:"files"` }` maps tag → file → sha256.
  - `func VerifyIndex(data, sigB64 []byte, pubPEM []byte) (*Index, error)`: an ECDSA P-256 public key (PKIX PEM); the signature is base64 ASN.1 over SHA-256 of `data`.
  - `(*Index) Lookup(v xrayver.Version, file string) (string, bool)`
  - `type Verifier struct { Upstream Chain; IndexURLs []string; IndexPub []byte; HTTP *http.Client }`. `Upstream` holds only `direct` and `proxy`.
  - `type Verified struct { SHA256 string; Method string }`, where `Method` is `"dgst"`, `"index"` or `"unverified"`.
  - `func (v Verifier) Expected(ctx context.Context, r Request) (Verified, error)` first fetches `<file>.dgst` through `Upstream`. Only when every upstream attempt fails does it fetch `IndexURLs[i]` and `IndexURLs[i] + ".sig"` and look the file up. When neither works it returns `Verified{Method: "unverified"}` with `ErrNoHash`. A `.dgst` that downloads but doesn't parse is an error, not a reason to fall back to the index.

- [ ] **Step 1: Write the failing tests:**
  - `TestParseDgst`: both line forms from real releases, mixed with the MD5/SHA1/SHA2-512 lines → the right hash. Garbage → error.
  - `TestVerifyIndex`: generate a key in the test and sign with `ecdsa.SignASN1` over `sha256.Sum256(data)`. A good signature passes; one flipped byte in `data` fails; a wrong key fails.
  - `TestExpectedPrefersDgst`: upstream serves a `.dgst` and the index has a *different* hash → the `.dgst` wins (`Method "dgst"`).
  - `TestExpectedFallsBackToIndex`: upstream returns 503 for everything → `Method "index"` with the index hash.
  - `TestExpectedNoHash`: no upstream, no index → `ErrNoHash`.
- [ ] **Step 2: Run** `go test ./internal/artifacts -run 'Dgst|Index|Expected'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `verify.go`.
- [ ] **Step 4: Run** the same command. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add release verification with the hash index fallback"`

### Task 10: Core slots

**Files:**
- Create: `internal/artifacts/slots.go`
- Test: `internal/artifacts/slots_test.go`

**Interfaces:**
- Consumes: `xrayver.Version`, `Verified` (Task 9).
- Produces:
  - `type Meta struct { Version string `json:"version"`; Source string `json:"source"`; ZipSHA256 string `json:"zip_sha256"`; BinarySHA256 string `json:"binary_sha256"`; Verified string `json:"verified"`; InstalledAt time.Time `json:"installed_at"` }`
  - `type Slot struct { Version xrayver.Version; Dir string; Meta Meta }`
  - `func InstallCore(coresDir string, v xrayver.Version, zipPath string, m Meta) (Slot, error)` extracts only the root entry `xray`, which must be a regular file of at most 200 MiB. It writes it at mode 0755 into `coresDir/.tmp-<ver>-<random>/` together with `meta.json`, then renames that directory to `coresDir/<ver>`. An existing slot is an error (`ErrSlotExists`).
  - `func ListCores(coresDir string) ([]Slot, error)`: newest version first. It skips `.tmp-*` directories and directories without a valid `meta.json`.
  - `func CleanTemp(coresDir string) error`
  - `func Prune(coresDir string, keep []string) ([]string, error)` removes every slot whose version isn't in `keep` (and every `.tmp-*`), and returns what it removed. Which versions to keep is the caller's decision (Task 11: the most recently committed ones).

- [ ] **Step 1: Write the failing tests:**
  - `TestInstallAndList`: two zips built in the test → two slots, newest first; `xray` has mode 0755; `meta.json` round-trips.
  - `TestInstallRejects`: each of these leaves no slot and no `.tmp-*`: a zip without `xray`, `xray` as a symlink entry, `../xray`, `bin/xray` only, a 0-byte file, and a non-zip file.
  - `TestInterruptedInstall`: a `.tmp-26.10.21-abc/` left behind → `ListCores` ignores it, `CleanTemp` removes it.
  - `TestPruneKeeps`: slots `26.1.18`, `26.3.27`, `26.10.21` and keep `[26.10.21 26.3.27]` → `26.1.18` removed, the others intact; keeping a version with no slot is fine.
- [ ] **Step 2: Run** `go test ./internal/artifacts -run 'Install|Interrupted|Prune'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `slots.go`.
- [ ] **Step 4: Run** the same command. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add xray core slots"`

### Task 11: Core update and rollback

**Files:**
- Create: `internal/artifacts/core.go`, `internal/artifacts/health.go`, `internal/artifacts/history.go`
- Test: `internal/artifacts/core_test.go`

**Interfaces:**
- Consumes: Tasks 1, 2 (`runnerapi.Client`, `Selection`, `Candidate`), 8, 9 and 10.
- Produces:
  - `type HealthChecker interface { Check(ctx context.Context) error }`
  - `type SOCKSProbe struct { Addr, URL string; Timeout time.Duration }`: a GET through SOCKS5; any 2xx passes.
  - `type XrayAPIProbe struct { Runner *runnerapi.Client; Server string }`: runs `api statssys --server=<Server>` (default `127.0.0.1:10085`); exit 0 passes.
  - `func AllOf(cs ...HealthChecker) HealthChecker`
  - `type CoreUpdater struct { Data string; Arch string; Fetch Chain; Verify Verifier; Runner *runnerapi.Client; Health HealthChecker; Keep int; TrialDeadline time.Duration; EarlyExit time.Duration; HealthWindow time.Duration; Now func() time.Time; Log io.Writer }`. The defaults are `Keep` 2, `TrialDeadline` 120 s, `EarlyExit` 10 s and `HealthWindow` 30 s.
  - `type UpdateOptions struct { ConfigFile string; AllowUnverified bool }`
  - `type Result struct { From string `json:"from,omitempty"`; To string `json:"to"`; Outcome string `json:"outcome"`; Source string `json:"source,omitempty"`; Verified string `json:"verified,omitempty"`; Detail string `json:"detail,omitempty"`; At time.Time `json:"at"` }`. The outcomes are the trial outcomes plus `"unhealthy"` (health failed, trial aborted), `"noop"` (already active) and `"refused"` (below the floor, unverified without consent, or locked).
  - `func (u *CoreUpdater) Update(ctx context.Context, version string, o UpdateOptions) (Result, error)`. `version` is `latest` or a version.
  - `func (u *CoreUpdater) Rollback(ctx context.Context) (Result, error)`
  - `var ErrLocked`
- `Update` runs these steps in order:
  1. Take `flock` on `<data>/state/artifacts.lock` without blocking (on failure: `refused`, `ErrLocked`).
  2. Resolve `latest` with `Latest(ctx, u.Verify.Upstream.Sources...)`.
  3. Refuse a version below `xrayver.MinTUN` (`refused`, detail names 26.1.18).
  4. If the slot exists, skip fetching. Otherwise: `Verify.Expected`. `ErrNoHash` without `AllowUnverified` → `refused`. Then `Fetch.Fetch` with a check that compares `FileSHA256` to the expected hash (or accepts anything when unverified with consent), and `InstallCore`.
  5. The config is `o.ConfigFile` copied to `run/config/<sha256>.json`, or the active selection's config. With neither → error.
  6. Write `run/candidate.json` with the active `Geo` and `Deadline = Now() + TrialDeadline`, then `Runner.Trial`. `*TestFailedError` → `rejected`.
  7. Wait `EarlyExit`, then read `Status`. If the state isn't `trial` with this candidate → the runner's `last_trial` outcome (`exited`).
  8. Retry `Health.Check` until it passes or `HealthWindow` ends. On failure: `Runner.Abort` → `unhealthy`.
  9. `Runner.Commit` → `committed`, then `Prune` keeping the `Keep` most recently committed distinct versions from the history, newest first (the one just committed is first). With the default 2 this is "current and previous" (§4.4); failed candidates' slots go at the next commit.
  10. Append every `Result` as one JSON line to `<data>/state/core-history.jsonl`.
- `Rollback` picks the most recently committed version in the history that differs from the active one and still has a slot, and runs the same flow from step 5 with the active config. No such version → `refused`.

- [ ] **Step 1: Write the failing tests** with a fake runner (`httptest` implementing the Task 2 routes and recording calls), fake sources and a stub `HealthChecker`:
  - `TestUpdateCommits`: from `26.3.27` to `26.10.21` → `committed`; the fake runner saw trial then commit; `candidate.json` has the active config and a deadline 120 s ahead; the history has one line.
  - `TestUpdateRejected`: the fake runner returns 422 → `rejected`, no commit.
  - `TestUpdateUnhealthy`: health always fails → `Abort` called, `unhealthy`, no commit.
  - `TestUpdateRefusesOld`: `26.1.0` → `refused`, nothing fetched.
  - `TestUpdateUnverified`: no hash anywhere → `refused`; with `AllowUnverified` → `committed` and `meta.json` says `unverified`.
  - `TestUpdateNoop`: the active version → `noop`, no trial.
  - `TestUpdateLocked`: hold the lock from the test → `refused`, `ErrLocked`.
  - `TestRollback`: history commits `26.1.18`, `26.3.27`, `26.10.21` (active) → rollback trials `26.3.27`; with only one committed version → `refused`.
  - `TestPruneAfterCommit`: history commits `26.1.18`, `26.3.27`; slots also hold a failed `99.0.1`; commit `26.10.21` → slots left are exactly `26.10.21` and `26.3.27`.
  - `TestUpdateWrongHash`: the mirror serves a zip whose SHA-256 doesn't match the `.dgst` and the inbox has the right one → source `inbox`; when no source matches → an error naming each source, and no slot or `.part` left.
- [ ] **Step 2: Run** `go test ./internal/artifacts -run 'Update|Rollback|PruneAfter'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `core.go`, `health.go`, `history.go` (`syscall.Flock`, linux and darwin build).
- [ ] **Step 4: Run** `go test -race ./internal/artifacts`. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add xray core update and rollback"`

### Task 12: Minimal tikray CLI

**Files:**
- Create: `cmd/tikray/main.go`, `cmd/tikray/config.go`
- Test: `cmd/tikray/config_test.go`

**Interfaces:**
- Consumes: `CoreUpdater` and the rest of Task 11, `runnerapi.Client`, `ListCores`.
- Produces:
  - The commands `tikray core update <version|latest> [--config FILE] [--allow-unverified]`, `tikray core rollback`, `tikray core list` and `tikray core status`.
  - `update` and `rollback` print the `Result` as JSON, write it to `<data>/state/last-result.json` (mode 0600), and exit 0 for `committed`/`noop` and 1 otherwise.
  - `func configFromEnv(getenv func(string) string) (Config, error)` reads:
    - `TIKRAY_DATA` (default `/data`), `TIKRAY_ARCH` (default `runtime.GOARCH`);
    - `TIKRAY_RUNNER_URL` (default `http://172.31.255.3:8080`), `TIKRAY_SOCKS` (default `172.31.255.3:1080`);
    - `TIKRAY_UPSTREAM` (default `https://github.com/XTLS/Xray-core`), `TIKRAY_MIRRORS` (comma-separated templates);
    - `TIKRAY_INDEX_URLS` (comma-separated), `TIKRAY_INDEX_PUBKEY_FILE`;
    - `TIKRAY_PROBE_URL` (default `https://www.gstatic.com/generate_204`).
  - The runner token is read from `<data>/run/runner.token`.
  - Proxy health for the fetch chain is `Runner.Status` with state `running` or `trial` and `gateway_up`.
  - M2 replaces this env configuration with the state store.

- [ ] **Step 1: Write the failing test** `TestConfigFromEnv`: the defaults, an override of each variable, an empty `TIKRAY_MIRRORS` giving no mirrors, and a mirror template without `{file}` → error.
- [ ] **Step 2: Run** `go test ./cmd/tikray`. Expected: FAIL.
- [ ] **Step 3: Implement** `config.go` and `main.go` (stdlib `flag`, one `FlagSet` per subcommand).
- [ ] **Step 4: Run** `go test ./cmd/tikray && go vet ./...`. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add the tikray core CLI"`

### Task 13: Lab release fixtures

**Files:**
- Create: `test/lab/fixtures/labinet/releases.go`
- Test: `test/lab/fixtures/labinet/releases_test.go`
- Modify: `test/lab/fixtures/labinet/cmd/labinet/main.go` (serve it), `test/lab/network.go` and `test/lab/network_lab_test.go` (add `203.0.113.40` and `203.0.113.41` to `tklab-inet` lo), `test/lab/inet.go` (pass the releases root)

**Interfaces:**
- Produces:
  - `func ReleasesHandler(root string) http.Handler` serves `root/<tag>/<file>` at `/XTLS/Xray-core/releases/download/<tag>/<file>`. It answers `/XTLS/Xray-core/releases/latest` with a 302 to `/XTLS/Xray-core/releases/tag/<contents of root/LATEST>`.
  - Its behaviour is switched by flag files the test creates on the host: `root/.down` → 503 for everything; `root/.block-direct` → 403 for callers from `198.51.100.2`, the router's WAN, so only proxied requests (from `203.0.113.10`) get through.
  - `func MirrorHandler(root string) http.Handler` serves `/m/<tag>/<file>`, plus `/index.json` and `/index.json.sig` from `root/index/`.
  - `labinet` serves the fake GitHub on `203.0.113.40:80` and the mirror on `203.0.113.41:80`, with `-releases <dir>`.
  - `func MakeReleaseZip(dst, xrayPath string) (sha256 string, err error)` writes a zip with the `xray` entry plus `README.md`, the way XTLS's archives look, and returns its SHA-256.
  - `func WriteDgst(path, sha256 string) error` writes `MD5= …`, `SHA1= …`, `SHA2-256= <sha>` and `SHA2-512= …` lines.

- [ ] **Step 1: Write the failing tests:**
  - `TestReleasesServe`: a file is served under the tag path; `.down` → 503; `.block-direct` → 403 for `RemoteAddr` `198.51.100.2:1234` and 200 for `203.0.113.10:1234`.
  - `TestLatestRedirect`: Location is `/XTLS/Xray-core/releases/tag/v26.10.21`.
  - `TestMakeReleaseZipInstalls`: the zip from `MakeReleaseZip` installs with `artifacts.InstallCore` (Task 10), proving the fixture and the installer agree.
- [ ] **Step 2: Run** `go test ./test/lab/fixtures/labinet`. Expected: FAIL.
- [ ] **Step 3: Implement** the handlers, helpers and wiring.
- [ ] **Step 4: Run** `go test ./test/lab/fixtures/labinet && go vet -tags lab ./test/lab/...`. Expected: `ok`.
- [ ] **Step 5: Commit** `git commit -m "Add fake GitHub releases and a mirror to the lab"`

### Task 14: Core lifecycle end to end on CHR

**Files:**
- Create: `test/e2e/routeros/m1-setup.rsc`, which is `spike/m0/routeros/setup.rsc` with these changes:
  - the containers are `tikray-runner` (image `tikray-runner-<arch>.tar`) and `tikray` (image `tikray-<arch>.tar`, envs `TIKRAY_UPSTREAM=http://203.0.113.40/XTLS/Xray-core`, `TIKRAY_MIRRORS=http://203.0.113.41/m/v{version}/{file}`, `TIKRAY_INDEX_URLS=http://203.0.113.41/index.json`, `TIKRAY_INDEX_PUBKEY_FILE=/data/state/index.pub`, `TIKRAY_PROBE_URL=http://203.0.113.30/whoami`, `start-on-boot=no`);
  - the runner has no xray selection yet;
  - `tikray` mounts `disk1/tikray/data` at `/data` read-write (it needs `state/` and `inbox/`); the runner keeps M0's mounts (cores and geo read-only, run read-write);
  - the M0 lab additions (`lab-fasttrack.rsc`) are copied as `test/e2e/routeros/lab.rsc`.
- Create: `test/e2e/lab.go` (deploy and helpers), `test/e2e/core_lab_test.go`, `test/e2e/config/xray-client.json`. The config is M0's client config plus a SOCKS inbound on `0.0.0.0:1080` and `"api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]}`, with `"stats": {}`.
- Modify: `Makefile` (`lab` target includes `./test/e2e/...`), `docs/superpowers/specs/2026-10-24-tikray-design.md` §10 (M1 status) and §8.4 (the scenarios that now run).

**Interfaces:**
- Consumes: `test/lab` (`SetupNetwork`, `BootReadyCHR`, `StartInet`, `Push`, `Import`, `Run`, `Get`, `PowerCycle`, `XrayBinaryVersion`, `Arch`), the images from Task 7, the fixtures from Task 13 and the fake cores from Task 4 (built for the target GOARCH).
- Produces:
  - `func runTikray(ctx context.Context, c *lab.CHR, args string) (artifacts.Result, error)`: `/container/set [find name=tikray] cmd="<args>"`, then `/container/start`, poll until the status is `stopped` (10 min on arm64), and read `disk1/tikray/data/state/last-result.json` with `/file/get … contents`.
  - `func runnerStatus(ctx context.Context) (runnerapi.Status, error)`: the host reaches `172.31.255.3:8080` through the lab's host route, with the token read via `/file/get`.

- [ ] **Step 1: Write the test** `TestCoreLifecycle` (build tag `lab`). Before the subtests: build real zips for `26.1.18`, `26.3.27` and the newest release (`lab.ResolveXrayVersion("latest")`), and fake zips `99.0.1` (`badconfig`) and `99.0.2` (`exit2s`). Write `.dgst` files for all of them except `99.0.1`. Sign an index that holds only the `26.3.27` entry and push its public key to `/data/state/index.pub`. Push the client config to `/data/inbox/xray-client.json`. Then, in order:
  1. `bootstrap`: the runner is `empty`. `core update 26.1.18 --config /data/inbox/xray-client.json` → `committed`, source `direct`; the LAN client's `whoami` is `203.0.113.10`.
  2. `update_latest_via_proxy`: create `.block-direct`. `core update latest` → `committed` to the newest release, source `proxy`; the runner's `xray_version` names it; LAN proxied.
  3. `rejected`: `core update 99.0.1 --allow-unverified`. `99.0.1` has no `.dgst`, so the "unverified" path is exercised too. → `rejected`; the runner is still on the newest release; LAN proxied.
  4. `crashing`: `99.0.2` → `exited`; still on the newest release; LAN proxied.
  5. `mirror_and_index`: create `.down`. `core update 26.3.27` → `committed`, source `mirror 203.0.113.41`, verified `index`.
  6. `rollback`: `core rollback` → `committed`, back to the newest release.
  7. `prune`: `/data/cores` holds exactly the newest release and `26.3.27`, since `Keep` is 2.
  8. `reboot_during_trial`:
     - write a `candidate.json` for `26.3.27` with a 10-minute deadline via `/file/add`, and call `Trial` from the host;
     - `PowerCycle`;
     - after boot the runner is `running` on the newest release, `last_trial.outcome` is `reboot` and `candidate.json` is gone.
  9. `gateway_follows_xray`: `core update 99.0.2 --allow-unverified` while polling `gateway_up` → it reads false at least once during the trial and true again afterwards.
- [ ] **Step 2: Run** `TIKRAY_LAB_CHANNEL=stable go test -tags lab -count=1 ./test/e2e -run TestCoreLifecycle -v -timeout 240m`. Expected: PASS on x86_64. Then run it with `TIKRAY_LAB_CHANNEL=long-term` and with `TIKRAY_LAB_ARCH=arm64` on stable. Expected: PASS for both.
- [ ] **Step 3: Update the spec**:
  - §10 M1 → done, with a pointer to this test;
  - §8.4, the update scenarios run now: "xray update, plus an update with a broken binary that must revert";
  - §3.3, the rulings at the top of this plan (`abort`, port, `GOMEMLIMIT` default).
- [ ] **Step 4: Commit** `git commit -m "Test the xray core lifecycle end to end on CHR"`
