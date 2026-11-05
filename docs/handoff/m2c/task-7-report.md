# Task 7 report: compat test of hot outbound changes against real xray

Status: DONE_WITH_CONCERNS

The test is written, runs on every release and records the real behaviour. It FAILS, on purpose
and unweakened, on two findings (below): one on every release, one on the oldest. hot.go is untouched.

Commit: `fb767521ef5ef82d354cf78331ba97aa6d0c491a` on `m2c-auth`
(message `Test hot outbound changes against every xray release tikray supports`, no trailers, not pushed).

Files:
- `/home/user/tikray/.claude/worktrees/m2c-auth/test/compat/hot_test.go` (new): `TestHotAgainstReleases`.
- `/home/user/tikray/.claude/worktrees/m2c-auth/test/compat/xrayapi_test.go`: the config builder split into
  `apiConfigWith(port, probeURL, probeInterval, services, outbounds)`; `apiConfig` calls it with the same
  arguments as before, so M2b's config is byte-identical and `TestXrayAPIAgainstReleases` still passes.

## What the test does

For each release in `compatVersions` (default: `render.Tested[0]` = 26.1.18, and the newest two tags,
26.9.30 and 26.10.21; all three binaries were already in the cache, `git ls-remote` worked) it starts xray
with: `api-in`, API services `HandlerService, RoutingService, StatsService, ObservatoryService` (the order
render uses), the `proxy-open` leastPing balancer over `srv-`, an observatory over `srv-` with
`probeInterval` 2 s, and outbounds `direct` (first, so xray's default is not a server's outbound, as
`hotPlan` requires) then `srv-a` (freedom).

It calls the binary as the runner does (`<bin> api <args>`, no shell, exit code, stdout and stderr kept
apart), in Task 6's exact forms: `rmo --server=<addr> <tag>` and `ado --server=<addr> <file>`, with the
file `{"outbounds":[...]}`, 0600 in a 0700 dir, named `<sha256>.json` (hot.go's `addOutbounds`).
Liveness signals: `OutboundStatus` from `internal/xray` polled up to 30 s (`observeWait`), and
`xray api lso` as the direct check (used when the release has it; all tested ones do).

Each step is its own subtest (`TestHotAgainstReleases/<core>/<step>`), so one failing step does not hide
the others. Every failure reads `xray-core <ver>, step "<step>": ...` and carries the call's exit code,
stdout and stderr (`%q`); every call is logged with `-v`, and xray's own output is logged for a failed
release. Steps:

1. `baseline`: lso = [direct srv-a]; the observatory lists srv-a.
2. `ado adds an outbound`: ado of srv-b exits 0; lso and `OutboundStatus` (within 30 s) list srv-b; `BalancerTargets` logged, not asserted.
3. `rmo removes an outbound`: rmo srv-a exits 0; lso drops it; `OutboundStatus` drops it within 30 s.
4. `rmo of a missing tag` (carry 1): `rmo srv-missing` must exit non-zero and change nothing.
5. `ado of an existing tag` (carry 1): ado of srv-b again must exit non-zero and change nothing.
6. `ado of several outbounds` (carry 1): `[srv-c, srv-d]` in one file exits 0, added in file order, both listed.
7. `ado of several outbounds, one failing` (carry 1): `[srv-e (new), srv-b (exists), srv-f (new)]`: must exit non-zero, stop at srv-b (srv-f never tried, not in lso), leave srv-e in place (not rolled back).
8. `rmo and ado of one tag` (my addition, not in the brief): rmo srv-b, then ado srv-b with other settings, which is how Task 6 sends a changed outbound; exits 0, lso and `OutboundStatus` list it again.

## Results per version and step

PASS = as Task 6 assumes. FAIL = a finding (see below). The default run is 26.1.18, 26.9.30, 26.10.21; I
also ran 26.3.27 and 26.4.13 with `TIKRAY_COMPAT_VERSIONS=v1.260327.0,v26.4.13` to find where finding 2
changes (26.4.13 was built from a shallow clone of the tag, by the lab's own code).

| step | 26.1.18 | 26.3.27 | 26.4.13 | 26.9.30 | 26.10.21 |
|---|---|---|---|---|---|
| 1 baseline | PASS | PASS | PASS | PASS | PASS |
| 2 ado adds | PASS | PASS | PASS | PASS | PASS |
| 3 rmo removes | **FAIL** (finding 2) | **FAIL** (finding 2) | PASS (dropped ~2 s) | PASS (~2 s) | PASS (~2 s) |
| 4 rmo of missing tag | **FAIL** (finding 1) | **FAIL** | **FAIL** | **FAIL** | **FAIL** |
| 5 ado of existing tag | PASS | PASS | PASS | PASS | PASS |
| 6 ado several | PASS | PASS | PASS | PASS | PASS |
| 7 ado several, one failing | PASS | PASS | PASS | PASS | PASS |
| 8 rmo then ado | PASS | PASS | PASS | PASS | PASS |

## Findings (for the controller to rule on; nothing was changed or weakened)

### Finding 1: `rmo` of a tag xray does not have exits 0, on every release

Command: `xray api rmo --server=127.0.0.1:<port> srv-missing`
Result on 26.1.18, 26.3.27, 26.4.13, 26.9.30 and 26.10.21 alike: `exit 0, stdout "removing: srv-missing\n{}\n\n", stderr ""`.
lso is unchanged afterwards. So rmo is idempotent: it never fails on a missing tag. (xray's `RemoveOutbound`
returns success for an unknown tag.) Task 6's assumption that it exits non-zero is wrong everywhere, so
this cannot be gated by version; it is an assumption of Task 6's fake and tests to correct. What this
means for hot.go is the controller's call: a hot change whose rmo hits an outbound that is already gone
carries on instead of falling back to a trial.

Failure line: `xray-core 26.1.18, step "rmo of a missing tag": xray api rmo of a tag xray does not have: exit 0, stdout "removing: srv-missing\n{}\n\n", stderr "", want a non-zero exit`

### Finding 2: before 26.4.13 the observatory never drops a removed outbound's status

Command: `xray api rmo --server=127.0.0.1:<port> srv-a`, then poll `OutboundStatus` for 30 s (2 s probe interval).
- 26.1.18 and 26.3.27: rmo exits 0 (`stdout "removing: srv-a\n{}\n\n"`), lso drops srv-a at once, but
  `OutboundStatus` still lists srv-a after 30 s, frozen: `{Tag:srv-a Alive:true ... LastSeen/LastTry 10:41:01}`
  while srv-b is probed every round (10:41:31). `BalancerTargets(proxy-open)` is `["srv-b"]`, so the
  balancer is right; only the observatory's list is stale. It stays until xray restarts.
- 26.4.13, 26.9.30, 26.10.21: srv-a is gone from `OutboundStatus` about 2 s after rmo (one round).

Cause, from the sources: `app/observatory/observer.go` in v26.1.18..v26.3.27 has
`updateStatus(outbounds) { ... // TODO should remove old inbound that is removed ... }`, a no-op;
v26.4.13 and later call `clearRemovedOutbounds(outbounds)` every round. I fetched `observer.go` at 22 release tags (26.1.18 to 26.10.21): none up to v26.3.27 has
`clearRemovedOutbounds`, every one from v26.4.13 on has it. There is no release tag between 26.3.27 and
26.4.13, so **26.4.13 is the first release that drops it** (confirmed by running the test on both).

Possible effect on tikray (my reading of `internal/health/health.go`, not tested): `serverHealth` matches
the state's members by tag, so a removed server's stale entry is never read. But a tag that comes back
(a changed outbound goes in as rmo then ado of the same tag; or a removed server is enabled again) finds
the old entry, and shows the previous Alive/Delay until the next probe round, one probe interval, on
releases before 26.4.13. `render.Tested[0]` is 26.1.18, so tikray supports these releases. If the
controller wants a gate it would be `render.Features` with Min 26.4.13, but the observatory is the only
thing that differs and the hot calls themselves work on every release.

### Confirmed as Task 6 assumes, identically on all five releases

- **`ado` of an existing tag** (healing relies on it): `exit 1, stdout "adding: srv-b\n", stderr "failed to add outbound: rpc error: code = Unknown desc = app/proxyman/outbound: existing tag found: srv-b\n"`. lso unchanged.
- **`ado` of several outbounds**, all new: `exit 0, stdout "adding: srv-c\n{}\n\nadding: srv-d\n{}\n\n"`: added in file order, both in lso and in `OutboundStatus`.
- **`ado` of several, the second existing** (`[srv-e, srv-b, srv-f]`): `exit 1, stdout "adding: srv-e\n{}\n\nadding: srv-b\n", stderr "failed to add outbound: rpc error: code = Unknown desc = app/proxyman/outbound: existing tag found: srv-b\n"`. It stops at the first failure (srv-f is never tried and is not in lso), and srv-e, added before the failure, stays in place (not rolled back): lso is `[direct srv-b srv-c srv-d srv-e]`. So after a partial ado the running xray holds a part of the change, which is what the marker and healing in Task 6 are for.
- **`rmo` of a tag xray has**: `exit 0, stdout "removing: <tag>\n{}\n\n"`; **`rmo` then `ado` of the same tag** works, both exit 0.
- **`ado` of a new outbound**: `exit 0, stdout "adding: srv-b\n{}\n\n"`; lso lists it at once and `OutboundStatus` within about 2 s (one round), Alive true.

Small observations, no action needed: on 26.9.30 and 26.10.21 `ado` prints xray's own warning lines on stdout (exit 0)
for deprecated settings, e.g. `freedom.domainStrategy` (my first draft of step 8 hit it; I changed the
test's changed outbound to `"settings":{"userLevel":1}` to keep the log clean). `rmo` reads each argument
as a file path first (`loadArg`) and treats it as a tag only if that fails, so a tag equal to a readable
file in the runner's working directory would be read as a config; `srv-<id>` tags make this very unlikely (read from source, not tested).

## Commands run and results

- `go vet -tags compat ./test/compat/`: clean (run before and after the last edit).
- `gofmt -l test/compat`: no output.
- `go test -tags compat -count=1 -v -run TestHotAgainstReleases ./test/compat/...` (default releases, final file):
  `FAIL`, 47.8 s. 26.1.18 fails steps 3 and 4; 26.9.30 and 26.10.21 fail step 4 only; all other steps pass.
  The brief expects PASS on every version; it does not, because of findings 1 and 2.
- `TIKRAY_COMPAT_VERSIONS=v1.260327.0,v26.4.13 go test -tags compat -count=1 -v -run TestHotAgainstReleases ./test/compat/...`:
  `FAIL`, 106 s. 26.3.27 fails steps 3 and 4; 26.4.13 fails step 4 only.
- `go test -tags compat -count=1 -run "TestXrayAPIAgainstReleases|TestCompatVersions|TestGeoCodes|TestWriteGeoDat" ./test/compat/...`: `ok` (the builder refactor did not change M2b's tests).
- `make test` (`go vet ./... && go test ./...`): all packages `ok` (cached, as no untagged code changed). No timing-sensitive flake seen.
- Full verbose logs of the runs (not committed): `/tmp/claude-0/-home-user-tikray/d8985965-8c91-53e3-95ba-176f31bab2e8/scratchpad/hot-run-final.txt` and `.../hot-run-extra.txt`.

## Concerns / decisions for the controller

1. Finding 1 applies to all releases: Task 6's assumption (and its fake, if it models rmo of a missing tag as a failure) needs a ruling; no version gate can fix it.
2. Finding 2: decide whether the observatory's stale entry before 26.4.13 needs a gate, a health-side guard, or nothing.
3. The committed test fails as long as xray behaves this way. It is behind the `compat` tag, so `make test` is unaffected. I did not weaken it; if the controller rules that a behaviour is accepted, the matching assertion can then be changed in a follow-up.
4. Two small choices of mine: the config has a non-server `direct` outbound first (the brief names only srv-a); and step 8 is an addition (rmo then ado of one tag).

---

# Fix round 1 (FIX_BASE fb76752)

Status: DONE. No finding from the new checks.

Commit: `79f8582a5fcb9cbbaa84ec57a890692853f9cd0d` on `m2c-auth`, message
`Match real xray: rmo of a missing tag succeeds, and the observatory keeps removed outbounds before 26.4.13`
(no trailers, new commit, not amended, not pushed). hot.go is untouched: no logic change anywhere.

Files changed: `internal/artifacts/core_test.go`, `internal/artifacts/hot_test.go`, `test/compat/hot_test.go`.

## Rulings applied

### F1 (rmo of a missing tag exits 0: benign, no gate)

1. **Fake runner** (`internal/artifacts/core_test.go`, `liveAPI`). `rmo` of a tag that is not live now exits 0
   with stdout `removing: <tag>\n{}\n\n` per operand and empty stderr, and removes the tag if it is live.
   A live tag prints the same: I saw exactly `"removing: srv-a\n{}\n\n"` from real xray for a tag it has,
   so the fake now matches that too. The doc comment of `liveAPI` says what real xray does (rmo exits 0 for
   a tag it lacks; ado refuses a tag that is there and goes no further). ado is unchanged (it fails for an
   existing tag, as real xray does).
2. **`TestHotInterruptedHeals`**. The row "the rmo went through" (active srvA, candidate srvA2, live without
   srvA) is re-expected: committed, `res.Hot` true, Detail `applied without restarting xray: added 0,
   removed 0, changed 1`, actions `test, xray-api, xray-api, adopt`, live == the candidate's tags, marker
   gone. In the table a row with an empty `why` is the one where the hot change goes through; the row
   "the ado went through" is as it was. The test's doc comment is rewritten to say so, and the field's
   comment says what an empty `why` means.
   I read the whole artifacts package for anything else that assumes an rmo of a missing tag fails: no other
   test reaches one (the other rows with `f.live` either restart xray from the active config first, so the
   tag is live, or make no xray api call), and there is no such claim in a comment in hot.go, core.go or the
   tests. (The plan document, `docs/superpowers/plans/2026-10-26-m2c-auth-hot.md` line 362, says "A non-zero
   exit is a hot failure", which is still right for the logic; I left docs alone.)
3. **Compat step "rmo of a missing tag"** asserts exit 0 on every version and that lso is unchanged; its
   comment names the real behaviour and says the hot path's safety rests on the marker and the PID checks.

RED/GREEN for the changed unit row (the test was changed first, then the fake):

RED, test row changed, fake still refusing an rmo of a missing tag:
```
$ go test -count=1 -run TestHotInterruptedHeals ./internal/artifacts/
--- FAIL: TestHotInterruptedHeals (0.07s)
    --- FAIL: TestHotInterruptedHeals/the_rmo_went_through (0.03s)
        hot_test.go:778: Result = {From:26.10.21 To:26.10.21 Outcome:committed Kind:config ... Detail:the hot change failed (xray api rmo --server=127.0.0.1:10085 srv-aaaaaaaa: exit status 1: failed to remove outbound srv-aaaaaaaa: not found), so a trial was tried Hot:false ...}, want the hot change, changing one
        hot_test.go:780: runner actions = [test xray-api trial commit], want [test xray-api xray-api adopt]
FAIL
```
GREEN, after the fake matches real xray:
```
$ go test -count=1 -run TestHotInterruptedHeals -v ./internal/artifacts/
--- PASS: TestHotInterruptedHeals (0.06s)
    --- PASS: TestHotInterruptedHeals/the_ado_went_through (0.04s)
    --- PASS: TestHotInterruptedHeals/the_rmo_went_through (0.02s)
PASS
```

### F2 (before 26.4.13 the observatory keeps a removed outbound's entry: no gate)

4. **Step "rmo removes an outbound"**, on every version: rmo exits 0, lso drops the tag, and
   `BalancerTargets(proxy-open)` does not include it (asserted right after the rmo on all five releases; the
   log shows `["srv-b"]` on the three default releases). `OutboundStatus` dropping the tag is asserted only from 26.4.13: the named value
   `observatoryPrunes = xrayver.Version{26, 4, 13}` (a `var`, as a struct can't be a const), with a comment
   citing xray's `clearRemovedOutbounds` in `app/observatory/observer.go`, added in v26.4.13, the no-op
   `updateStatus` before it, and why the hot path does not wait on it. Below that version the step waits
   `lingerWait` (3 probe rounds, 6 s), then `t.Logf`s the lingering entry and asserts nothing either way
   (e.g. `before xray-core 26.4.13 the observatory keeps the status of a removed outbound: after 6s it still
   lists {Tag:srv-a Alive:true Delay:1ms ... LastSeen/LastTry 10:48:28}`). The release is parsed from the
   binary's version with `xrayver.Parse`, and compared with `Less`.
5. **Step "rmo and ado of a changed outbound"** (the earlier step 8, now the one the ruling asks for): rmo of
   srv-b, then ado of srv-b with other settings (`"settings":{"userLevel":1}`), each exit 0, lso right in
   between and after; then within 30 s `OutboundStatus` must show srv-b with a `LastTry` later than the ado's
   end, i.e. a fresh probe. `LastTry` is in whole seconds, so the ado's time is cut to the second and the
   check is `LastTry > floor(ado end)`, which means the probe began after the ado. It passed on every
   version, so there is no finding and no gate: the new outbound is probed afresh within one round
   (about 1 to 2 s), also on 26.1.18 and 26.3.27, where the new outbound takes over the old entry.
   I extended the existing replace step instead of adding a second near-identical one.

## Results per version and step (all PASS)

Default releases (`go test -tags compat -count=1 -v -run TestHotAgainstReleases ./test/compat/...`: `ok`,
29.2 s) and, with `TIKRAY_COMPAT_VERSIONS=v1.260327.0,v26.4.13`, 26.3.27 and 26.4.13 (`ok`, 20.3 s).
Then `-count=3` on the defaults: `ok`, 87.3 s (no flake in the new fresh-probe check).

| step | 26.1.18 | 26.3.27 | 26.4.13 | 26.9.30 | 26.10.21 |
|---|---|---|---|---|---|
| 1 baseline | PASS | PASS | PASS | PASS | PASS |
| 2 ado adds an outbound | PASS | PASS | PASS | PASS | PASS |
| 3 rmo removes an outbound (lso drops it, balancer stops targeting it) | PASS | PASS | PASS | PASS | PASS |
| 3 (cont.) observatory drops its status | not asserted; entry kept, logged | not asserted; entry kept, logged | asserted, dropped in ~2 s | asserted, dropped in ~2 s | asserted, dropped in ~2 s |
| 4 rmo of a missing tag (exit 0, lso unchanged) | PASS | PASS | PASS | PASS | PASS |
| 5 ado of an existing tag (exit non-zero, nothing changed) | PASS | PASS | PASS | PASS | PASS |
| 6 ado of several outbounds (in order) | PASS | PASS | PASS | PASS | PASS |
| 7 ado of several, one failing (stops, earlier ones stay) | PASS | PASS | PASS | PASS | PASS |
| 8 rmo and ado of a changed outbound (fresh probe after the ado) | PASS | PASS | PASS | PASS | PASS |

Run time of the rmo step: about 6 s on 26.1.18 and 26.3.27 (the 6 s linger log), about 1.9 s elsewhere.

## Commands run

- `go test -race -count=1 ./internal/artifacts/`: `ok` (16.3 s) on the final tree. One earlier run, made
  right after the fake change, failed once in `TestRedactDetail/an_update` (apply_test.go:586: Detail was
  `health check failing for 200ms: ... context deadline exceeded`, wanted `unknown user ‹redacted›`): the
  known 200 ms health-window timing flake, unrelated to rmo. Re-run alone with `-race`: `ok`. Whole package
  with `-race` again: `ok` (16.2 s), and once more on the final tree: `ok`. I did not change that test.
- `go vet ./... && go vet -tags compat ./test/compat/`: clean. `gofmt -l` on the changed packages: no output.
- `make test`: all packages `ok` (artifacts re-run, 10.9 s; the others cached).
- Logs (not committed): `/tmp/claude-0/-home-user-tikray/d8985965-8c91-53e3-95ba-176f31bab2e8/scratchpad/` files
  `red-unit.txt`, `green-unit.txt`, `hot-fix1-default.txt`, `hot-fix1-extra.txt`.
