# M2b decisions, carries and deferred minors

From the M2b execution ledger (copied in full to m2b-ledger.md beside this file). Every ruling names what it costs if wrong.

## Rulings I made (in order)

1. P1: Ruling: in `serve`, the per-state updater and the monitor's probe take the probe URL from the state snapshot's `Health.ProbeURL` unless `TIKRAY_PROBE_URL` is set — the T2 rule applied per snapshot, so a `PUT /v1/health` takes effect without a restart — cost if wrong: one field read.
2. P2: Ruling: `service.Config.Runner` is an interface `service.Runner{ Status(ctx) (runnerapi.Status, error); Test(ctx, []byte) (runnerapi.TestResult, error) }` that `*runnerapi.Client` satisfies — tests need a fake, and the plan's tests say fake — cost if wrong: a rename.
3. P3: Ruling: the service sets `Redact = s.Redactor()` on every updater the `Updaters` factory returns, so the factory (T11) never needs the service — breaks the New→Redactor cycle — cost if wrong: none visible.
4. P4: Ruling: event kinds are `apply, core, refresh, degraded, untested, cleanup, error` (`untested` from T8/T9 saves without a runner test; `cleanup` for a cleared pin or a dropped rule) — T8/T9 emit kinds T7 didn't list — cost if wrong: renames.
5. P5: Ruling: T7 adds `artifacts.ReadHistory(data string) ([]Result, error)` (exported wrapper of `readHistory` on `<data>/state/core-history.jsonl`) and `func (s *Service) Core(ctx) (CoreInfo, error)` with `CoreInfo{Active string; Slots []artifacts.Slot; History []artifacts.Result}`; T10's `GET /v1/core` calls it — the route had no backend method — cost if wrong: one method.
6. P6: Ruling: T7 exports `service.ErrRunnerUnavailable`, wrapped by ApplyNow/CoreUpdate/CoreRollback/Core when the runner can't be reached; T10 maps it to 503 `runner_unavailable` — the route table needs a sentinel — cost if wrong: one error.
7. P7: Ruling: T9 exports `service.ErrFetchFailed`, wrapped (with the redacted reason) when both fetch paths fail; T10 maps it to 502 `fetch_failed`; T13 step 5 expects 502 `fetch_failed` — a failed fetch is not a refusal (422) — cost if wrong: one status code.
8. P8: Ruling: `serve` passes `LoadOrCreateCert` the listen address's IP when `TIKRAY_LISTEN` names one, else the host's non-loopback unicast addresses at first creation — the client pins the fingerprint, so SANs are informational — cost if wrong: none (pinning).
9. P9: Ruling: T13 step 3 reads liveness from `GET /v1/status`'s `health`; `/v1/health` stays the settings (`GET` returns `state.Health`, `PUT` sets it) — avoids one path meaning two things — cost if wrong: one route.
10. Task 1: implementer DONE_WITH_CONCERNS aabae83. Ruling: Status.Degraded (T7) lists the IDs of servers whose Invalid is set in the current state; degraded events come only from Store.Degraded() (what this Open disabled) — so a persisted degraded server stays visible after restarts without repeating events — cost if wrong: one filter.
11. Task 1: Ruling: CLI direct paths (readState) silently drop degraded servers — T11's direct-path commands print one stderr line per Store.Degraded() server ('server <id> (<name>) disabled: <reason>') — a user running apply without the daemon should learn a server was dropped — cost if wrong: a stderr line.
12. Task 1: Ruling: Invalid reasons carry no field path, so T7's degraded events and Status name the server ('server <id> (<name>) disabled: <reason>') — the reason alone ('must not be empty') is unreadable — cost if wrong: message text.
13. Task 3: Ruling: T11 builds the service's runnerapi.Client with HTTP nil (or a client whose timeout exceeds 20 s plus margin) so Test's 20 s xray bound is never cut short — reviewer ⚠️ — cost if wrong: tests cut short read as untested.
14. Task 4: Ruling: healthChecks(cfg, runner) returns (health, proxy) with proxy always the SOCKS probe; newUpdater(..., socks bool) keeps M2a's ProxyAvailable-or---config rule and sets ProxyHealth nil when !socks — the brief's signature had no input for that rule, and a nil-on-empty-address probe would fail open — cost if wrong: a signature shape.
15. Task 4: Ruling: the redactor is a pure function service.RedactorFor(st store.State) func(string) string (T7); Service.Redactor() calls it on the current state, and T11's direct CLI paths (apply, core update, core rollback without the daemon) set CoreUpdater.Redact = RedactorFor(st) too — otherwise the direct path writes raw xray output to state/core-history.jsonl, against the no-secrets-in-history constraint — cost if wrong: one call per path.
16. Task 4: Ruling: T7 events, T8 Refused reasons and T10 API bodies use only err.Error() / Result.Detail (redacted) and never errors.As(err, &*TestFailedError) to read .Output, which Unwrap leaves raw — reviewer ⚠️ — cost if wrong: a secret in an API body.
17. Task 5: Ruling: the observatory service path is /xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus (proto package at app/observatory/command/command.proto:3), not the plan's xray.app.observatory.command — real xray 26.10.21 answers the plan's path with UNIMPLEMENTED; the plan gets a '(changed: …)' note at the end — cost if wrong: none (verified on 5 releases).
18. Task 5: Ruling: go.mod gains golang.org/x/text v0.30.0 (required by x/net/http2 → idna) and indirect x/mod, x/sync, x/tools bumps forced by the graph; no grpc — accepted, stdlib-first allows x/ modules the plan named — cost if wrong: a few KB of binary.
19. Task 6: Ruling: Snapshot.Servers lists the servers xray's observatory watches (the balancers' members, in state order), not every enabled server — with a pin only the pinned server is observed, so listing the rest as dead would pin the level at degraded; Status still carries the full server list via State — cost if wrong: a UI shows fewer servers' health.
20. Task 6: Ruling: the proxy probe keeps SOCKSProbe's 10 s timeout (runner/xray calls 5 s), so one check can take ~25 s worst case — the brief's 5 s was per call to runner/xray, and a 5 s probe would misjudge slow proxies — cost if wrong: a slower snapshot refresh.
21. Task 6: Ruling: snapshot types carry snake_case JSON tags (T7/T10 serialise them) — cost if wrong: renames.
22. Task 6: Ruling: Status reports Level 'unknown' until the monitor's first check (Snapshot().Level == ''), and RedactorFor also redacts the state's probe-URL userinfo — reviewer ⚠️ + Minor 2 — carried in task-7-carries.md #12 — cost if wrong: a label, one more secret.
23. Task 7: Ruling: the apply loop also retries runnerapi.ErrBusy (a trial left open by a crashed tikray) with the same backoff — the runner reverts it within TrialDeadline, so retrying converges — cost if wrong: a few extra tries.
24. Task 7: Ruling: redactor extras (share links, other forms of a subscription URL, case-insensitive keys, merged overlapping matches) accepted — wider redaction only hides more — cost if wrong: over-redacted messages.
25. Task 7: Ruling: WireGuard 'secretKey' is a credential and joins the redactor's secret keys — the plan's list (id, password, privateKey, preSharedKey, seed) missed it; spec says server credentials — cost if wrong: one over-redacted key.
26. Task 8: Ruling: sharelink Warnings (e.g. allowInsecure ignored) are recorded as one event each, new kind 'warning', message 'server <id> (<name>): <warning>' (redacted) — a user whose link was changed on import should learn it; the API signature stays — cost if wrong: one event kind.
27. Task 8: Ruling: clearing Invalid via a new link/outbound does not auto-enable; enabling stays explicit (it may be in the same patch) — cost if wrong: one extra click.
28. Task 8: Ruling: a Link patch keeps the server's name; an Outbound patch clears Link (the link no longer describes the server) — cost if wrong: a name change.
29. Task 8: correction (supersedes the muddled 'carry to T10' line above): Ruling: T10 maps a mutation's bare context.Canceled/DeadlineExceeded to 503 'unavailable' with detail 'the request was cancelled or timed out' (the client usually has gone away, so the body rarely matters); *service.Refused via errors.As with a *service.Refused target → 422; ErrRunnerUnavailable (from ApplyNow/CoreUpdate/CoreRollback/Core) → 503 'runner_unavailable' — cost if wrong: one status code.
30. Task 9: Ruling: manual RefreshSubscription of a disabled subscription → *Refused — Disabled means 'not fetched' — cost if wrong: one error.
31. Task 9: Ruling: a URL change in UpdateSubscription resets LastFetch and LastError so the new address is fetched next — accepted — cost if wrong: one early fetch.
32. Task 9: Ruling: if xray rejects every entry, nothing is merged and the refresh returns *Refused — merging would remove every server, the block-page rule's spirit — accepted — cost if wrong: a provider that truly emptied keeps stale servers until fixed.
33. Task 9: Ruling: a failed manual refresh also holds the scheduler for min(1h, Interval); a post-fetch failure (second conflict) records an 'error' event — accepted.
34. Task 9: Ruling: a refresh that gives a kept server with Invalid set a new outbound that passes the checks and the runner test clears Invalid and leaves Disabled as is (no auto-enable) — same rule as UpdateServer (Task 8); keeping Invalid would mask a provider's fix forever — cost if wrong: one field. Dispatched with the review's fixes.
35. Pre-T11: Ruling: the CLI falls back to the direct path only on 'connection refused' to /healthz; a TLS error, timeout or wrong fingerprint is an error, not a fallback — a silent fallback would let two processes write the state — cost if wrong: a user with a broken daemon must fix it before using the CLI.
36. Pre-T11: Ruling: serve's startup line is 'tikray: serving on <addr>, certificate sha256 <fingerprint>' on stderr, never the token — cost if wrong: wording.
37. Task 10: Ruling: a failed apply/core update/rollback (a Result outcome rejected/unhealthy/refused plus an error) is 422 'refused' with the redacted error as detail — the client needs the outcome, and it is the request's own failure, not the server's — cost if wrong: one status code.
38. Task 10: Ruling: a body over 1 MiB is 400 'bad_request' (not 413); a wrong method on a real path is 404 'not_found' (the table has no 405) — cost if wrong: two status codes.
39. Task 10: Ruling: additions accepted — ServeListener, Location on 201s, runnerapi.ErrBusy → 409 busy, Cache-Control: no-store, server_test.go.
40. Task 10: Ruling: POST /v1/apply, /v1/core/update, /v1/core/rollback and /v1/subscriptions/{id}/refresh run with context.WithoutCancel(r.Context()) (bounded by the service's own lifetime, not the client's connection) — a client that disconnects or is Ctrl-C'd must not cancel a router-side trial mid-way; mutations (runner Test ≤20 s) keep the request context — dispatched with the review's fixes — cost if wrong: an abandoned request still finishes.
41. Task 10: Ruling: no ETag on /healthz and 401 — they're not about the state — cost if wrong: one header.
42. Task 10: Ruling: a tls.key without tls.crt (crash between writes on first start) is regenerated — nothing was served with it; both present and mismatched, or a cert without a key, stay errors — re-graded from reviewer Minor 3 by effect (a power cut at first start would stop tikray starting forever) — cost if wrong: one regeneration.
43. Task 10: Ruling: a skipped subscription line on the wire is scheme + '://…' + '#<fragment>' — the raw 80-char line can hold a new credential (reviewer Minor 2, re-graded: the T11 CLI/M4 UI would print it) — cost if wrong: less context for a skipped entry.
44. Task 11: Ruling: accepted judgment calls — core update --config is refused while a daemon answers (the daemon owns the config); read commands (server list, status, …) need the daemon; a failed apply/update/rollback via the daemon prints the refused Result as 'code: detail'; last-result.json is written on the API path too; sub add without --name names it after the URL's host — cost if wrong: CLI ergonomics.
45. Task 11: Ruling: serve must not exit when run/runner.token is missing (RouterOS starts both containers together; a lost race would stop the tikray container for good). The HTTPS API and /healthz come up at once; the runner client waits for the token (re-reading it every second), and until then status shows level down with runner error 'waiting for the runner token' — dispatched with the review's fixes — cost if wrong: a slower failure signal.
46. Task 11: Ruling: serve takes an exclusive flock on <data>/state/serve.lock for its lifetime and exits with 'tikray: another tikray serve owns <data>' when it's held — the global 'one process owns the state' — dispatched with the review's fixes — cost if wrong: none (lock released on exit).
47. Task 11: Ruling: TIKRAY_API, when unset, derives from TIKRAY_LISTEN (its IP if specific else 127.0.0.1, its port) — and the direct paths take serve.lock non-blocking and refuse when held — closes the probe-then-write window — cost if wrong: a CLI that refuses while a stale lock… (flock is released on process exit, so no stale lock).
48. Task 11: Ruling: re-graded reviewer Minor 3 to Important — core update --config builds its redactor over the config file's outbounds too, so its credentials never reach core-history.jsonl — global constraint 'no secrets in the history, on the direct path too' — cost if wrong: one helper.
49. Task 11: Ruling: ruling B implemented as fail-fast runner calls ('waiting for the runner token') plus a 1 s background re-read that kicks the loop when the token appears — API calls and status never hang — accepted — cost if wrong: none.
50. Task 11: Ruling: a lock refusal records a refused Result in last-result.json like any refusal; the state and history stay untouched — accepted — cost if wrong: one file write.
51. Task 12: Ruling: the tikray binary goes to /usr/local/bin/tikray with ENTRYPOINT ["/usr/local/bin/tikray"] — busybox's default PATH includes /usr/local/bin, so 'tikray status' works in /container/shell (the reason for busybox); only comments name /tikray — dispatched with the review's fixes — cost if wrong: one path.
52. Task 12: Ruling: keep busybox 1.37.0-musl (the brief's 1.37/1.36 rule) though 1.38.0 exists — cost if wrong: one tag bump later.
53. Task 13: Ruling: health.Monitor gains Poke() (non-blocking, coalescing) and the service pokes it after every apply pass and core update/rollback — for up to 10 s after each apply ProxyHealthy is false, so a refresh right after a change can't fall back to the proxy, the path that matters when direct is blocked — cost if wrong: one extra check per apply.
54. Task 13: Ruling: re-graded reviewer Minors 1 (added:1 race), 2 (restart check passes with a trial in progress), 5 (shell check only notes output) to Important — each lets a check pass without the behaviour its name claims (global: a check must be able to fail) — cost if wrong: a little test code.
55. Task 13: Ruling: the block-page check waits for the server still up (not lab-b) to be alive — on arm64 lab-b was the one the failover stopped; the proxy path needs any alive server — cost if wrong: none.
56. Final: Ruling: re-graded into the fix pass by effect — Minor 1 redactor keys (pass, user, auth, key, secrets: server credentials per the constraint, one line); Minor 2 status 'degraded' up to 60 s after a fixing apply (poke must make the probe due; misleading after every change); Minor 3 waiting-for-token gives 500 not 503 (misleading); Minor 4 runner token never re-read (a regenerated runner token breaks tikray until restart); Minor 5 'detached' ops not bounded by the service (comment false; orphan trial on SIGTERM); Minor 6 a refresh whose store write fails is never held off (refetch + xray tests every minute forever); Minor 8 closedAddr port-reuse flake; Minor 10 Location headers to non-existent routes — cost if wrong: one fix pass a little larger.
57. Final: Ruling: Minor 7 (servers saved untested before a core exists are never re-tested) deferred — needs a persistent store marker and a re-test pass (new behaviour); carry to M3 (the installer bootstraps the core before any server/subscription) and M2c (re-test untested servers once a core exists) — cost if wrong: a user who adds a subscription before the core can be stuck with a rejected server until they disable it (the trial still protects the data path).
58. Final: Ruling: Minor 9 (pre-M2b history lines re-redacted only with the current state), Event.Seq restarting at 1 (M4 needs a boot id — carry to M4), serial per-entry xray tests on a large first refresh (carry to M2c: batch then bisect), runner's missing ReadTimeout (carry to M3 with the firewall) — deferred.
59. Final: Ruling: accepted implementer notes — a runner gone after the pre-check yields 422 with its Result (an outcome means the operation's own error); through the daemon stderr reads 'tikray: <code>: <detail>'; ErrNoToken text unprefixed (keeps the status line); F7 bounds operations only via api.Serve/ServeListener (serve's only path); F3's 'key'/'user' may over-redact — cost if wrong: messages.
60. Final: Ruling: the token race is load-bearing (a daemon crash) — fixed in the same wave as the smallest change (load the pointer once in get, concurrent get/drop test), by the same implementer after its lab re-run; no lab re-run for it (token read only); the controller verifies it with the focused race test — cost if wrong: none.

## Carried to later tasks / M2c / M3 / M4

- Task 5: carry to T6: wrap xray.StatusError with the RPC name; the monitor tolerates one failed poll after an xray restart (shared idle h2c connection) before reporting it.
- Task 5: carry to T6: xray's unixTime returns Local times — the monitor normalises LastTry/LastSeen with .UTC() before they are serialised.
- Task 6: carry to T7: Status passes the snapshot's error strings (Runner.Err, Servers[].LastError, Probe.Err) through Redactor() — xray's last_error is its own text.
- Task 7: carry to T8/T9: 'runner unreachable' is detected as a *url.Error from net/http — fakes that simulate a down runner must fail that way (e.g. a closed httptest server), not with a bare error.
- Task 7: carry to T8/T9: never call the service's event recorder (record) inside a store.Update fn — collect events and record them after Update returns.
- Task 7: carry to T10: the API token is not in store.State, so RedactorFor can't cover it — T10's error/log paths must never include the token (and redact it if echoed).
- Task 7: carry to T11: the service's runnerapi.Client must always have an HTTP timeout (HTTP nil gives the defaults) — the loop's runner calls carry no deadline of their own; the Updaters factory must be safe for concurrent calls (Status and a pass).
- Task 8: carry to T10: map *service.Refused with errors.As(err, &r) where r is *service.Refused; bare context.Canceled/DeadlineExceeded from a mutation map to 503 'runner_unavailable'? no — map ctx errors to 500 'internal' only when the server's own ctx ended, else to 504-free 503; ErrRunnerUnavailable is not reachable from mutations (they save untested) — T10 maps what can occur.
- Task 9: carry to T10: RefreshResult.Skipped is subscription.Skipped (untagged: Line, Err) — T10's wire type maps it to snake_case {line, reason} with the reason redacted.
- Task 10: carry to T11: GET /v1/state, /v1/servers and /v1/subscriptions return credentials and URLs — the CLI's human-readable list output must not print outbound credentials or subscription URLs (show id, name, protocol/address, enabled; --json passes the API's JSON through).
- Task 12: carry to T13: confirm RouterOS imports the busybox-based archive, and what /file/get returns for the multi-line PEM (Lab.api normalises it).
- Task 13: carry to M3: the installer must never set cmd="" — leave cmd unset or set cmd=serve.

## Notes for the final review

- Final: note: cmd/tikray-runner/main.go:98-103 http.Server has no ReadTimeout either (same shape as Task 10's finding; bridge-local and token-protected) — final review to triage.
- Final: note: redactor secretKeys lacks 'pass'/'user' (socks/http outbound users) and 'auth' (hysteria) — a raw outbound of those kinds could leak via xray output — final review to triage.

## Deferred minors

- Task 1: minor (deferred): pre-existing timing flake cmd/tikray TestUpdateConfigFileSurvivesAnUnreadableState (300ms health deadline under parallel load); passes alone and -count=3
- Task 1: minor (deferred): read() refuses a file whose revision is AnyRevision (unrequested, 2 lines, tested) — accepted: guards rev+1 wrap.
- Task 1: minor (deferred): own() reorders a server's multi-fault problems (name, outbound, subscription).
- Task 1: minor (deferred): Validate message for Invalid-but-enabled says 'until its outbound is replaced' but the fix also needs invalid cleared.
- Task 1: minor (deferred): redundant non-nil []string{} guards in admit/degrade/Degraded.
- Task 1: minor (deferred): a migrating Open writes the un-degraded state, so Degraded() repeats on each restart until an Update (no migration exists yet at Current=1).
- Task 2: minor (deferred): literal U+2028/U+2029 bytes in test rows (model_test.go:327-328, sharelink_test.go:214) — write as escapes.
- Task 2: minor (deferred): validate.go:143 refusal text 'control characters or bidi overrides' now also covers line/paragraph separators — reword.
- Task 2: minor (deferred): sharelink.go:298 comment on ForbiddenInName classes is incomplete.
- Task 3: minor (deferred): runnerapi Client.HTTP comment still says 10 s; Test uses 30 s when nil.
- Task 3: minor (deferred): TestConfig reads runningSelection before MkdirTemp/parse/write; a revert's cleanStage in that gap gives 500 internal (service treats as untested) — re-read before runTest would tighten.
- Task 3: minor (deferred): no concurrency bound on /v1/test (each call spawns xray; service calls serially today).
- Task 3: minor (deferred): timing margins in TestTestConfigTimeout (800ms vs 1s) and TestServerTestWhileTheRunnerIsBusy.
- Task 3: minor (deferred): '/v1/test' string repeated in middleware and mux (server.go:430, :52).
- Task 4: minor (deferred): single baseline probe — one transient failure waives the proxy check for that Apply (brief-mandated 'once'; candidate still needs xray API + data path); consider one quick retry before waiving.
- Task 4: minor (deferred): baseline HealthWindow cap (core.go:387-389) untested.
- Task 4: minor (deferred): baselineSkipped text duplicated in apply_test.go:239 and main_test.go:194.
- Task 4: minor (deferred): Data=='' redaction branch (core.go:179-180) untested.
- Task 5: minor (deferred): grpc.go:173-175 dead nil-slice guard after io.ReadAll.
- Task 5: minor (deferred): shared h2c transport has no ReadIdleTimeout/PingTimeout — a silently dead TCP path gives 5 s timeouts per poll until TCP gives up.
- Task 5: minor (deferred): compat test only exercises alive=true live; alive=false/99999999/last_error and BalancerMsg.override verified only against hand-built bytes.
- Task 5: minor (deferred): compat subtests use the parent's t.Context().
- Task 6: minor (deferred): a carried-over observation keeps ProxyHealthy true for up to ~2×Interval after a failed xray poll (could gate on a not-serialised carried flag).
- Task 6: minor (deferred): LevelIdle comment says 'no server is enabled'; real condition is 'the balancers have no member'.
- Task 6: minor (deferred): ProxyHealthy ignores a failed last Probe (brief-mandated) — T9 may decide.
- Task 6: minor (deferred): alive-scan closure repeated 3× (anyAlive helper).
- Task 6: minor (deferred): TestRunChecksEveryInterval is weak; no test re-maps a kept observation after a state change.
- Task 7: minor (deferred): artifacts TestUpdateNeedsTheDataPath/gateway_down (200 ms health window) flaked once under -race -count=3 with service in parallel; passes alone.
- Task 7: minor (deferred): debounce has no maximum wait (reviewer: delay not loss; ApplyNow bypasses); a 30 s burst cap would be cheap insurance.
- Task 7: minor (deferred): Pending stays true after a successful ApplyNow while the loop is backing off (up to 5 min).
- Task 7: minor (deferred): Status/catchUp build a full updater (RedactorFor parse) just to render on every poll.
- Task 7: minor (deferred): ErrBusy retry untested.
- Task 7: minor (deferred): lock wait returns bare ctx.Err() without service: prefix.
- Task 7: minor (deferred): redact.go has both (*Service).redact and package func redact.
- Task 7: minor (deferred): redaction is case-sensitive for values; an upper-case UUID printed lower-case by xray could slip through.
- Task 7: minor (deferred): unhealthy retry decides on one Status call right after the failed abort; a runner back within ms is not retried (narrow window, by the prescribed design).
- Task 7: minor (deferred): secretKeys var doc reads as a fragment; pass doc doesn't mention a restart.
- Task 8: minor (deferred): no test makes the revision go stale during the runner's Test (second check in change→Update).
- Task 8: minor (deferred): the untested-event redaction check can't fail (no fake error text holds the id).
- Task 8: minor (deferred): bare ctx.Err() at servers.go:113-114 without service: prefix.
- Task 8: minor (deferred): an xray -test over the runner's 20 s bound is reported as a rejection and the server isn't saved — watch on arm64 TCG in T13.
- Task 8: minor (deferred): redundant assertion in TestUpdateServerWithoutANewOutboundIsNotTested; server tests still in the 1011-line mutate_test.go; generic names edit/note/source; awkward testServer doc; nameless raw outbound refusal shows servers[3].name.
- Task 9: minor (deferred): a scheduled refresh checks 'due' before waiting for the refresh lock, so it can repeat a just-finished manual refresh back to back.
- Task 9: minor (deferred): cutLine/maxLineRunes and sameJSON/decodeJSON duplicate M2a subscription helpers (cut, outboundKey) — export small helpers so 'differs' and Merge agree.
- Task 9: minor (deferred): TestRefreshesDoNotOverlap relies on a 5 ms sleep.
- Task 9: minor (deferred): 'every entry refused' case of TestRefreshErrorsHaveNoURL checks nothing; per-entry xray reasons are discarded on that path (consider returning skipped with the *Refused).
- Task 9: minor (deferred): RefreshSubscription and schedule docs say a failed refresh always sets LastError/holds — no longer true for a mid-fetch re-point.
- Task 9: minor (deferred): a successful fetch of the old address after a re-point ends with a 'refresh was not stored' error event (noise; no state stamped).
- Task 10: minor (deferred): two processes creating the token/cert at once can each get a different one (rename-over); os.Link-based create would make it exclusive.
- Task 10: minor (deferred): path tricks (//healthz, /healthz/, OPTIONS/POST /healthz, /healthz/../v1/state) behave correctly but are not pinned by a test.
- Task 10: minor (deferred): 'TLS 1.2 is the oldest' test passes without MinVersion (Go default); TestServerSettings is the real check.
- Task 10: minor (deferred): secret.go:78 doc still says 'when both files are missing'.
- Task 10: minor (deferred): a malformed link with a raw '#' in its credential shows the text after '#' as its name label.
- Task 11: minor (deferred): cmd/tikray 300 ms health-window tests flaked 2/32 full-package -race runs after T11 (0/35 at BASE); pass alone 20/20 — widen the window in the final pass if it recurs.
- Task 11: minor (deferred): daemon() checks cl.Fingerprint=='' before ctx.Err(), so Ctrl-C during the probe reports 'no certificate fingerprint'; apiError's 'tikray serve goes on with it' also prints for read commands.
- Task 11: minor (deferred): commands_test.go is a new 1028-line file (split by noun).
- Task 11: minor (deferred): lock-held messages name 'serve' even when the holder is a direct run (wording per ruling).
- Task 11: minor (deferred): apiForListen maps 'host:' (empty port) to 443 while net.Listen picks a random port.
- Task 12: minor (deferred): inet.go SubsDir block repeats the ReleasesDir block (absDir helper).
- Task 12: minor (deferred): Lab.api polls every 2 s until ctx ends — Task 13 must pass a bounded ctx; each failed attempt logs two 'run …' lines (paths only).
- Task 12: minor (deferred): unrequested comment-only change in cmd/tikray/main.go prepareDirs (design claim, unverified).
- Task 13: minor (deferred): refused_server's leak check matches only the full 40-char id (a truncated echo would pass).
- Task 13: minor (deferred): the whole /container/print detail (env-current) goes into committed results — a future envlist secret would land there; note only arch, tag, default-entrypoint, default-cmd, PATH.
- Task 13: minor (deferred): test-wide ctx with no per-call bound at :172/:439; :511 fingerprint-vs-log comparison can match the old line (tls.crt comparison is the real check).
- Task 13: minor (deferred): task-13-report.md says 'no product code changed' in its first section (superseded by the fix section).
- Task 13: minor (deferred): pass pokes the monitor on every runner-unreachable retry (one extra check per ≥10 s retry).
- Final: deferred-minor triage: none of the ledger's minor (deferred) lines block merge (reviewer); T4 single-baseline-probe and T9 discarded per-entry reasons stay deferred.
- Final: minor (deferred): F8's Refused-from-validation path shares the write-error branch but has no test of its own (no input found that fails post-merge validation).
