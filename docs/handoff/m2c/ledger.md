# SDD ledger — plan: docs/superpowers/plans/2026-10-26-m2c-auth-hot.md

Spec: docs/superpowers/specs/2026-10-24-tikray-design.md (reachable). Branch m2c-auth from 91b123a (main after M2b's merge); plan commit 63f6249.
User approved the plan as written (single admin; root token kept; sessions persisted; rule edits stay trials).

## Pre-flight scan

### Shared interfaces (producer → consumer)

| Tasks | Produced | Consumed | Found |
|---|---|---|---|
| T1 → T2 | `Store`, `ChangePassword(ctx, current, next)` | T2 changes it to `ChangePassword(ctx, keep, current, next)` | consistent (T2 states the change) |
| T1/T2 → T3 | `Store.{NeedsSetup, Claim, Reset, SignIn, Session, SignOut, ChangePassword, CSRFFor, CheckCSRF, CreateToken, Tokens, RevokeToken, CheckToken}`, `Limiter.{Allow, Fail}` | T3 handlers | consistent |
| T3 → service | `Backend.Record(kind, msg)` and event kind `auth` | T3's file list doesn't include internal/service | P1 |
| T3 → T4 | `NewHandler(b, root, a, lim, …)` | T4 serve wiring | consistent |
| T5 → T6 | `Client.Adopt(ctx, config)`, `ErrBusy`, `ErrNoCore` | T6 step 7 | consistent |
| M1/M2b → T6 | `Client.XrayAPI(ctx, args...)`, `Client.Test(ctx, []byte)`, `ProxyHealth`, baseline | T6 steps 2–6 | consistent |
| T6 → T7 | `ado`/`rmo --server=` forms, "existing tag" refusal | T7 compat | consistent |
| T6 ↔ T8 | T6 edits artifacts + cmd/tikray newUpdater; T8 edits store/service | — | no shared file |
| T6 → T9 | `Result.Hot` (JSON `hot`) in status `last_apply` | T9 hot checks | consistent |
| T2 Limiter → T9 | one per-IP bucket for setup AND sign-in failures, capacity 5 | T9 check 2 spends 3 failures, then check 4 expects exactly 5 more before 429 | P2 (conflict) |

### Per-task self-consistency

| Task | Found |
|---|---|
| T1 | ok |
| T2 | ok |
| T3 | needs `service.Record` + `KindAuth` outside its file list → P1 |
| T4 | ok |
| T5 | ok |
| T6 | ok (`RunnerRun` added in 63f6249) |
| T7 | ok |
| T8 | ok |
| T9 | rate-limit check order → P2 |

### Pre-flight rulings

- P1: Ruling: Task 3 also edits internal/service/events.go (exported `KindAuth = "auth"`) and adds `func (s *Service) Record(kind, msg string)` (redacted, like the internal recorder) so `*service.Service` satisfies the API's `Backend` — the handler needs a way to record auth events — cost if wrong: one exported method.
- P2: Ruling: TestAuth's order becomes setup_required, claim_admin, session_and_csrf, api_token, restart_keeps_auth, login_rate_limit — the restart resets the in-memory limiter, so the rate-limit check starts from a full bucket of 5 regardless of the 3 bad codes in claim_admin — cost if wrong: check order only.

## Tasks
Task 1: dispatched (BASE 63f6249, sonnet)
Task 1: implementer DONE_WITH_CONCERNS da3281f.
Task 1: Ruling: DummyHash is a hardcoded PHC of a discarded random password with the fixed parameters (not computed in init) — computing it would cost ~100 ms and 19 MiB in every tikray command on a router; timing equals a real check — cost if wrong: none.
Task 1: Ruling: exported ErrInvalid (validation errors satisfy errors.Is) accepted, so Task 3 maps them to 400 — cost if wrong: one sentinel.
Task 1: carry to T2: fileData Tokens/Sessions are []json.RawMessage placeholders to retype; argonHook counts argon2 runs; Store.now is the clock hook; hook-using tests must not run in parallel.
Task 1: review ✅ Approved (a087eb1d92384f571).
Task 1: Ruling: NormalizeSetupCode drops every unicode.IsSpace rune and upper-cases ASCII only — it can only remove characters, never create a false match — cost if wrong: none.
Task 1: carry to T2 (binding): SignIn refuses an unknown username even when CheckPassword(DummyHash, pw) is true (the dummy's preimage is in the source history) — decide by the username comparison, run the dummy check only for timing.
Task 1: Ruling: re-graded reviewer Minors 2 and 6 into T2 (same file, security-adjacent): Reset removes setup.code before committing 'no admin' so no crash point revives an old code; loadFile checks ValidUsername on the stored admin so a hand-edited control/bidi name can't be echoed — cost if wrong: two small edits.
Task 1: carry to T4 (binding): the CLI must not call OpenStore (it writes auth.json/setup.code — one-owner rule); add a read-only helper in internal/auth (e.g. ReadSetupCode(dir) (code string, ok bool, err error)) for 'tikray setup-code'; a missing file with no admin should say so honestly (e.g. 'no setup code yet: start tikray serve' when auth.json has no admin) rather than 'claimed'.
Task 1: minor (deferred): Claim returns an error after the admin is saved when removing setup.code fails (a retry then gets ErrAlreadyClaimed).
Task 1: minor (deferred): OpenStore ignores a non-NotExist os.Stat error on setup.code.
Task 1: minor (deferred): PHC canonical re-encode check (password.go:153,156) untested.
Task 1: minor (deferred): TestChangePassword's 'the username' case uses a too-short name, so the not-equal-to-username rule is never reached.
Task 1: minor (deferred): wait error says 'checking' for HashPassword too; Store.admin() method shadows type admin.
Task 1: minor (deferred): GREEN evidence in the report is paraphrased, not raw output — future reports paste raw output.
Task 1: complete (commits 63f6249..da3281f, review clean)
Task 2: dispatched (BASE da3281f, sonnet)
Task 2: implementer DONE_WITH_CONCERNS 7759500.
Task 2: Ruling: ChangePassword ends the other sessions in the same commit as the new hash (EndOtherSessions also exists) — one write, no window — accepted.
Task 2: Ruling: SignOut/EndOtherSessions swallow a failed save (ended in memory, saved by the next write) per the brief's no-error signatures — cost if wrong: a signed-out session could revive after a crash if the save failed.
Task 2: Ruling: the 20-session cap drops the oldest by creation (the brief's 'oldest'), and expired tokens count toward 50 until revoked — accepted — cost if wrong: UX.
Task 2: carry to T3 (binding): key the Limiter by the /64 for IPv6 client addresses (IPv4 exact) — an attacker can't get a fresh bucket per IPv6 address; map ErrBadCredentials→401 bad_credentials, ErrBadCode→401 bad_code, ErrTokenLimit→409, ErrNoToken→404, ErrInvalid→400; always resolve the Session before CSRFFor/CheckCSRF (they don't check the session exists).
Task 2: review ❌ Needs fixes (a860e73ecae23289c): Important (plan-mandated interface) — Allow reserves nothing, so concurrent attempts from one IP (and globally) all pass and each hashes a guess; the 2-slot semaphore queues rather than refuses.
Task 2: Ruling: Limiter.Allow(ip) returns (done func(failed bool), ok, retryAfter) and reserves a token from both buckets on ok; done(true) keeps it, done(false) refunds (only failures count); replaces Allow/Fail — the brief's two-call interface let concurrent bursts through — cost if wrong: an interface change Task 3 consumes.
Task 2: Ruling: folded two small findings into the round — the session cap never drops the session it just made (clock step-back); the 'expired tokens count toward 50' ruling gets its test.
Task 2: minor (deferred): wall-clock expiry can revive an ended session/expired token when the router clock steps back (no RTC) — doc note at most.
Task 2: minor (deferred): duplicated lower-hex check (validHash/validTokenID); sumHex named sha256Hex in a comment; concurrency test lacks ChangePassword/SignIn writers.
Task 2: fix round 1/5 dispatched (resume a6dd816492609048e; FIX_BASE 7759500).
Pre-T3: Ruling: ErrAlreadyClaimed → 409 already_claimed; ErrBadPassword (password change) → 403 bad_password; a request refused before any credential check (bad JSON, validation, already claimed) refunds its limiter token (done(false)) — only credential failures count — cost if wrong: status codes.
Pre-T3: Ruling: the session cookie has Max-Age = the absolute limit (7 d) and is cleared (Max-Age=0) on logout and on a 401 for an ended session — cost if wrong: a stale cookie lingers.
Task 2: fix round 1/5 (3 addressed, 0 open — limiter reserves on Allow, cap keeps the new session, expired-at-cap test; commits 7759500..b38f307; re-review ad3806f6cb1e32f0f)
Task 2: minor (deferred): a late done(false) after its per-IP bucket was dropped/recreated refunds the current bucket; a refund can forgive less than one refill of a concurrent failure (fluid-bucket model).
Task 2: complete (commits da3281f..b38f307, review clean after 1 fix round)
Task 3: dispatched (BASE b38f307, sonnet; carries in task-3-carries.md)
Task 3: implementer DONE_WITH_CONCERNS 366442d, ec155bd.
Task 3: Ruling: additive auth.Store.Username() and auth.SessionLife accepted (needed for GET /v1/auth/session and the cookie Max-Age) — cost if wrong: two exports.
Task 3: Ruling: PUT /v1/auth/password is cookie (session) only — a named token or the root token gets 403 — and a wrong current password goes through the limiter like a sign-in failure (done(true)), with an 'auth' event 'password change failed from <ip>' — a stolen token must not be able to guess the password at argon2 speed and lock the admin out — dispatched with the review's fixes — cost if wrong: a script can't change the password (the root-token reset remains).
Task 3: Ruling: a failed sign-in event names the username only when it equals the admin's ('sign-in failed for <admin> from <ip>'); otherwise 'sign-in failed for an unknown user from <ip>' — a password typed into the username field must never land in an event — dispatched with the review's fixes — cost if wrong: less detail on probes.
Task 3: Ruling: accepted judgment calls — signed_in true for any valid credential; session/logout 403 to bearers; unclassified sign-in errors count as failures; M2b's unknown-field error echoing the caller's own key name.
Task 3: minor (deferred): failed sign-ins can fill the 200-event ring (≤ ~400/h global) and push out apply events — M4 may separate auth events.
Task 3: review ❌ Needs fixes (a85e1b69e990e5fd6): Important — isPublic uses the decoded path while ServeMux routes on the escaped path, so /v1/auth%2Fsetup etc. skip auth and CSRF and the catch-all leaks the revision via ETag (probed).
Task 3: Ruling: serve.go wiring of auth.OpenStore/NewHandler in Task 3 accepted (forced by NewHandler's signature); serve creating setup.code before Task 4's hint is fine.
Task 3: Ruling: folded the reset-vs-password-change race into the round (export auth.ErrNoAdmin → 409 setup_required) — a 500 'internal' would mislead.
Task 3: minor (deferred): NewHandler doesn't panic on a nil store/limiter at construction; expired-token test sleeps 80 ms on the real clock; authState doesn't clear an ended-session cookie; session/logout duplicate the bySession check.
Task 3: fix round 1/5 dispatched (resume a8e94a5674843bdac; FIX_BASE ec155bd): pattern-based public check + rulings A (password cookie-only, limited) and B (event username) + ErrNoAdmin.
Task 3: Ruling: an anonymous request to an unclean spelling of a public route (/v1//auth/state) gets the mux's 301 to the clean path — it carries no ETag or state and only names a public route — accepted — cost if wrong: none.
Pre-T4: Ruling: 'tikray setup-code' with no code and no admin prints 'no setup code yet: start tikray serve' (never 'claimed'); 'admin reset' without a daemon takes serve.lock and resets directly — cost if wrong: wording.
Task 3: fix round 1/5 (4 addressed, 0 open — mux-pattern public check, password cookie-only + limited, admin-only username in events, ErrNoAdmin 409; commits ec155bd..63cb096; re-review adba789c490259b2b, 2667-request path probe clean)
Task 3: minor (deferred): a reset landing between CheckPassword and the commit makes ChangePassword answer 403 bad_password (spends a limiter token, records a failure) though the password was right — narrow window.
Task 3: complete (commits b38f307..63cb096, review clean after 1 fix round)
Task 4: dispatched (BASE 63cb096, sonnet; carries in task-4-carries.md)
Task 4: implementer DONE_WITH_CONCERNS e4ef857.
Task 4: Ruling: accepted — setup-code exits 0 with 'claimed' on stdout, 1 with 'no setup code yet' on stderr; the hint line prints before 'serving on'; admin reset without a daemon on a fresh root creates auth.json/setup.code (a reset makes a code by definition); a hand-removed setup.code while serve runs says 'start tikray serve' (the read-only helper can't remake it) — cost if wrong: wording.
Task 4: minor (deferred): token rm sends its argument as the id, so a pasted full tkr_ token goes in the URL path (TLS, pinned, not logged) — the CLI could take the id out of a full token.
Task 4: review ✅ Approved (a850bac9cdcdc5b77).
Task 4: minor (deferred): commands.go:47-53 header says CLI commands never write the state (admin reset now does, under serve.lock); serve-held refusal text duplicated (commands.go:514, main.go:506); token create's 'shown only once' line on stdout makes TOKEN=$(…) capture two lines (stderr friendlier); c.say(adminResetDone) uses a constant as the format; sign-in commands could move to commands_auth.go; test helper duplicates apiclient's pinned client.
Task 4: complete (commits 63cb096..e4ef857, review clean)
Task 5: dispatched (BASE e4ef857, sonnet)
Task 5: implementer DONE 6278b16 (adopt leaves r.v.running — the process's own selection — so onExit still matches a crash and restarts from the adopted active.json; 400 checks precede 409; exported runnerapi.ValidateConfig, AdoptRequest; shared decodeBody).
Pre-T6: Ruling: the hot path removes leftover run/hot/*.json (a crash's) before writing a new one, and the file after ado either way; an untagged outbound disqualifies the plan; an unreadable active config or a runner not 'running' goes straight to the trial — cost if wrong: an extra trial.
Task 5: review ✅ Approved (a8912562eb4dc176a).
Task 5: minor (deferred): Adopt doc says 'while xray runs from the active selection' (after a failed Reload it adopts with the running core/geo — consistent with what's live; reword); ErrInvalidConfig comment omits non-regular files and the 400 detail echoes the caller's string; two near-duplicate client test rows; decodeBody accepts trailing data (pre-existing xray-api behaviour).
Task 5: complete (commits e4ef857..6278b16, review clean)
Task 6: dispatched (BASE 6278b16, opus; carries in task-6-carries.md)
Task 6: implementer DONE_WITH_CONCERNS fdf5577.
Task 6: Ruling: the five extra checks are accepted — runner must run the active core with a nonzero PID; the active config name is validated before reading; a post-adopt status check confirms the same xray PID (a mid-change restart falls back); Runner.Restart when the fallback trial never restarted xray (refused/rejected after a mutation); a server outbound may not be xray's first (default) outbound — each falls back to a trial or restart — cost if wrong: an extra trial.
Task 6: Ruling: a Test error that isn't a rejection falls back to the trial with the note — the trial then reports the runner's state — accepted.
Task 6: Ruling (load-bearing): a pending marker closes the crash gap — before the first xray api call write run/hot/pending (0600) naming the candidate; remove it after the adopt, or after the fallback trial/restart ends; any Apply that finds the marker skips both the noop check and the hot path: if the render equals the active config it runs Runner.Restart (xray resyncs to active.json), else a full trial — otherwise a tikray that died after ado/rmo and a later state change (e.g. the added server deleted, so render == active) leaves a stray server outbound live forever — dispatched with the review's fixes — cost if wrong: one extra restart after a crash.
Task 6: carry to T7: confirm real xray behaviour the fake assumes — rmo of a missing tag and ado of an existing tag exit non-zero; ado takes several outbounds in one file.
Task 6: review ✅ Approved (a7993e9ce56f112ec) — but the marker ruling as worded wouldn't close the gap: the service's pass/catchUp skip Apply when render == active.
Task 6: Ruling (amended, load-bearing): the marker run/hot/pending is written before the first xray api call; removed only after a verified end state (change ok incl. the PID check, or a fallback trial actually started, or a Restart succeeded); honoured whatever u.Hot is; an Apply finding it skips noop and hot (render == active → Runner.Restart; else trial, and Restart if refused/rejected); internal/service's pass and catchUp call Apply when artifacts.HotPending(data) — cost if wrong: one extra restart after a crash.
Task 6: Ruling: folded into the round — the fallback's restart decision by xray PID (not the outcome string; the double fault), sweep stale run/hot/*.json in locked, the note's wording, the nil-u test panic, and the missing rejected/Status-error rows.
Task 6: minor (deferred): TestHealthProbesOfACommand 300 ms window flaked once under -race (pre-existing timing fragility); no test that Rollback never goes hot; Detail counts are numbers, not tag lists (accepted).
Task 6: ruling round 1/5 dispatched (resume a5d2e4b4bda41bab5; FIX_BASE fdf5577).
Task 6: ruling round 1 implemented 55e3ad1, c103901.
Task 6: Ruling: accepted conservative edges — a failed post-adopt status restarts xray even if the fallback committed; a marker with an unrenderable state waits until a render works; an update/rollback leaves the marker for the next Apply (one extra restart); an unreadable marker counts as present — each costs at most an extra restart, never a stray outbound.
Task 6: minor (deferred): hot.go is 502 lines.
Task 6: re-review round 1 (a3cf1a7916b901226): items 1-3 ADDRESSED; New Breakage 1 (Important): on change's exits before the adopt (rmo, ado, probe) h.pid is still st.XrayPID from Apply's start — a supervisor restart of xray during Test/baseline (X1→X2), a hot call on X2 that fails, and a refused/rejected fallback trial make resync see X2≠X1, clear the marker and skip the restart: a stray (or missing) server outbound with no marker; regression from fdf5577 (repro in scratchpad/repro/internal/artifacts/zz_repro_test.go).
Task 6: Ruling: on every error exit of change after the marker is written and before the adopt, h.pid is taken from a Status after the failure (cleanupContext; -1 on error, which resync treats as "restart") — any xray with another PID was then started after the last xray api call, from the active config or a trial's candidate; the hotAttempt.pid comment is corrected; the two repros become TestHotFallbackRestoresXray rows — cost if wrong: an extra restart.
Task 6: ruling round 2/5 dispatched (resume a5d2e4b4bda41bab5; FIX_BASE c103901).
Pre-T9: Ruling: results files are <ros>-<arch>-m2c-auth.json and -m2c-hot.json (suite names m2c-auth, m2c-hot), not one -m2c.json — recordChecks writes one file per suite and two suites under one name overwrite each other — cost if wrong: file names only.
Task 6: ruling round 2 implemented 791ce92 (pidNow after each failed call before the adopt; two RED→GREEN rows).
Task 6: re-review round 2 (a3cf1a7916b901226): New Breakage 1 ADDRESSED (pidNow on the rmo, addOutbounds and probe exits; repros RED at c103901, GREEN at 791ce92; edge tests clean) — Approved.
Task 6: complete (commits 6278b16..791ce92, review clean after 2 ruling rounds)
Task 7: dispatched (BASE 791ce92, sonnet; carries in task-7-carries.md)
Task 7: implementer DONE_WITH_CONCERNS fb76752 (TestHotAgainstReleases on 26.1.18, 26.9.30, 26.10.21, plus 26.3.27/26.4.13; apiConfigWith split from apiConfig). Confirmed on all: ado of an existing tag exits 1 ("existing tag found"); ado of several adds in file order, stops at the first failure, keeps the earlier ones; rmo then ado of one tag works. Findings F1, F2.
Task 7: Ruling (F1): rmo of a missing tag exits 0 on every release ("removing: <tag>\n{}") — rmo is idempotent, which is benign: the hot path's safety rests on the marker and the PID checks, never on rmo failing (an rmo that removes nothing still ends with the tag absent, as the candidate wants); no version gate and no hot.go change; the fake runner's rmo of a missing tag exits 0 with that stdout, TestHotInterruptedHeals' "the rmo went through" row now expects the hot change itself to bring xray to the candidate (Hot true, live == candidate), and the compat step asserts exit 0 with lso unchanged — cost if wrong: none for safety.
Task 7: Ruling (F2): before 26.4.13 the observatory keeps a removed outbound's OutboundStatus entry (no clearRemovedOutbounds; lso and BalancerTargets drop it) — no gate: health reads OutboundStatus by the state's own tags (serverHealth byTag) and the balancer's candidates come from the outbound manager, so a removed server's stale entry is never read; a changed server (rmo+ado of its tag) shows its old result until the next probe round. The compat test asserts lso and BalancerTargets drop the tag on every version, OutboundStatus drop from 26.4.13 (a named constant citing clearRemovedOutbounds), and on every version that a re-added tag's OutboundStatus gets a LastTry after the ado within 30 s — if that fails on a version, it's a finding and the hot path gets gated there — cost if wrong: a stale health row for one probe round.
Task 7: fix round 1/5 dispatched (resume ae2a0e6dbf1ca9f94; FIX_BASE fb76752).
PAUSE (user, 2026-10-26): no new dispatches until the user resumes; Task 7 fix round 1 (ae2a0e6dbf1ca9f94) was already running and is left to finish its local commit.
Task 7: fix round 1 implemented 79f8582 (fake rmo of a missing tag exits 0; TestHotInterruptedHeals rmo row now hot, RED→GREEN; compat: lso/BalancerTargets drop on all, OutboundStatus drop from 26.4.13 (observatoryPrunes), fresh LastTry after a changed re-add within 30 s on all five releases — no gate). Paused: Task 7 review not yet dispatched.
