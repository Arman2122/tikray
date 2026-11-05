# Task 9 carries (controller rulings that amend the brief — binding)

1. **TestAuth's order (pre-flight P2).** Run the checks in this order: setup_required, claim_admin, session_and_csrf, api_token, restart_keeps_auth, login_rate_limit.
   - The setup and sign-in failures share one per-IP bucket of 5, which refills 1 every 60 s.
   - The limiter lives in memory, so the restart resets it. login_rate_limit therefore starts from a full bucket, whatever the 3 bad codes in claim_admin spent.
   - In login_rate_limit:
     - each of the 5 wrong passwords is 401 `bad_credentials`;
     - the 6th, and the right password after it, are 429 with `Retry-After` in whole seconds (≤ 60);
     - wait that long (bounded: at most `Retry-After` + 5 s), then the right password is 200.
2. **The fixed values (Tasks 1–4).**
   - The cookie is `tikray_session` with `Secure; HttpOnly; SameSite=Strict; Path=/`, and `Max-Age` is 7 days.
   - The CSRF header is `X-Tikray-CSRF`.
   - The setup code reads `XXXX-XXXX-XXXX` (Crockford base32).
   - API tokens read `tkr_<8hex>_<43 b64url>`.
   - Error codes: `bad_code` 401, `bad_credentials` 401, `rate_limited` 429, `already_claimed` 409. A cookie request that changes anything without the right CSRF header is 403 `csrf`. The CSRF value is `csrf_token` in the setup, login and session answers.
3. **setup_required (Task 4).**
   - `tikray setup-code` at `/container/shell` prints the code and exits 0.
   - serve's stderr hint is `tikray: no admin yet: run "tikray setup-code" in this container to get the setup code`, before `serving on`.
   - Check that the code string appears nowhere in the container log (`containerLog`), not just that the hint line lacks it.
   - After the claim, `tikray setup-code` prints `the admin has been claimed`.
4. **Secrets in results.** The results JSON and the test log never carry the setup code, the password, a cookie value, a CSRF value or an API token. Record lengths and shapes, not values. The same rule covers `t.Logf`/`note`.
5. **The root bearer (`state/api.token`)** is what `Lab.api` already uses. TestService's 8/8 re-run on 7.25 x86_64 is the evidence that the auth chain kept it working. A cookie or user-token client is new here: build it on the pinned client (`apiClient`) with a cookie jar, or set headers by hand. Don't fork the TLS pinning.
6. **TestHot (Task 6).**
   - `last_apply.hot` is JSON `hot` on the status.
   - A hot apply's Detail starts `applied without restarting xray: added N, removed N, changed N`.
   - Read the xray PID from the runner's Status (`runnerStatus`).
   - "lab-b alive" means `OutboundStatus` lists it alive within 30 s.
   - `hot_survives_runner_restart`: the runner's `active.json` config must equal the `To` of tikray's last apply. That is the Task 5 Adopt. After the runner container restarts, whoami still goes through b.
   - Also assert that `run/hot/pending` is absent after each step. Use `Lab.exists` on the tikray side at `<data>/run/hot/pending`. A leftover marker would mean the next apply restarts xray needlessly.
7. **Task 7 findings (ledgered F1, F2).**
   - `rmo` of a missing tag exits 0 on every release; rmo is idempotent.
   - Before xray 26.4.13 the observatory keeps a removed outbound's `OutboundStatus` entry. `lso` and `BalancerTargets` do drop it.
   - For `hot_remove`, decide 'lab-a is gone' by `xray api lso` or `BalancerTargets`, not `OutboundStatus`. The lab's core may be older than 26.4.13.
   - The spec's §3.4 hot-change limits get one line: before 26.4.13 a removed server's observatory entry lingers until xray restarts, which is harmless because health reads by the state's tags.
8. **Lab rules (from M1–M2b).**
   - Run labs in the background with a log file and bounded waits.
   - Kill leftovers by PID (`ps -C`), never with `pkill -f`.
   - Start dockerd yourself for each image build, and stop it afterwards. The background limit is 2 h, so don't leave one running across runs.
   - RouterOS `cmd=""` does not unset cmd: use `/container/unset … cmd`.
   - Results files: `recordChecks` writes one file per suite name, so two suites named `m2c` would overwrite each other. Use the suite names `m2c-auth` (TestAuth) and `m2c-hot` (TestHot). That gives `test/e2e/results/<ros>-<arch>-m2c-auth.json` and `…-m2c-hot.json`, e.g. `7.25-x86_64-m2c-auth.json`. Commit all six.
