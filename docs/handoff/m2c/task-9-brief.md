### Task 9: End to end: sign-in and hot changes on CHR

**Files:**
- Create: `test/e2e/auth_lab_test.go` and `test/e2e/hot_lab_test.go` (tag `lab`), and the results files `test/e2e/results/<ros>-<arch>-m2c.json`.
- Modify: `test/e2e/lab.go` (helpers), and the spec's §3.4, §7 and §10.

**Interfaces:**
- Consumes: Tasks 1–8, and M2b's `TestService` helpers (`startServe`, `Lab.api`, `Lab.setSub`, the pinned client).
- Produces: `TestAuth` and `TestHot`, recorded together in the m2c results.
- **`TestAuth`, in order:**
  1. `setup_required`: a fresh serve. `GET /v1/auth/state` says setup is required. The code from `/file/get state/setup.code` equals what `tikray setup-code` prints at `/container/shell`, and serve's log line holds no code.
  2. `claim_admin`:
     - three wrong codes → 401 `bad_code`;
     - the right code → 200, with `Set-Cookie` flags `Secure`, `HttpOnly`, `SameSite=Strict`;
     - the code file is gone and `state` says signed in.
  3. `session_and_csrf`:
     - `GET /v1/status` with the cookie → 200;
     - `PUT /v1/policy` with the cookie and no header → 403, and the revision is unchanged;
     - with the header → 200;
     - the root bearer with no header → 200.
  4. `login_rate_limit`:
     - 5 wrong passwords → 401 each;
     - the 6th, and then the right password → 429 with `Retry-After`;
     - after waiting `Retry-After` the right password works.
  5. `api_token`: create, then use it (200); the list has no secret; revoke, then 401.
  6. `restart_keeps_auth`: `/container/stop`, then start. The old cookie and the token still work, and setup isn't required.
- **`TestHot`, in order** (with M2b's lab-a and lab-b, a smart device, and the lab probe URL):
  1. `hot_add`: with lab-a applied and traffic through it, add lab-b by link.
     - Within 60 s: `applied`, and `last_apply.hot` is true.
     - The runner's xray PID is unchanged (`runnerapi.Status.XrayPID`), and observatory shows lab-b alive within 30 s.
  2. `hot_remove`: remove lab-a. The PID is unchanged, `hot` is true, and whoami goes through b.
  3. `not_hot`: change the device policy to `full`. A trial runs (the PID changes, `hot` is false), and whoami goes through b.
  4. `hot_survives_runner_restart`: restart the runner container. Its `active.json` config equals the one tikray last applied, and whoami goes through b.
- Run on CHR 7.25 x86_64, 7.23.8 x86_64 and 7.25 arm64, and commit each results file. Re-run M2b's `TestService` on 7.25 x86_64: the auth chain must not break the root bearer.
- **Spec:** §3.4 (hot changes are done, with their limits and the fallback), §7 (the fixed auth values), §10's M2 row.

- [ ] **Step 1: Write `TestAuth` and `TestHot`** with the checks above.
- [ ] **Step 2: Run both on 7.25 x86_64 stable** (in the background, logged)

  Run: `TIKRAY_LAB_CHANNEL=stable go test -tags lab -p 1 -count=1 -v -timeout 240m -run 'TestAuth|TestHot' ./test/e2e/`. Expected: 6/6 and 4/4.

  A failing check is a finding: root-cause it and fix the code, not the check, unless the check contradicts the spec.

- [ ] **Step 3: Run them on long-term x86_64 and stable arm64.** Expected: 6/6 and 4/4 each.
- [ ] **Step 4: Re-run `TestService` on 7.25 x86_64.** Expected: 8/8.
- [ ] **Step 5: Update the spec, and commit**

  `git commit -m "Test sign-in and hot changes end to end on CHR"`
