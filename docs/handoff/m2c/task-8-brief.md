### Task 8: Service: re-test untested servers, and test in batches

**Files:**
- Modify: `internal/store/model.go` (`Server.Untested`), `internal/service/servers.go`, `internal/service/subscribe.go`, `internal/service/apply.go`.
- Create: `internal/service/retest.go`.
- Test: `internal/service/retest_test.go`, `internal/service/subscribe_test.go`, `internal/store/model_test.go`.

**Interfaces:**
- Produces:
  - `store.Server.Untested bool`, JSON `untested,omitempty`. It is set when a server is saved without a runner test (M2b's untested paths) and cleared by a passing test.
  - `func (s *Service) testOutbounds(ctx, outbounds map[string]json.RawMessage) (rejected map[string]string, err error)`.
    - It tests up to 32 outbounds in one config through `Runner.Test`.
    - On a rejection it bisects (halves, recursively) until each rejected outbound is alone, so 1 bad server out of 200 costs about 16 tests, not 200.
    - A runner error returns `err` (untested), as in M2b.
  - **The refresh's per-entry test and AddServer's test use it.** The refresh also tests entries whose kept server is `Untested`, even when unchanged.
  - **Re-test:** after a loop pass or a core update/rollback that leaves a core running, if any server is `Untested`, test those in a batch:
    - rejected → `Disabled`, `Invalid = reason`, `Untested` cleared, and a `degraded` event;
    - passed → `Untested` cleared.

    It writes with one `store.Update` and kicks if anything changed. A runner error leaves them for the next pass.

- [ ] **Step 1: Write the failing tests:**
  - `TestBatchBisects`: 200 outbounds with 2 bad → both found with ≤ 20 `Test` calls, and the rest pass.
  - `TestBatchRunnerDown`.
  - `TestUntestedMarked`: a save with no core sets it.
  - `TestRetestAfterCoreArrives`: an untested bad server is degraded with an event, and the good one is cleared.
  - `TestRefreshRetestsUntested`.
  - The store round-trips `untested`.
- [ ] **Step 2: Run them**

  Run: `go test ./internal/service/ ./internal/store/`. Expected: FAIL.

- [ ] **Step 3: Implement.** Then run `go test -race -count=3 ./internal/service/` and `make test`. Expected: PASS.
- [ ] **Step 4: Commit**

  `git commit -m "Test servers in batches, and test again the ones saved untested once a core runs"`

