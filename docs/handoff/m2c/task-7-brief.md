### Task 7: Compat: hot changes against real xray

**Files:**
- Create: `test/compat/hot_test.go` (tag `compat`).

**Interfaces:**
- Consumes: M2b's `test/compat` helpers (`compatVersions`, the cached binaries, `TestXrayAPIAgainstReleases`' config builder), Task 5–6's command forms.
- Produces: `TestHotAgainstReleases`. For each version in `compatVersions`:
  1. Start xray with `api-in`, the HandlerService, an observatory and a `proxy-open` leastPing balancer over `srv-`, with outbound `srv-a` (freedom).
  2. `xray api ado --server=<api> <file with srv-b>`. Then `OutboundStatus` lists `srv-b` within 30 s, and `BalancerTargets` may include it.
  3. `xray api rmo --server=<api> srv-a`. Then `srv-a` drops out of `OutboundStatus` within 30 s.
  4. `ado` of an existing tag exits non-zero (Task 6 relies on this for healing).

  Run: `go test -tags compat -count=1 -run TestHotAgainstReleases ./test/compat/...`. Expected: PASS on every version.

- [ ] **Step 1: Write the test.** Run it; it passes when the xray behaviour matches. A version where a step differs is a finding: report it, and gate the hot path on that version in Task 6 through `render.Features`.
- [ ] **Step 2: Commit**

  `git commit -m "Test hot outbound changes against every xray release tikray supports"`
