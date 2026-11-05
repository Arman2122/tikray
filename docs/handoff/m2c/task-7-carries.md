# Task 7 carries (controller notes — binding)

1. **What Task 6's fake assumes, which this test must confirm on every release** (from the Task 6 review):
   - `xray api rmo --server=<api> <tag>` of a tag xray doesn't have exits non-zero;
   - `xray api ado --server=<api> <file>` of a tag xray already has exits non-zero (Task 6's healing relies on it);
   - `ado` with several outbounds in one file adds them in order and stops at the first failure (check what it does with the ones before the failure: added and left in place).
   Add a step for each. If a release behaves differently, it is a finding: report the exact behaviour; the controller will rule on gating the hot path by version (`render.Features`).
2. **Exactly what Task 6 sends.** Read `internal/artifacts/hot.go` for the argument forms (`rmo --server=…`, `ado --server=… <file>`) and the outbound-file shape (`{"outbounds":[…]}`); the compat test uses those exact forms, not hand-written variants.
3. **The config.** Reuse M2b's `TestXrayAPIAgainstReleases` config builder in `test/compat/xrayapi_test.go` (api-in, HandlerService, observatory, `proxy-open` leastPing over `srv-`); add the HandlerService if that builder lacks it.
4. **Liveness signals.** "Listed" means `OutboundStatus` from `internal/xray` within 30 s (the observatory picks a new outbound up on its next round — keep the observatory's interval short in the test config, e.g. 2–5 s); also `xray api lso` (outbound list) if the release has it, as a direct check that doesn't wait on the observatory.
