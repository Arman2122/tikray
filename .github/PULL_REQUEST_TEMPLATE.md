## Summary

<!-- Describe what this PR changes and why. -->

## Verification

- [ ] `make test` passes in Linux / WSL2
- [ ] `make race` passes without data races
- [ ] `go vet -tags lab ./test/... ./internal/... ./spike/...` passes
- [ ] If `web/` changed: `make ui` completed with 0 errors and 0 warnings
- [ ] Verified no secrets (credentials, tokens, URLs, passphrases) reach logs, errors, events, or API responses
- [ ] Any deviation from the design spec is recorded in the milestone ledger (`Ruling: ...`)
