# Instructions for AI assistants working on tikray

Start with [`docs/handoff/README.md`](docs/handoff/README.md). It covers the project's status, where work stopped, the next steps, how to test, and the code map. The spec in `docs/superpowers/specs/` is the binding authority; the plans in `docs/superpowers/plans/` argue from it.

## Rules (set by the owner, binding)

- **Commit author:**
  - Author every commit as `Arman2122 <arman.seyri@gmail.com>`.
  - Add no trailers: no `Co-Authored-By`, no `Claude-Session`, nothing.
  - Never put AI model names in commits, PR text or code.
- **History:** never force-push or rewrite pushed history, and never merge a PR, without asking the owner first.
- **Secrets:** never let a secret reach logs, errors, events, history, API responses, test output or results files. That covers:
  - share links, server credentials, subscription URLs;
  - API and root tokens, passwords and hashes;
  - the setup code, session ids, CSRF tokens and keys.
- **Tests:** work test-first. Run `make test` (vet + unit tests) before every commit; it must stay green.
- **Linux only:** the code builds and tests only on Linux. On Windows, run every command in WSL2 Ubuntu. `scripts/dev-setup.sh` installs the tools.
- **Decisions:**
  - Make decisions yourself, as a senior engineer would.
  - Record every departure from the plan in the milestone's ledger as `Ruling: <what> — <why> — <cost if wrong>`. For M2c that is `docs/handoff/m2c/ledger.md`.
- **Style:**
  - stdlib first;
  - errors carry their package prefix (`auth: …`);
  - comments say why;
  - match the surrounding code's naming and comment density.
