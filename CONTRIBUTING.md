# Contributing to tikray

Thank you for your interest in contributing to **tikray**! This guide covers environment setup, coding conventions, security invariants, and the pull request workflow.

## Development Environment

`tikray` runs inside MikroTik RouterOS Linux containers and uses Linux-specific system calls (`netlink`, `flock`, `O_NOFOLLOW`/`Openat`). All Go builds and tests must run on **Linux** (or **WSL2 Ubuntu** on Windows).

### Prerequisites

- **Go 1.24+** (see [`go.mod`](go.mod))
- **Node.js 20+ & npm** (only required when editing the Web UI under `web/`)
- **Docker with the classic image store** (`{"features":{"containerd-snapshotter":false}}` in `/etc/docker/daemon.json`) for `make images`
- **QEMU & root privileges** for full RouterOS CHR lab runs (`make lab-deps`)

On Debian/Ubuntu or WSL2 Ubuntu:

```sh
scripts/dev-setup.sh        # Go toolchain + make test
scripts/dev-setup.sh --lab  # Optional: QEMU, Docker, and CHR lab tools
```

## Working Test-First

Every behavioral change or bug fix must include tests:

```sh
# 1. Vet + unit tests (must stay green before every commit)
make test

# 2. Race detector across all Go packages
make race

# 3. Verify lab build-tag compilation
go vet -tags lab ./test/... ./internal/... ./spike/...

# 4. If you edited web/, type-check and rebuild the embedded bundle
make ui
```

## Coding Standards

- **Standard library first** — Avoid adding external Go or npm dependencies unless strictly justified; RouterOS containers have tight flash and RAM budgets.
- **Package-prefixed errors** — Exported errors carry their package prefix (e.g., `backup: …`, `routeros: …`, `auth: …`).
- **Comments explain why** — Focus comments on invariants, RouterOS quirks, and failure modes rather than restating obvious code.
- **Unix LF line endings** — `.gitattributes` enforces LF across the repository; shell and RouterOS `.rsc` scripts fail on CRLF.
- **Strict secret discipline** — Never allow any of the following into logs, error messages, events, history files, API views, or test output:
  - Share links, server UUIDs/passwords, subscription URLs
  - Root API token, named API tokens, passwords or hashes
  - Setup code, session IDs, CSRF tokens/keys, backup passphrases, RouterOS credentials

## Web UI Contributions (`web/`)

- Built with Svelte 5 (runes), Vite, and TypeScript (`strict: true`).
- Keep **zero external fonts, CDNs, or third-party runtime beacons** — the UI must work 100% offline behind censored or air-gapped networks.
- Keep `npm run check` at **0 errors and 0 warnings**.
- After editing `web/`, run `make ui` so `internal/ui/dist/` stays synchronized with source, and verify `go test ./internal/ui ./internal/api`.

## Pull Requests

1. Fork the repository and create a topic branch from `main`.
2. Keep commits focused, atomic, and cleanly described.
3. Run `make test`, `make race`, and (when touching `web/`) `make ui`.
4. Fill out the PR template explaining what changed, why, and how it was verified.
5. Never force-push shared branches or commit credentials/capture files.
