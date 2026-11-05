# M2c shared context (every implementer and reviewer reads this)

Project: tikray, an xray-core client for MikroTik RouterOS v7 in two containers (tikray = control, tikray-runner = data path). Go 1.24, module `github.com/Arman2122/tikray`, GPL-3.0. M0, M1, M2a and M2b are merged (M2b: `tikray serve`, the HTTPS API with a root bearer token, the service, health, the CLI over the API). M2c adds human sign-in and hot changes.

Plan: `docs/superpowers/plans/2026-10-26-m2c-auth-hot.md` (your brief is your task's section of it).
Spec (binding authority): `docs/superpowers/specs/2026-10-24-tikray-design.md`.
Ledger with the controller's rulings: `.superpowers/sdd/2026-10-26-m2c-auth-hot/progress.md` — a `Ruling:` line that names your task binds you like the brief.

## Global Constraints (verbatim from the plan)

- Everything in M2b's Global Constraints still holds: one process (`tikray serve`, holding `state/serve.lock`) owns the state (and now `auth.json`); the API is HTTPS with the pinned self-signed certificate; the default policy sends everything direct; kill-switch traffic never goes direct; errors carry their package prefix; stdlib first.
- **Secrets never appear** in logs, events, errors, history or API responses. Secrets are: M2b's (server credentials, subscription URLs, the root token), passwords and password hashes, the setup code, session ids, CSRF tokens (except the response that hands one to its own session), API tokens and their hashes (except the one response that creates a token), and the CSRF key. The setup code is shown only by `tikray setup-code` and in the `setup.code` file.
- **Files:** `auth.json` and `setup.code` are 0600 in the 0700 state directory, written with `internal/atomicfile`; `run/hot/` is 0700 and its files 0600, removed after use.
- **Fixed values:**
  - **argon2id:** m = 19456 KiB, t = 2, p = 1, 16-byte salt, 32-byte key, as a PHC string (`$argon2id$v=19$m=19456,t=2,p=1$<salt b64>$<hash b64>`). At most 2 hashes run at once; more wait, bounded by their context.
  - **Passwords:** 10 to 256 bytes, not equal to the username. **Usernames:** 1 to 64 runes, no rune `store.ForbiddenInName` refuses.
  - **Setup code:** 12 symbols of Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), shown `XXXX-XXXX-XXXX`; input normalised (upper-cased, `-` and spaces dropped, `O`→`0`, `I`/`L`→`1`).
  - **Sessions:** 32 random bytes, base64url, stored only as SHA-256; idle 12 h, absolute 7 days; at most 20 (oldest dropped); cookie `tikray_session` with `Secure; HttpOnly; SameSite=Strict; Path=/`.
  - **CSRF:** header `X-Tikray-CSRF`; token `base64url(HMAC-SHA256(csrf_key, session id))`; required on every cookie-authenticated request whose method isn't GET or HEAD; bearer requests are exempt.
  - **API tokens:** `tkr_<8 hex id>_<43 base64url chars>` (32 random bytes), stored as SHA-256 of the secret part; names 1 to 64 runes; at most 50; optional expiry; `last_used` kept in memory, saved at most every 10 min.
  - **Rate limit** (setup and sign-in failures only): per client IP, a bucket of 5 refilling 1 per 60 s; global, a bucket of 100 refilling 1 per 9 s; an empty bucket is 429 with `Retry-After`, before any hashing.
- **The root token** (`api.token`) keeps every M2b right and is the only credential that may reset the admin (`POST /v1/auth/reset`).
- **Hot changes** apply only when the candidate render differs from the active config in nothing but `outbounds` entries whose tag starts with `srv-` (added, removed or changed, compared as canonical JSON), the core and geo are the same, and the runner is `running`. `TIKRAY_HOT=off` makes every apply a trial.

## Working rules

- Work only in `/home/user/tikray/.claude/worktrees/m2c-auth` (branch `m2c-auth`). Use absolute paths or that directory as cwd.
- The Bash tool here refuses: shell loops, commands built from `$variables`, `cd … &&` chains, and inline heredoc scripts. Run plain separate commands; if you need a script, write it to a file with the Write tool first, then run it.
- Commits: the repo's configured identity is already `Arman2122 <arman.seyri@gmail.com>`. Use plain `git commit -m "<message from the brief>"`. **No trailers at all** (no Co-Authored-By, no Claude-Session, nothing). Never push, never amend or rebase existing commits, never touch other branches.
- `make test` is the full unit suite. Use `-race` where the brief says. Known timing-sensitive cmd/tikray tests (300 ms health windows) can flake under heavy parallel load: if one fails in a full run, re-run it alone and record both; don't change it.
- Follow the surrounding code's style: comment density, naming, error prefixes like `auth: …`.
- Never print secrets in test failure messages either.
