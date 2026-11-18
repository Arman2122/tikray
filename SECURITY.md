# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `1.0.x` | Yes |
| `< 1.0` (pre-release milestones) | No — upgrade to `1.0.x` |

## Security Architecture

`tikray` is designed to operate safely on edge routers facing untrusted WANs and filtered networks:

- **Zero-Secret Views & Logs**: Server credentials, share links, subscription URLs, passwords, setup codes, API tokens, session IDs, CSRF keys, RouterOS credentials, and backup passphrases are excluded from API views, event logs, history files, and redacted error responses.
- **Authentication & Browser Protection**:
  - Passwords hashed with Argon2id (`19456 KiB`, `t=2`, `p=1`, concurrency capped at 2).
  - Browser sessions use `Secure; HttpOnly; SameSite=Strict` cookies plus HMAC-SHA256 `X-Tikray-CSRF` headers on every non-read request.
  - Setup and login attempts are rate-limited per IP (and `/64` for IPv6) plus a global bucket.
  - Named API tokens are restricted from password changes, admin resets, encrypted backup export/restore, and offline inbox uploads.
- **Encrypted Backups**: Backups (`tikray-backup-v1`) use Argon2id + AES-256-GCM with format version as AAD and strict min/max KDF parameter validation to prevent memory/CPU DoS on constrained routers.
- **Certificate Pinning**: Both the RouterOS native API-SSL client and CLI client pin exact SHA-256 leaf certificate fingerprints.
- **Supply Chain Integrity**:
  - Container images are verified with `cosign verify-blob` and chunked SHA-512 installer digests.
  - `xray-core` archives are verified against upstream `.dgst` or ECDSA P-256 signed hash indexes.
  - Filesystem updates use symlink-safe `O_NOFOLLOW` / `openat` traversal and atomic fsynced renames.
- **RouterOS Isolation**:
  - Private container bridge uses reply-only ARP, disabled MAC learning, and explicit forward firewall guards.
  - Every RouterOS write is generation-bound and scoped to `tikray:`-owned objects.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately using one of:

1. **GitHub Security Advisories** (preferred): Open a private advisory at `https://github.com/Arman2122/tikray/security/advisories/new`.
2. **Direct email**: Send details to `arman.seyri@gmail.com` with subject `[tikray-security]`.

Include:
- Affected component (`tikray`, `tikray-runner`, `tikray-installer`, `routeros/*.rsc`, or `web/`)
- Version / commit hash and RouterOS version (if applicable)
- Clear reproduction steps or proof-of-concept
- Potential impact

### Response Expectations

- Acknowledgement within **72 hours**.
- Confirmed vulnerabilities receive a coordinated fix, regression test, and security advisory credit (unless anonymity is requested).
