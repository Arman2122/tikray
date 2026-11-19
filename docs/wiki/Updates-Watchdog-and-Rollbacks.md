# Updates, Watchdog & Rollbacks

One of `tikray`'s core design principles is **safe, independent updates**: updating Geo data should never restart your containers, updating `tikray` should never drop your active VPN traffic, and a bad `xray-core` release should never strand your LAN offline.

---

## 1. Four Independent Update Lifecycles

| Lifecycle | Command / UI Action | Cryptographic Verification | Rollback Mechanism | Traffic Impact |
|---|---|---|---|---|
| **`xray-core`** | `tikray core update latest` | Upstream `.dgst` SHA-256 or ECDSA P-256 signed `index.json` | Deadline-backed runner trial auto-reverts to previous slot | ~1–2 s switch |
| **Geo Data** | `tikray geo update latest --profile iran` | Upstream SHA-256 + `O_NOFOLLOW` immutable slot | Journaled rollback of both xray slot & RouterOS domestic address-list | Seamless |
| **`tikray` Control** | `tikray image update tikray v1.0.1` | `cosign verify-blob` + archive digest | RouterOS watchdog blue/green swap + `/healthz` revert | **Zero** |
| **`tikray-runner`** | `tikray image update runner v1.0.1` | `cosign verify-blob` + archive digest | RouterOS watchdog swap + gateway ping revert | Brief container restart |

---

## 2. How Deadline-Backed Trials Work

Whenever `tikray` switches `xray-core` or applies a non-hot-reloadable config change:
1. `tikray` renders the version-gated `xray-core` JSON config (`internal/render`) and asks `tikray-runner` to start a **deadline-backed trial**.
2. `tikray-runner` launches the new candidate `xray-core` and sets an enforced hard rollback timer.
3. `tikray` verifies both:
   - `xray-core` gRPC API responsiveness
   - End-to-end SOCKS connectivity through the candidate config against your configured `probe_url`
4. Only after both probes succeed does `tikray` call `commit`. If anything fails — or if `tikray` crashes mid-update — `tikray-runner` **automatically reverts** to the last known-good slot when the deadline expires.

### Zero-Downtime Hot Outbound Reloads
When only `srv-*` server outbounds change (adding/removing/enabling/disabling a server or refreshing a subscription) and `TIKRAY_HOT` is enabled (the default):
- `tikray` swaps outbounds live through `xray api` (`rmo` / `ado`), probes health, and calls runner `POST /v1/adopt`.
- **Active LAN connections stay open with zero interruption.**
- If hot reload returns an error, `tikray` falls back automatically to a standard trial.

---

## 3. Native RouterOS Watchdog

The installer provisions a native RouterOS scheduler (`tikray-watchdog`) running every minute — completely independent of Go code:

- **Control Plane Check:** Fetches `https://<control-ip>/healthz` and verifies both `ok: true` and the installation's public `installation_id`.
- **Data Plane Check:** Pings the runner gateway over the isolated reply-only ARP bridge.
- **Exponential Backoff:** Three consecutive missed probes trigger an automatic restart of the affected container, backed off at `1, 2, 4, 8, 15` minutes until healthy.
- **Zero Flash Wear on Healthy Checks:** Steady healthy checks perform **zero** RouterOS state writes.
- **Safe Yielding:** Automatically yields during an active installer, container image upgrade, `tikray-emergency-off`, or uninstall.

---

## 4. Encrypted Backup & Disaster Recovery

Back up your complete configuration (servers, credentials, subscription URLs, per-device policies, custom rules, DNS, and health settings) into a portable **`tikray-backup-v1`** file sealed with **Argon2id (`19456 KiB, t=2, p=1`) + AES-256-GCM**:

### Export Backup
- **Web UI:** **Settings → Encrypted Backup → Export Backup** (enter a 10–256 character passphrase).
- **CLI:**
  ```sh
  TIKRAY_BACKUP_PASSPHRASE="your-strong-passphrase" \
    tikray backup export --out tikray-backup.json
  ```

### Restore Backup
- **Web UI:** **Settings → Encrypted Backup → Restore Backup** (upload `.json` + enter passphrase).
- **CLI:**
  ```sh
  TIKRAY_BACKUP_PASSPHRASE="your-strong-passphrase" \
    tikray backup restore --in tikray-backup.json
  ```

> **Cross-Router Safe:** When restoring onto a managed MikroTik RouterOS installation, `tikray` **automatically preserves the target router's installed bridge subnet** (`network`), so you can migrate a backup from Router A to Router B without breaking container networking.
>
> **Security:** Named API tokens (`tkr_*`) cannot export or restore backups; use an interactive admin browser session or the container-local root CLI.
