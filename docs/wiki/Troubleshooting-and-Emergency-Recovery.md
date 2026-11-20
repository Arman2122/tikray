# Troubleshooting & Emergency Recovery

This cookbook covers rapid recovery from outages, forgotten credentials, RouterOS conflicts, and clean removal.

---

## 1. Emergency Off (Instant Direct Internet)

If you ever suspect `tikray` is blocking traffic or you need immediate direct WAN access — **even if both containers are stopped or broken** — run in the RouterOS terminal:

```routeros
/system/script/run tikray-emergency-off
```

- Detaches all `tikray` steering rules, DNS redirects, IPv6 guards, and **all kill switches** immediately.
- Purges affected conntrack bindings safely while preserving your owner firewall, management access, and unrelated connections.
- Writes an inert `tikray-emergency-state` marker that survives reboot.
- When both containers return healthy, `tikray` automatically re-verifies desired policy, re-arms protection, and clears the marker.

---

## 2. Lost Admin Password

You do **not** need to reinstall or lose your servers/policies. Run inside the control container:

```routeros
/container/shell [find comment="tikray:tikray"] cmd="tikray admin reset"
```

- Clears the admin password and active browser sessions (your servers, policies, and named API tokens remain intact).
- Generates a fresh one-time setup code — retrieve it via:
  ```routeros
  /container/shell [find comment="tikray:tikray"] cmd="tikray setup-code"
  ```
- Open the Web UI to claim your new admin password.

---

## 3. Common Diagnostic States (`routeros.degraded` & UI Banners)

Run `tikray status` (or check the **Dashboard** and **Live Events** in the Web UI) to inspect `routeros`:

| Symptom / Status | Cause | Fix |
|---|---|---|
| **`routeros.untested: true`** (on RouterOS `7.26+`) | You upgraded to a canonical RouterOS `7.26+` release not yet verified in CHR CI | Non-blocking informational notice. Reconciliation runs normally on the modern `7.23+` profile; check `tikray events` after any RouterOS upgrade. |
| **`routeros.degraded: "bridge_repair"`** | A new local route or address overlaps the private `/29` bridge subnet | Open **Settings → Bridge Repair** (or call `PUT /v1/network`) to move atomically to a clean non-overlapping `/29` subnet. |
| **Device admission refused (broad NAT)** | An owner `srcnat`/`masquerade` rule lacks `out-interface` / `out-interface-list=WAN`, rewriting LAN client IPs before reaching `tikray-runner` | Scope your WAN masquerade rule to `out-interface-list=WAN`, and keep `tikray:` NAT exception rules above owner NAT rules. |
| **Rules keep re-triggering reconciliation** | Manual edit or foreign rule placed above `tikray:` bridge forward or NAT guards | Inspect `/ip/firewall/filter` and `/ip/firewall/nat` for rules tagged `tikray:`; keep `tikray:` guards above FastTrack and permissive owner rules. |
| **Installer reports `tikray-install-lock` busy** | Another install session is active or was killed mid-run | Wait for the active session to finish (lock expires automatically after at most 30 minutes or on reboot) before re-importing. |
| **`xray-core` update rolled back automatically** | New candidate failed gRPC health or `probe_url` SOCKS check within the trial deadline | Check **Live Events** (`tikray events`) for the redacted probe error; verify `probe_url` is reachable through your active server and that at least one enabled server is healthy. |
| **Login returns `429 Too Many Requests`** | Too many failed setup/login attempts triggered IP rate limiting | Wait for the `Retry-After` countdown shown in the Web UI (automatic reset). |

---

## 4. Collecting Safe Diagnostics for Bug Reports

`tikray` automatically redacts secrets from `tikray status`, `tikray stats`, and `tikray events`:

```sh
tikray version
tikray status --json
tikray stats --json
tikray events
```

On RouterOS, include:

```routeros
/system/resource/print
/container/print detail
```

> **Never paste raw share links, subscription URLs, `/data/state/routeros.json`, `api.token`, or `setup.code` into GitHub issues.**

---

## 5. Clean Uninstall (`keep` vs. `purge`) & Reinstall

Generate or download `uninstall.rsc` (`go run ./cmd/tikray-installer -uninstall-out uninstall.rsc`), upload it to RouterOS, and run:

### Keep Data (Default — Recommended Before Reinstalling)
```routeros
:global tikrayUninstallData "keep"
/import file-name=uninstall.rsc
```
Removes both containers, RouterOS account, routes, firewall rules, ARP/FDB entries, and private bridge — while preserving `/data` (servers, admin, TLS certificate, core slots) and printing your previous **public installation ID**.

To reinstall later onto that kept `/data` volume (same disk, directory, and subnet):
```routeros
:global tikrayReuseID "<previous-public-installation-id>"
/import file-name=install.rsc
```

### Complete Purge
```routeros
:global tikrayUninstallData "purge"
/import file-name=uninstall.rsc
```
Deletes everything including `/data` cleanly.
