# M3 execution ledger

The [amended M3 plan](../../superpowers/plans/2026-11-06-m3-routeros.md) starts from main at `d9050d7`. The original review draft is `4744887`. M3a is on `m3-routeros`. M3b starts only after the owner approves merging M3a and its merge is on main.

## Owner amendments

Ruling: Gate Task 1 on a throwaway, four-part capability spike on real CHR 7.23.8 and 7.25 x86_64 — binary hashing, least privilege and notifications, comment ownership and netwatch behavior must be demonstrated before building against them — cost if wrong: a failed assumption needs a design trade-off and owner approval before Task 1.

Ruling: Deliver M3a and M3b in separate PRs, each with its own matrix, final review and owner merge approval — ship the installer, reconciler, basic watchdog and uninstall together before adding geo, image updates, outage/watchdog coverage and CHR CI — cost if wrong: two reviews, two evidence builds and a wait for M3a to merge.

Ruling: Test and document one router-local emergency off command in M3a's routing suite — the owner needs normal LAN routing even with both containers down, and the next reconcile must restore the desired protections — cost if wrong: a deliberately suspended kill switch permits ordinary WAN egress until reconciliation.

Ruling: Keep DHCP lease discovery read-only in M3 and defer reservation creation to M4 — the UI milestone owns that mutation — cost if wrong: owners create reservations themselves until M4.

## Task 0 — disposable CHR capability gate

The amendments and four rulings were pushed in `53976c5` after a passing `make test`. Task 0 uses cached x86_64 CHR ready images under QEMU TCG in WSL2, a separate copy-on-write overlay per run, and an ephemeral account restricted to the simulated control IP (.2). The real group policy readback was exactly `read,write,api`. No product code or live router is involved.

On each router, the owner account could create and sign the API-SSL certificate and establish the pinned connection. On **both 7.23.8 and 7.25**, the owner API refused a certificate template with `comment=tikray:…`, accepted the identical template without the comment, and refused to set a comment on the existing signed certificate. This disproves C for the installer-created certificate. The preflight fixture initially mistook RouterOS's explicit denied rights (such as `!policy`) for grants. It was corrected to compare only the positive grants and rerun.

### Results and scope

Probe source: [`fb28bc8`](https://github.com/Arman2122/tikray/commit/fb28bc85168050bb94fad9e69e3fb61b426bfb77). Reproduction instructions: [spike/m3/README.md](../../../spike/m3/README.md). The real probe returns a nonzero exit when a claim fails or remains unproven. On each target it recorded **61 PASS, 3 FAIL and 2 INCONCLUSIVE** across 66 checks. The three failures were restricted user removal, restricted group removal and certificate ownership. The two inconclusive results were route and conntrack notifications. The gate is **closed**.

| Claim | 7.23.8 x86_64 | 7.25 x86_64 | What the router demonstrated |
|---|---|---|---|
| A. Bounded binary SHA-512 | Pass | Pass | A real tar, including NULs and every byte value, matched the independent Go SHA-512 values for all seven ordered chunks (16 KiB maximum, short last chunk). The router rejected a flipped byte, one-byte truncation and two swapped chunks. |
| B. Traffic menus and tagged teardown under `read,write,api` | **Fail for full teardown** | **Fail for full teardown** | All nine traffic/config menus passed create/read/set/remove. The four ordered firewall menus also passed move and relative-order readback. The restricted client could not remove either a tagged RouterOS user or a tagged group; the owner successfully issued the same removals and verified absence. |
| C. Every managed object accepts the ownership tag | **Fail for certificates** | **Fail for certificates** | Twenty ordinary object classes retained the exact tag. The independent signed-certificate control failed even as owner, both on template creation and when setting the signed row. |
| D. Netwatch changes only open DNS rules | Pass | Pass | Real up/down/up transitions enabled, disabled and re-enabled exactly the open UDP/TCP DNS NAT rules. Closed rules and unowned look-alikes retained their states. The complete NAT ID sequence remained identical. |

**B by operation.** The results below match on both targets. Verified by readback after mutation. “Deletion observed” means an event for the exact deleted row ID. A separately correlated edit was not proven in these runs.

| Native menu | Restricted writes / readback | Native listener |
|---|---|---|
| `/ip/firewall/mangle`, `/ip/firewall/filter`, `/ipv6/firewall/filter`, `/ip/firewall/nat` | Add, read, edit, move relative to a distinct anchor, remove | Deletion observed on each |
| `/ip/firewall/address-list`, `/ipv6/firewall/address-list` | Add, read, edit, remove | Deletion observed on both |
| `/routing/table` | Add, read, edit, remove a FIB table | Deletion observed |
| `/ip/route` | Add, read, change comment and distance, remove an isolated active route | Inconclusive. Neither restricted nor owner session yielded a correlated edit/deletion within the observation windows. |
| `/tool/netwatch` | Add, read, set both script bodies, verify them, remove | Deletion observed |
| `/ip/firewall/connection` | Read two actual LAN-to-WAN UDP five-tuples, remove only the target by ID. The witness kept its session-local ID and the same socket returned a fresh, nonce-matched echo. | Inconclusive. Subscriptions preceded traffic. Neither session delivered a correlated event for the new target within the bounded observation. |

**C and teardown by class.** Bridge, veth, bridge port, bridge IP, table, route, IPv4/IPv6 list members and filters, IPv4 mangle/NAT, user, group, env, mount, script, scheduler, netwatch and a stopped amd64 container all passed tagged-add/readback. The restricted identity removed rows in eighteen classes. Only user and group required the owner. The signed certificate lacked a usable ownership comment. In a separate permission control, the restricted user could remove a disposable **unsigned template** by ID. That result does not establish a safe way to identify or remove a signed certificate. Neither session removed the live TLS certificate.

**Verification.** The owner independently observed the restricted account at the allowed control IP. A forbidden group creation failed under the restricted account and succeeded as owner. Private checks inspected router log/history and host VM diagnostics for both generated canaries. No credential is included in the evidence. `make test` and `go vet -tags lab ./spike/m3/...` passed. An independent review checked exact-ID controls, listener evidence, error classifications, privacy, and the same-socket witness. Earlier fixture-only errors (mount syntax, field name for imported architecture, and conntrack observation timing) were corrected and are excluded from the results.

The final serial runs took 54.80 s on 7.23.8 and 63.77 s on 7.25. All 66 public verdicts and reasons matched. Both tests exited 1 at the capability gate. The final host check found no remaining lab QEMU process, namespace or interface.

### Proposed changes after the spike (superseded by the owner's decision below)

The following is a proposal, not an approved change to the design.

1. Treat the router's API-SSL certificate as an **owner-managed prerequisite**. Reuse and pin a suitable existing certificate. Otherwise stop before router changes and show the owner how to provide one. Never adopt/delete a certificate by name or fingerprint alone. Trade-off: a router without a suitable certificate needs one manual setup step.
2. Keep the control account at exactly `read,write,api`. Let the local, owner-run `uninstall.rsc` remove the tagged user and group by verified ID, along with their tagged dependencies, even with both containers down. Trade-off: a complete uninstall requires an owner session; the daemon cannot perform it remotely with its own account.
3. Treat native object notifications as hints wherever measured. Use startup/settings-change reads and a periodic route check (propose 30 s) for route drift; read conntrack directly on policy changes and verify targeted invalidations. Keep closed traffic protected independently during the route polling interval and test deletion of an essential route with a WAN-side leak witness. Trade-off: some externally induced drift is detected on the next check and the router incurs the periodic reads. The experiments do not establish that RouterOS can never emit these events.

Task 1 stayed stopped at `ffe363b` pending the owner's decision.

### Owner decision — Task 1 authorized

Ruling: Preserve the one-paste installer and create a self-signed API-SSL certificate when no suitable certificate exists, tracking only an installer-created certificate in a separate `tikray:`-tagged, non-executable receipt — RouterOS certificates cannot carry the ownership comment, and the owner rejected a manual certificate prerequisite — cost if wrong: a missing, corrupt or mismatched receipt requires owner intervention before teardown.

The certificate receipt records the created certificate's name and exact SHA-256 fingerprint and the original API-SSL enabled state, certificate setting and address list. A second import preserves the receipt. A suitable pre-existing certificate is reused and pinned, never listed as owned in the certificate receipt, and never deleted. Uninstall preflights the receipt and reference safety before dismantling anything, restores the original API-SSL settings, verifies the service no longer uses the certificate, rechecks its fingerprint, and only then deletes the certificate. Any mismatch or unsafe reference follows `shared_reference_refuses`. Required tests cover preserved receipt on reimport, a same-name replacement with another fingerprint, and exact restoration of the original API-SSL settings.

Ruling: The local owner-run `uninstall.rsc` removes the tagged user and group by verified ID while the control account retains exactly `read,write,api` — the owner approved this privilege boundary after both CHRs denied those removals to the restricted account — cost if wrong: full uninstall needs an owner session.

Ruling: Reconcile routes every 30 s and on changes using router-side filters, and query conntrack only for affected client addresses — route and conntrack notifications remain unproven, and the owner forbids full-table reads for every periodic or on-change pass — cost if wrong: external drift can wait up to one polling interval and each filtered read consumes router work.

Only tikray's own routing tables and `tikray:`-tagged routes may be read in those passes. Connection invalidation reads select the affected client addresses on the router before results are returned. Filtering a downloaded full table in Go does not satisfy this rule. Closed traffic keeps an independent protection while routes are stale. The CHR WAN-side leak witness must demonstrate this throughout the polling window.

These decisions open Task 1. M3b still waits for the owner-approved M3a merge.
