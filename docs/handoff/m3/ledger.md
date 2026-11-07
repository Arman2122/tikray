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

## Task 1 — native transport and version adapters

The approved receipt, owner-run teardown and router-filtered read plan was committed and pushed in `4fe9623`, after `make test`.

Ruling: Validate the installed release and platform on each authenticated native connection before exposing it to writers, and admit only the two measured releases for now — a reconnect can follow a RouterOS upgrade, and the adapter must not silently promise an unmeasured command shape — cost if wrong: another release needs adapter evidence before installation.

Ruling: Keep session framing/demultiplexing and read-only profile detection in `session.go` and `detect.go` beside `client.go`, and share adapter examples in `adapters/testdata/profiles.json` — concurrency ownership and detection are independently reviewable, and the later installer must consume the same selector cases — cost if wrong: two extra source files and one fixture.

Ruling: Return nonempty final native `!done` properties as the last `Command` row, accept complete router-filtered `Listen` sentences, and emit generation-labelled ready/disconnected changes — adds return their new ID in `ret`, while reconnect recovery must ask the caller for scoped state instead of downloading full tables or replaying mutations — cost if wrong: callers must observe generation changes before writing.

The initial client and codec tests failed to compile before implementation. A TLS peer then exercised pin-before-login, shared commands/listeners, targeted cancellation, login backoff and uncertain mutations. A valid 2,048-row reply failed before the command queue fix. The slow-callback overflow test reproduced a stale observation after failure before the generation checks were added. Independent review found and corrected the shutdown/install race, lost subscription on send failure, cumulative stream-row counting and small command queue.

The first real 7.23.8 transport check reached the adapter and refused the fixture. Its installed release is `7.23.8 (long-term)`, its independently configured update preference is `stable`, and its board label has a `CHR ` prefix followed by the QEMU machine description.

Ruling: Derive the installed release's channel from the exact verified release catalog and accept the read-only CHR board prefix with a validated hypervisor suffix — the upgrade preference does not identify the running release, and genuine CHR reports include the virtual machine description — cost if wrong: a newly formatted hardware label needs an adapter update. Raw hardware labels are not retained in a profile or public diagnostic.

Ruling: Treat filtered notifications as hints and re-read every owned collection with router-side filters at least every 30 s — a comment-filtered stream on real CHR delivered changed rows but did not deliver the deleted row's tombstone, so reliable deletion repair needs the spec's periodic check — cost if wrong: more filtered reads and up to one polling interval before repair. The independent closed-policy guard remains mandatory during that interval.

Ruling: Provide `CommandAt(ctx, generation, words)` for a reconciler plan bound to an observed connection — a separate generation check followed by an unbound command could cross a reconnect — cost if wrong: a stale plan must be rebuilt from scoped reads. The transport compares the selected session before any write and never switches it mid-command.

The final targeted unit/race suite passes. Regression coverage includes valid large replies, listener lifetimes beyond 32,768 events with drained queues, callback reentrancy and overflow, close versus replacement-session installation, partial mutation writes without replay, listener-send recovery, stale-generation refusal, and the unfiltered `getall` alias. The codec also passed 161,064 fuzz executions in its isolated test run. Private peer errors and connection configuration stay out of public diagnostics.

`TestM3NativeClient` passed on CHR 7.23.8 x86_64 and 7.25 x86_64 under QEMU TCG. On each it used the production client with the restricted account to detect and pin the router, add/read/change/remove a precisely filtered fixture, observe its changed row while excluding a separately changed foreign row, cancel only the subscription, and perform a subsequent read on generation 1. Both generated credential canaries passed the router/host privacy audits. Filtered tombstones remain an explicitly unproven signal and are not required by that positive observation test.

Task 1 implementation is committed and pushed as [`4e4d116`](https://github.com/Arman2122/tikray/commit/4e4d11655b504cb7f4d2979722d9a877e9b3831b). A fresh reviewer approved the final source and independently passed the routeros race suite and lab vet. `make test` passed before the commit. Task 4 must explicitly preflight the 7.23.8 memory/restart fields, which the adapter represents as unproven; that label does not mean the fields are absent. Task 3 must use `CommandAt` for mutation plans and scoped reads after every generation change.

Task 1 complete. The committed source was rerun serially with `TIKRAY_LAB_CHANNEL=7.23.8` and `7.25`, `TIKRAY_LAB_ARCH=x86_64`, and `go test -tags lab -p 1 -count=1 -v -timeout 14m -run '^TestM3NativeClient$' ./spike/m3/`, under bounded background wrappers. Both exited 0 (14.29 s and 25.98 s), with two private canary audits per run. The final source review was approved and the full repository gate passed again for this evidence update. No lab QEMU process, interface or namespace remained. Tasks 2–4, 6a, 7 and the remaining M3a acceptance work are pending.

## Task 2 — compile the policy and validate network inputs

Implementation and regression tests: [`fe3da80`](https://github.com/Arman2122/tikray/commit/fe3da80960aa388a252da9c6324986fc49bbdad0), pushed to `m3-routeros`. `Project` keeps the network, policies, device addresses/MACs and literal domestic IPv4 ranges. `Desired` compiles a snapshot to tagged objects, dependencies and placement constraints without router I/O. The first compiler tests were RED on the missing interfaces. Store tests reproduced admission of unsafe new overlaps, and HTTPS tests reproduced the missing recovery path.

Ruling: Compile the selected LANs into disjoint source CIDRs, excluding router IPs, subnet/broadcast addresses and explicit direct clients — mangle, DNS and egress filtering must agree on the same population, including with a proxy default — cost if wrong: several small prefixes may replace a single LAN prefix. The /8 test verifies coverage without expanding individual hosts. Explicit M2 device prefixes remain disjoint.

Ruling: Require the complete effective LAN-list membership and refuse an unsafe foreign interaction before activating steering; allow an all-direct target to request detachment without a live gateway — a custom list can include a guest or WAN, whereas returning to normal routing needs no new next hop — cost if wrong: an ambiguous topology needs correction before steering can resume. A verified on-link IPv4 gateway, including link-local, or a positively identified point-to-point interface can supply the single open fallback. The point-to-point representation is unit-tested; the CHR probe uses an IPv4 gateway.

Ruling: Keep distinct private/reserved destination entries but exclude the globally reachable 192.0.0.9 and 192.0.0.10 from the default local bypass — both anycast assignments belong inside an otherwise reserved /24 — cost if wrong: an external destination could bypass a closed policy. [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)

Ruling: Preserve observed owner routing marks with exact returns at the start of the private chain, after the router-local return — the CHR positive control saw ordinary prerouting traffic while `routing-mark=main` matched zero of those packets and the native API rejected the `no-mark` routing matcher — cost if wrong: a missed overlapping mark writer could capture an owner flow. Ambiguous, terminal or otherwise conflicting owners must be reported from scoped observations and refused.

Ruling: Derive one common packet mark only from owned connections carrying no prior packet mark, and require an independently sufficient, immediately following owner accept before inserting the FastTrack exception — RouterOS can send packets from an established flow through the ordinary filter path, where an early accept could bypass a later owner deny — cost if wrong: complex, logged or ambiguous FastTrack configurations may require adjustment. Reject collisions, overlapping QoS writers, terminal mangle rules and intersecting owner port forwards whose reply path the guard would block.

Ruling: Guard closed original-source traffic on every egress outside the tikray bridge, with local and smart-domestic exemptions; protect forwarded translated DNS before those exemptions — a missing route or an owner routing mark can select another interface, even with one main default — cost if wrong: a conflicting owner forwarding policy must be refused. Open DNS has a router redirect behind its primary rule for clients using a hardcoded resolver. Netwatch sets only the exact open primary bits that need changing, including when a row is recreated while the runner already answers ping.

Ruling: Link private-chain siblings and the leading DNS group to their next desired row, with the group tail anchored before the first effective row outside that group — blindly inserting a single missing DNS fallback at the head can permanently bypass a healthy primary — cost if wrong: additional scoped order observations during repair. The executor must allow newly inserted rules to become valid before declaring steering active.

Ruling: Admit previously loadable M2 network overlaps for inspection and expose a repair-only authenticated `PUT /v1/network` — M2 could save multiple offending prefixes while its device API edits one row at a time and runner endpoints bind at startup — cost if wrong: the owner must submit all necessary corrections in one revision and restart serve after bridge repair. The operation accepts a verified replacement subnet, explicit removals offending the old or replacement bridge/forbidden ranges and an optional `remote_dns` only for a conflict introduced by the new router resolver. The fully validated write preserves unrelated devices, servers, subscriptions and credentials. A repaired bridge carries a durable local-verification bit. Startup and offline runner operations check the assigned control address and prefix and an unambiguous direct kernel route to the runner. On failed verification the service remains available for HTTPS repair and withholds runner access.

Ruling: Private runner HTTP requests bypass environment proxies and refuse redirects before using a peer-supplied Location — an HTTP proxy or redirect can defeat a correct on-link route check and receive the runner bearer or configuration-test body — cost if wrong: an operator-configured intermediary cannot relay private runner control requests. This applies to ordinary calls, tests and caller-provided timeouts.

The policy matrix covers direct, smart and full defaults, open and closed overrides, router-local traffic, foreign marks, changed next hops and deterministic input order. IPv6 guard tests cover lease replacement, MAC/ingress ambiguity, direct exceptions, dedicated subnet policies, and aliases. The repair tests cover stale revisions, authentication, atomic rejection, credential preservation and refusal of an off-link runner. A fresh reviewer approved the final source after reproductions and fixes. Race tests passed in the seven affected packages, lab vet passed, and `make test` passed before the implementation commit.

**Task 3 carries.** Use the compiled `Before` links when recreating one missing row. Resolve first-in-chain anchors with dynamic FastTrack statistics rows accounted for. Verify the actual ingress, mark writers, owner rule adjacency and conflicts with filtered reads. Stage guards and dependencies before exposing a newly closed source. On an IPv6 policy/lease change, account for existing FastTracked IPv6 flows using scoped neighbor/conntrack evidence or refuse when protection cannot be proven.

**Task 2 complete.** The committed implementation `fe3da80` ran serially under QEMU TCG with `TIKRAY_LAB_ARCH=x86_64` and `TIKRAY_LAB_CHANNEL` pinned to each release. The bounded background command was `go test -tags lab -p 1 -count=1 -v -timeout 5m -run '^TestM3CompiledIPv4$' ./spike/m3/`. The actual compiled IPv4 and IPv6 rows were accepted on both routers. With a positive WAN traffic control, each run observed the closed source/route marks, a closed flow blocked after both routes were removed, preserved foreign routing marks, a misrouted translated DNS packet blocked, stable FastTrack placement, and open DNS primary/fallback counters changing on fresh transactions as netwatch went up/down. The runner ping endpoint was simulated. Resolver answers, full xray traffic and packet-level IPv6 coverage belong to the M3a acceptance suite.

| CHR x86_64 | Result | Ordinary prerouting / explicit-main control hits | Private diagnostic audit |
|---|---|---|---|
| 7.23.8 | PASS, 42.18 s | 3 / 0 | PASS |
| 7.25 | PASS, 43.46 s | 3 / 0 | PASS |

Both wrappers exited 0. No lab QEMU process, interface or namespace remained. Task 3 is next.

## Task 3 — Scoped reconciliation and emergency off

Ruling: Allow one read of active IPv4 main-table defaults in each topology snapshot, approved by the owner — both tested CHRs denied `/ip/route/check` to the control account, and neither an on-link address nor a successful lookup proves the active default is unique — cost if wrong: a stale or ambiguous gateway could misroute open clients. The read requires `routing-table=main`, `dst-address=0.0.0.0/0` and `active=true` on the router and requests only `gateway,immediate-gw,ecmp`. Follow a verified change of gateway or interface. Reject multipath and unverifiable recursion before steering writes. The exception grants no main-table write.

Ruling: Journal resolved policy selectors and the last verified public policy projection in a private atomic checkpoint — the state write, runner commit, router writes and removal of old connections can each fail independently — cost if wrong: an interrupted transition can leave a client blocked until proof is available. Stage only the affected guards before accepting a change. Read back guards after invalidation, invalidate stale proofs before a repair write, recheck the committed runner selection during release, and restore protection on a failed release. On a rejected new client, recover any independently damaged protection already owed to an existing client.

Ruling: Separate transient guard and flow invalidation scope by client, transport and destination where the live policy permits it — a missing TCP DNS rule or changed domestic prefix cannot justify interrupting all of a client's traffic — cost if wrong: stale bindings could persist or a healthy flow could reset. Compare original and reply tuples immediately before removing a verified ID. An exact source or numeric range is always present on RouterOS. Preserve router management and distinguish owner mark writers and DNS translations before removing a binding.

Ruling: Refuse new IPv6 tightening if prior FastTracked sources cannot be identified safely, and re-arm already accepted protection before reporting that condition — an expired neighbor entry cannot enumerate every former privacy address, while a full-table connection read violates the owner's scope — cost if wrong: some configurations with historical IPv6 FastTrack need owner intervention before a new closed policy can be acknowledged. Status reports `ipv6_fasttrack_scope` without peer diagnostics.

Ruling: Keep the emergency-off marker inert and durable, and verify affected bindings again after the owned hooks are disabled — traffic may arrive while a watchdog job finishes, or a local off command can be interrupted after disabling a rule — cost if wrong: a dormant proxy binding can survive an apparently successful off command, or an owner's independent DNS redirect can be cleared. Preserve equivalent owner translations. The next verified reconcile re-arms policy and clears the marker.

Ruling: Bound each native call and a competing policy edit's lock wait independently, and honor the caller's deadline for a progressing change — building then verifying one guarded client already took over 20 s on emulated CHR, and restarting the release of a large set of guards at a fixed interval could prevent convergence — cost if wrong: a slow configuration change can hold the policy writer longer. Status and HTTPS discovery use separate bounded reads, and the service retains its 30 s sweep.

Ruling: Keep policy-row operations in `Plan` and compute scoped conntrack invalidations from the transition journal at execution time — concrete connection IDs and their tuples must be observed under the installed guards, and must be observed again after a lost acknowledgement — cost if wrong: an old binding could survive or an unrelated replacement could be reset. `Reconcile` returns operation counts and a fixed error category. The service represents that category in its public status.

Ruling: Require the running service for managed apply, rollback and core-update operations — the standalone updater cannot stage or recover router guards around a runner trial — cost if wrong: recovery after loss of the control process requires restarting `serve`. The owner-side emergency command remains available on the router. Missing installation credentials alongside an existing policy journal fail safely.
