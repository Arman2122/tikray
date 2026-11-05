# M3 execution ledger

The [amended M3 plan](../../superpowers/plans/2026-11-06-m3-routeros.md) starts from main at `d9050d7`. The original review draft is `4744887`. M3a is on `m3-routeros`. M3b starts only after the owner approves merging M3a and its merge is on main.

## Owner amendments

Ruling: Gate Task 1 on a throwaway, four-part capability spike on real CHR 7.23.8 and 7.25 x86_64 — binary hashing, least privilege and notifications, comment ownership and netwatch behavior must be demonstrated before building against them — cost if wrong: a failed assumption needs a design trade-off and owner approval before Task 1.

Ruling: Deliver M3a and M3b in separate PRs, each with its own matrix, final review and owner merge approval — ship the installer, reconciler, basic watchdog and uninstall together before adding geo, image updates, outage/watchdog coverage and CHR CI — cost if wrong: two reviews, two evidence builds and a wait for M3a to merge.

Ruling: Test and document one router-local emergency off command in M3a's routing suite — the owner needs normal LAN routing even with both containers down, and the next reconcile must restore the desired protections — cost if wrong: a deliberately suspended kill switch permits ordinary WAN egress until reconciliation.

Ruling: Keep DHCP lease discovery read-only in M3 and defer reservation creation to M4 — the UI milestone owns that mutation — cost if wrong: owners create reservations themselves until M4.
