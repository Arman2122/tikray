# M3 execution ledger

The [amended M3 plan](../../superpowers/plans/2026-11-06-m3-routeros.md) starts from main at `d9050d7`. The original review draft is `4744887`. M3a is on `m3-routeros`. M3b starts only after the owner approves merging M3a and its merge is on main.

## Owner amendments

Ruling: Gate Task 1 on a throwaway, four-part capability spike on real CHR 7.23.8 and 7.25 x86_64 — binary hashing, least privilege and notifications, comment ownership and netwatch behavior must be demonstrated before building against them — cost if wrong: a failed assumption needs a design trade-off and owner approval before Task 1.

Ruling: Deliver M3a and M3b in separate PRs, each with its own matrix, final review and owner merge approval — ship the installer, reconciler, basic watchdog and uninstall together before adding geo, image updates, outage/watchdog coverage and CHR CI — cost if wrong: two reviews, two evidence builds and a wait for M3a to merge.

Ruling: Test and document one router-local emergency off command in M3a's routing suite — the owner needs normal LAN routing even with both containers down, and the next reconcile must restore the desired protections — cost if wrong: a deliberately suspended kill switch permits ordinary WAN egress until reconciliation.

Ruling: Keep DHCP lease discovery read-only in M3 and defer reservation creation to M4 — the UI milestone owns that mutation — cost if wrong: owners create reservations themselves until M4.

## Task 0 — disposable CHR capability gate

The amendments and four rulings were pushed in `53976c5` after a passing `make test`. Task 0 uses cached x86_64 CHR ready images under QEMU TCG in WSL2, a separate copy-on-write overlay per run, and an ephemeral account restricted to the simulated control IP (.2). The real group policy readback was exactly `read,write,api`. No product code or live router is involved.

Both owners could create and sign the API-SSL certificate and establish the pinned connection. On **both 7.23.8 and 7.25**, the owner API refused a certificate template with `comment=tikray:…`, accepted the identical template without the comment, and refused to set a comment on the existing signed certificate. This disproves C for the installer-created certificate. The preflight fixture initially mistook RouterOS's explicit denied rights (such as `!policy`) for grants. It was corrected to compare only the positive grants and rerun.
