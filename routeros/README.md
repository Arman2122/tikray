# RouterOS emergency off

Run this command in the router terminal as the owner. It works with both tikray containers stopped.

```routeros
/system/script/run tikray-emergency-off
```

This command deliberately suspends **all tikray kill switches**. A formerly closed client can send traffic directly through the router, use its configured DNS resolver and use IPv6 under the owner's normal firewall rules. Existing client connections may need to reconnect.

The command disables the owned runner netwatch, the IPv4 steering and egress hooks, the managed DNS redirects and the IPv6 and temporary guard entry points. Before detaching the policy, it records affected connection IDs and their original and reply tuples. After detachment it also checks for connections marked or translated to the runner while the watchdog was stopping. It removes matching bindings by ID, preserves equivalent owner DNS redirects, and verifies removal using the original client source. If a complex owner DNS rule could have produced the same translation, the command preserves that binding until it expires. New DNS transactions follow the remaining owner rules. The bridge isolation rules, owner firewall, router management access and unrelated client connections stay in place.

Run the command again if the router reports a busy watchdog, or after resolving an ownership conflict. A conflicting name, tag or selector requires inspection in the router terminal. The inert `tikray-emergency-state` script records the suspension across reboot. Leave it in place for recovery.

When both services return, the control plane rechecks the router, stages the required protections, invalidates affected stale flows and verifies the desired policy. The verified re-arm clears the suspension marker automatically. A failed re-arm keeps the marker for retry.

For a development installation, upload the repository's `emergency-off.rsc` file to the router and install the owner command with the following import. Subsequent imports reuse the tagged command.

```routeros
/import file-name=emergency-off.rsc
```

The production installer must include this script block. Its watchdog must check for `tikray-emergency-state` and an active `tikray-emergency-off` job at entry and immediately before any container restart.

## Control container handoff

The installer writes `/data/state/routeros.json` atomically with mode `0600` under the control container's private `0700` state directory. Version 1 requires `version`, `address` (router bridge IP and API-SSL port), `username` (`tikray`), `password`, the pinned SHA-256 certificate `fingerprint`, and `scope`. The scope contains `subnet`, `lan_list`, `lans` (interface, IPv4 prefix and optional dedicated flag), the install-time `wan` interface and optional `local_lans`. Keep this file on the control volume.

Each pass reads the active IPv4 main defaults with all three filters on the router and uses the resolved interface and gateway to verify the open fallback. An ambiguous or unverifiable path leaves reconciliation pending. The last verified policy and any outstanding guards are recorded in `/data/state/router-policy.json`. Restore these private state files together from the same installation.
