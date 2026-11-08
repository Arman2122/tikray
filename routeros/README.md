# Installing on RouterOS

The [M3 ledger](../docs/handoff/m3/ledger.md) records installer validation against the pinned RouterOS releases and the signing identity used for the lab artifacts.

Build an installer for the router's installed version and CPU from an authenticated image pair. The packager uses `cosign verify-blob` with an independently obtained publisher public key. Supply the Docker-save images and detached signatures in one directory, for example `tikray-arm64.tar`, `tikray-arm64.tar.sig`, `tikray-runner-arm64.tar` and `tikray-runner-arm64.tar.sig`.

```sh
go run ./cmd/tikray-installer -version 7.25 -arch arm64 \
  -images ./release-images -key ./publisher.pub -out ./install.rsc
```

Use `-arch amd64` for x86_64 CHR. Supported releases are 7.25 and 7.23.8. The generated script contains the expected archive lengths and the SHA-512 digest of each ordered 16 KiB chunk. Obtain the generated installer through a trusted channel. A party that can change the installer could also change its digests. The repository's `routeros/install.rsc` is the packaging source.

For a one-paste deployment, package with `-release-base https://<your-release-host>/<release-directory>`, publish that installer and both archives, substitute the real installer URL below, and paste into the owner's router terminal. Configure RouterOS HTTPS trust for that host first. Use a new local download filename on the first import.

Choose a public HTTPS origin that serves each file in its first response, such as a static release directory on GitHub Pages. GitHub's `/releases/download` and `/releases/latest/download` endpoints redirect to signed URLs. The packager rejects those bases. RouterOS can record a server's `Location` header even when the client refuses to follow it, so keep credentials out of both the original URLs and the server's responses.

The router downloads to a name unique to the current installer lease. It verifies the staged bytes and publishes the archive by ID before container import. A killed import can leave an `images/incoming-<nonce>-…tar` fragment. A later import uses a fresh name and preserves the old fragment for owner inspection. RouterOS streams the response to disk before its final length can be checked. Use an origin you trust to serve the expected archive size, or stage the already verified images offline when the data volume is tight.

```routeros
{ :local download [/tool/fetch url="https://<your-release-host>/<release-directory>/install.rsc" check-certificate=yes http-max-redirect-count=0 dst-path=tikray-install.rsc as-value]; :if (($download->"status") != "finished") do={ :error "Installer download failed" }; /import file-name=tikray-install.rsc }
```

For an offline install, upload the generated installer and the two matching archives with Winbox or WebFig. The default archive location is `disk1/tikray/images/`. For the xray core, choose an exact version, stage its architecture-specific upstream zip with the signed `index.json` and `index.json.sig` in `disk1/tikray/data/inbox/`, and put its independently trusted ECDSA P-256 (PKIX PEM) index public key at `disk1/tikray/data/state/index.pub`. Use the index public key format required by `tikray core update`. The xray index key and the image publisher key serve separate purposes.

```routeros
:global tikrayCore "26.10.31"; :global tikrayOffline true; /import file-name=tikray-install.rsc
```

The installer defaults to the mounted ext4 volume `disk1`, directory `tikray`, bridge subnet `172.31.255.0/29`, existing interface lists `LAN` and `WAN`, and online core version `latest`. Override non-secret values in the same owner session before import using `tikrayDisk`, `tikrayDir` (the name `tikray` or a `tikray-…` directory), `tikraySubnet`, `tikrayLanList`, `tikrayWanList`, `tikrayCore` and `tikrayOffline`. The LAN list must describe the complete client population on each selected ingress. The chosen WAN list must include the active default's verified outgoing interface. A route or local address overlapping the bridge must be resolved before installation.

Install the matching RouterOS container package, provide a compatible container temporary directory on the selected disk, and enable router DNS for the LAN. If device-mode requires physical confirmation, follow the terminal prompt and repeat the import after reboot. The installer preserves the disk layout, registry and existing firewall rules. It refuses a foreign mount or port that could expose the control volume or private bridge.

At completion the installer prints the LAN-accessible HTTPS URL and control certificate SHA-256 fingerprint. The setup code is available through `tikray setup-code` in the control container's private terminal. For interactive first setup on RouterOS versions that support shell commands, the owner can explicitly set `tikrayShowSetup=true` before import. Leave it unset for unattended installation. After a core bootstrap failure, correct the missing signed input or connectivity problem and rerun the same installer. A mismatched ownership receipt or changed API-SSL certificate requires owner inspection before retry.

During a verified import, an inert `tikray-install-lock` script identifies that import's temporary RouterOS job. A competing import refuses before changing the installation. Completion or a handled failure releases the claim immediately. If the owner session is killed, retry when the keeper has ended (at most 30 minutes), or after the router has rebooted. A missing or mismatched certificate proof requires inspection. The installer cannot adopt a certificate by name after an interruption between signing it and saving its fingerprint.

## RouterOS emergency off

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

The release template includes this script. The watchdog checks for the emergency marker and job before acting on a container.

## Basic watchdog

On the private bridge, static ARP entries map control and runner addresses to their container-side MACs. Static bridge host entries map those MACs to the two owned veth ports. The bridge uses reply-only ARP. Both ports have MAC learning and unknown-unicast flooding disabled so a stopped or recreated control port cannot send health traffic to the runner. These settings apply only to the tagged tikray bridge and ports.

The `tikray-watchdog` scheduler runs every minute. It fetches `/healthz` over transport-only HTTPS at the bound control address and checks both `ok: true` and the public installation ID from its receipt. The runner gateway has a separate ping check. Management clients continue to verify the UI certificate. Three consecutive misses allow a restart of that component. Further attempts are spaced 1, 2, 4, 8 and then 15 minutes apart. A successful probe clears that component's failure state.

The tagged, non-executable `tikray-watchdog-state` script holds the public installation ID, failure counts and restart times. Healthy steady checks cause no state writes. Restart decisions require an exact container name, interface and ownership tag. The watchdog waits for the first committed core and yields during an active installer, emergency shutdown or uninstall.

## Removing an installation

Generate the self-contained uninstaller from the reviewed sources. It can be
generated separately from the signed image pair.

```sh
go run ./cmd/tikray-installer -uninstall-out uninstall.rsc
```

Upload the generated file and import it from the owner's RouterOS terminal.
Choose **keep** to retain the configured servers, local admin, TLS identity
and installed core slots.

```routeros
:global tikrayUninstallData "keep"; /import file-name=uninstall.rsc
```

To delete the validated installation's `/data` instead, explicitly select
`purge` before import. An empty or unattended choice defaults to **keep**.
Both choices remove the owned containers, account, routes, firewall rules,
ARP/FDB bindings and private bridge. Restoring API-SSL uses the installer
receipt and verifies the original grants. A replacement certificate, owner
dependency or mismatched data identity stops teardown for inspection.

The inert `tikray-api-mode` record identifies whether the installer created
a certificate, added a service grant, or left API-SSL unchanged. The
uninstaller checks this independently of the receipt. If a changed service
has lost its receipt, restore the original proof before retrying. Neither
installation nor removal infers an unchanged service from a missing record.

A repeated import resumes the data choice in the pending uninstall marker.
A clean second import reports that the installation has already been
removed. Image archives outside `/data` remain available for reuse.
If the original data identity has already gone during an interrupted purge,
the uninstaller preserves unverified empty directories at that path.

A successful keep prints the previous **public installation ID**. To
reinstall on that retained volume, select the same disk, directory and
subnet and set the printed ID before importing the packaged installer.

```routeros
:global tikrayReuseID "<previous-public-installation-id>"; /import file-name=install.rsc
```

The new installation receives fresh RouterOS credentials and an installation
ID. The kept user state and control-plane TLS identity remain on the volume.

## Control container handoff

On a managed installation the daemon generates a public installation ID once under its service lock. The private intent in `state/install.request` retains it and `state/install.id` exposes the same value to the owner installer. Reimport checks it against the ID in the watchdog receipt. Keep the original control volume together when restoring a backup.

The installer writes `/data/state/routeros.json` atomically with mode `0600` under the control container's private `0700` state directory. Version 1 requires `version`, `address` (router bridge IP and API-SSL port), `username` (`tikray`), `password`, the pinned SHA-256 certificate `fingerprint`, and `scope`. The scope contains `subnet`, `lan_list`, `lans` (interface, IPv4 prefix and optional dedicated flag), the install-time `wan` interface and optional `local_lans`. Keep this file on the control volume.

Each pass reads the active IPv4 main defaults with all three filters on the router and uses the resolved interface and gateway to verify the open fallback. An ambiguous or unverifiable path leaves reconciliation pending. The last verified policy and any outstanding guards are recorded in `/data/state/router-policy.json`. Restore these private state files together from the same installation.
