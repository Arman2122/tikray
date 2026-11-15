# Container image releases

An owner packages the initial installer with a pinned ECDSA P-256 public key in PKIX PEM format. The packager runs cosign's detached blob verification for both Docker-save archives and binds the same public key into the delivered `install.rsc`. Obtain the public key and installer through an authenticated channel. The private signing key stays with the publisher.

## Publisher files

Build each named release for both target architectures with the same explicit `TIKRAY_IMAGE_VERSION`. For example:

```sh
TIKRAY_IMAGE_VERSION=v1.2.3 scripts/build-images.sh amd64 out/v1.2.3
TIKRAY_IMAGE_VERSION=v1.2.3 scripts/build-images.sh arm64 out/v1.2.3
```

Sign each exact saved archive with the publisher's pinned key, for example:

```sh
cosign sign-blob --key cosign.key --output-signature out/v1.2.3/tikray-amd64.tar.sig out/v1.2.3/tikray-amd64.tar
```

Publish the four archives (`tikray-amd64.tar`, `tikray-runner-amd64.tar`, `tikray-arm64.tar`, `tikray-runner-arm64.tar`) and their base64 detached `.tar.sig` files in the release directory. Each tar is limited to 128 MiB. The control image verifies the cosign P-256 ASN.1 signature over the SHA-256 digest of the complete file, its Docker config digest, OS/architecture, repository tag and executable role. A named release must have that exact signed `org.opencontainers.image.version` config label. The run-time verifier needs no registry credentials, transparency-log service or cosign executable.

A release name starts with an ASCII letter or digit, uses at most 64 letters, digits, dots, dashes or underscores, and must not contain `..`. `latest` is reserved for release discovery. Without an explicit label the build script uses the Git commit if available. A content selector `sha256-<64 lowercase hex digits>` binds the exact signed tar instead of a version label; this also permits an authenticated older build.

## Fetch and offline layout

`TIKRAY_IMAGE_UPSTREAM` sets the HTTPS publisher directory. With a selector such as `v1.2.3`, tikray reads `<upstream>/v1.2.3/tikray-amd64.tar` and its detached signature. The optional `<upstream>/latest` contains a single public release name for notification. `TIKRAY_IMAGE_MIRRORS` contains comma-separated HTTPS templates, with `{file}` and optional `{version}` and `{arch}`. Each verified file may come directly from the publisher, through a healthy proxy, via a mirror, or from the inbox. The pinned signature and release selector apply on every path.

For offline staging, place the two matching files for the requested component and architecture in `/data/inbox/images/<selector>/` on the control data volume. For example, update the runner from `/data/inbox/images/v1.2.3/tikray-runner-amd64.tar` and its `.sig`. Use the normal authenticated update command. A missing publisher URL leaves the inbox available; an unknown key or mismatched signature refuses the operation.

## Owner configuration on RouterOS

On an installed router, put the following JSON in `/data/state/image-source.json` on the control volume. Use a regular file with permissions `0600` in the private state directory, then restart the control container to load it. Use a publisher you trust and the signing key already pinned by the installer.

```json
{
  "version": 1,
  "upstream": "https://publisher.example/releases",
  "control_mode": "notify",
  "runner_mode": "manual",
  "runner_window": "02:00-03:00"
}
```

The optional `mirrors` array contains HTTPS templates. Each component accepts `manual`, `notify` (the default), or `auto`. Manual mode makes no automatic release checks. Notify records availability in events. Auto explicitly authorizes replacement. The optional `control_window` and `runner_window` use 24-hour UTC times and may cross midnight. Without a window, checks are at least 24 hours apart. With a window, the service attempts once per window when running. A malformed private file leaves policy service running and previously verified rollback available. Publisher settings cannot change the pinned key.

## Updating and checking the result

Run these commands with the authenticated tikray CLI:

```sh
tikray image status tikray
tikray image update tikray v1.2.3
tikray image status tikray
tikray image update runner v1.2.3
tikray image status runner
tikray image rollback runner
```

Wait for one operation to settle before requesting the next. An accepted update or rollback returns the operation ID and the source and target archive digests. The corresponding HTTP mutations return 202. Poll the component's status until `pending` disappears, then check `active` against the requested digest. A successful change reports the replaced image under `previous`. A rejected candidate leaves the original image active once the watchdog verifies its recovery. The control API is unavailable while its own container restarts. The runner may keep forwarding throughout a control replacement. A runner replacement interrupts proxied connections. When a control update migrates the state format, the older release reads its preserved state file on rollback. Changes saved only in the newer state file will no longer be active.

During preparation for a runner change, new fail-open connections can start using the owner's WAN and DNS before the old container stops. The watchdog moves existing flows in batches, checking only the affected client addresses. Many managed prefixes can take several one-minute ticks. Closed traffic remains protected. The five-minute health window starts when replacement begins, after preparation. A control update leaves the runner assigned to its existing traffic.

## Initial rollback material

The installer verifies the original pair under the installation's `images/` directory for container import. It then checks the exact tagged live container config IDs and copies the verified tars by native file ID into the separate, control-only `data/images/` directory. It binds the two current-image receipts to the installation ID and writes the publisher bootstrap record last. A missing receipt on an established installation stops reimport for inspection. Retain the original installation archives for reimport.

## First upgrade from M3a

The M3a control binary predates the image API. For the first upgrade, schedule a maintenance interval for both containers. The keep-and-reinstall procedure returns the LAN to the owner's routing during the gap, including devices normally assigned to the kill switch.

1. Obtain the new signed installer and both matching image archives through the authenticated release channel. Have the original M3a packaged uninstaller available and note the installed disk, directory and subnet.
2. Run the original uninstaller with its default **keep** choice. Save the public installation ID printed on success.
3. Stage the new matching pair at the installer's archive paths and upload its `install.rsc`. Select the same disk, directory and subnet. Set the retained public installation ID immediately before the import:

   ```routeros
   :global tikrayReuseID "<previous-public-installation-id>"; /import file-name=install.rsc
   ```

4. Check the reported TLS fingerprint, sign in with the existing owner account, and check `tikray image status tikray` and `tikray image status runner`. Both active digests should match the new delivered archives. Keep preserves the desired policy, xray selection and management TLS identity. Reinstall establishes a new installation ID and fresh RouterOS credentials.

Subsequent releases can use the component update commands above.
