# Installation Guide

This guide walks through installing **tikray** on a MikroTik RouterOS v7 router from scratch, covering RouterOS prerequisites, storage setup, packaging or downloading a verified installer, first-run admin setup, and post-install checks.

> Deploying without direct internet access on the router? Jump to [Offline & Censored Networks](Offline-and-Censored-Networks.md) after completing **Step 1 (Prerequisites)**.

---

## 1. Prerequisites on MikroTik RouterOS

### Supported RouterOS Versions
- **Lab-verified:** `7.25.1` (`7.25.x` stable), `7.24.6` (`7.24.x` long-term), and `7.23.8` (`7.23.x`).
- **Forward-compatible:** Canonical `7.26+` stable/long-term releases (surfaced with a non-blocking `untested` badge until verified in CHR CI).
- **Refused:** RouterOS v6, pre-`7.23.8`, `.0` patches, and `beta` / `rc` / `testing` / `development` channels.

### Required RouterOS Setup

1. **Install the matching `container` extra package**
   - Download the MikroTik `extra-packages` archive matching your exact RouterOS version and architecture (`arm64` or `x86`), upload `container-<version>-<arch>.npk` to the router root, and run `/system/reboot`.
2. **Enable container support in `device-mode`**
   ```routeros
   /system/device-mode/update container=yes
   ```
   Follow the terminal prompt (press the physical reset/mode button or power-cycle within the timeout on hardware routers; CHR applies on reboot).
3. **Prepare ext4 storage (`disk1`)**
   - Use an ext4-formatted USB 3.0 drive, NVMe drive, or dedicated ext4 partition (at least **512 MB** free; **2 GB+** recommended for core/geo/image rollback slots).
   - Verify the mounted disk name in RouterOS:
     ```routeros
     /disk/print
     ```
   - Configure a container temporary directory on that disk (avoid router internal flash):
     ```routeros
     /container/config/set tmpdir=disk1/tmp
     ```
4. **Verify LAN & WAN Interface Lists + Router DNS**
   - Ensure your router has existing `/interface/list` entries for `LAN` and `WAN` (or note your custom list names to pass via `tikrayLanList` and `tikrayWanList`).
   - Ensure the `LAN` list covers the full client population on each managed ingress interface, and `WAN` includes the active default route's outgoing interface.
   - Enable router DNS for LAN clients:
     ```routeros
     /ip/dns/set allow-remote-requests=yes
     ```
   - Make sure no existing route or local address overlaps the private container bridge subnet (`172.31.255.0/29` by default; customizable via `tikraySubnet`).

---

## 2. Fast Install Directly on MikroTik (Recommended — No Go Required)

Every GitHub Release ships signed multi-arch container archives (`tikray-{arm64,amd64}.tar`, `tikray-runner-{arm64,amd64}.tar`), Cosign signatures (`*.tar.sig` + `publisher.pub`), pre-packaged installers (`install-7.25.1-{arm64,amd64}.rsc`, `install-7.24.6-{arm64,amd64}.rsc`, `install-7.23.8-{arm64,amd64}.rsc`), `uninstall.rsc`, and an auto-detecting `bootstrap.rsc`.

Open **WinBox → New Terminal** (or SSH to your router) and paste:

```routeros
/tool/fetch url="https://github.com/Arman2122/tikray/releases/latest/download/bootstrap.rsc" dst-path="tikray-bootstrap.rsc"
/import file-name="tikray-bootstrap.rsc"
```

`tikray-bootstrap.rsc` checks your architecture, RouterOS release line, `container` package, `device-mode`, ext4 disk, and router DNS before downloading the matching `.tar` archives and verified `install-*.rsc` directly onto your ext4 disk (`disk1`), then runs `/import`. The packaged installer verifies every **16 KiB SHA-512 chunk** before importing containers.

> **Using a custom disk, subnet, or interface lists?** Set the optional globals in the same terminal before `/import file-name="tikray-bootstrap.rsc"`:
> ```routeros
> :global tikrayDisk "usb1"
> :global tikraySubnet "172.31.254.0/29"
> :global tikrayLanList "HOME-LAN"
> :global tikrayWanList "ISP-WAN"
> /import file-name="tikray-bootstrap.rsc"
> ```
> If you have imported Mozilla root CA certificates into RouterOS, also set `:global tikrayCheckCert true` (and add `check-certificate=yes` to the `/tool/fetch` line) to enforce TLS CA verification during bootstrap.

### Manual Download or Packaging (Advanced / Custom Mirror / RouterOS 7.26+)

- **Manual WinBox / WebFig Upload (Zero Go):** Download `install-<line>-<arch>.rsc`, `tikray-<arch>.tar`, `tikray-runner-<arch>.tar`, and `SHA256SUMS` from [GitHub Releases](https://github.com/Arman2122/tikray/releases/latest), verify checksums locally, upload the `.tar` files to `disk1/tikray/images/` and the installer to `disk1/tikray-install.rsc`, then run `/import file-name="disk1/tikray-install.rsc"`.
- **Package Your Own Installer with Go:** Place `tikray-<arch>.tar`, `tikray-<arch>.tar.sig`, `tikray-runner-<arch>.tar`, and `tikray-runner-<arch>.tar.sig` in `./release-images`, obtain `publisher.pub` out-of-band, and run:

```sh
go run ./cmd/tikray-installer \
  -version 7.25.1 \
  -arch arm64 \
  -images ./release-images \
  -key ./publisher.pub \
  -out ./install.rsc
```

- Use `-arch amd64` for x86_64 CHR.
- For self-hosted one-paste deployment, pass `-release-base https://<your-release-host>/<release-dir>` pointing to a **non-redirecting HTTPS static host** (such as GitHub Pages or your own static HTTPS server).
  > **Why doesn't `install.rsc` fetch from `github.com/.../releases/download` directly?** GitHub's release download URLs return HTTP 302 redirects to signed object-storage URLs. Because RouterOS can log redirect `Location` headers and `install.rsc` itself enforces `http-max-redirect-count=0`, `bootstrap.rsc` stages the archives into `disk1/tikray/images/` first and hands off to the unmodified, chunk-verified `install-<line>-<arch>.rsc`.

---

## 3. Installer Options & What It Provisions

### Customizing Non-Secret Installer Defaults

Override any of these global variables in the **same terminal session** before `/import file-name="tikray-bootstrap.rsc"` (or `/import file-name="disk1/tikray-install.rsc"`):

| Variable | Default | Purpose |
|---|---|---|
| `tikrayDisk` | `"disk1"` | Mounted ext4 volume name |
| `tikrayDir` | `"tikray"` | Base directory on disk (`tikray` or `tikray-…`) |
| `tikraySubnet` | `"172.31.255.0/29"` | Dedicated private `/29` bridge subnet |
| `tikrayLanList` | `"LAN"` | Existing RouterOS interface list for LAN clients |
| `tikrayWanList` | `"WAN"` | Existing RouterOS interface list containing active WAN |
| `tikrayCore` | `"latest"` | Initial `xray-core` version to bootstrap (e.g. `"26.11.9"`) |
| `tikrayOffline` | `false` | Set `true` for air-gapped installation from staged disk files |
| `tikrayShowSetup` | `false` | Optional interactive mode to print setup code at install end |
| `tikrayReuseID` | `""` | Previous public installation ID when reinstalling onto kept `/data` |
| `tikrayCheckCert` | `false` | Bootstrap only: pass `check-certificate=yes` to `/tool/fetch` |
| `tikrayBaseURL` | release tag URL | Bootstrap only: override HTTPS mirror URL for release assets |

### What the Installer Provisions Safely
- Dedicated private bridge `tikray` (`protocol-mode=none`, `arp=reply-only`, static ARP/FDB bindings, disabled MAC learning & unknown-unicast flooding).
- Scoped `tikray` RouterOS API-SSL account + certificate pinning receipt in `/data/state/routeros.json`.
- Both containers (`tikray` tagged `tikray:tikray` and `tikray-runner` tagged `tikray:runner`) mounted to `/data` on your ext4 volume.
- Native `tikray-watchdog` scheduler (1-minute health checks with exponential backoff) and `tikray-emergency-off` script.
- Return-traffic isolation rules above FastTrack and permissive owner rules.
- Preserves your existing RouterOS firewall, NAT, registry, and disk layout (refuses conflicting mounts or ports).

---

## 4. First-Run Setup & Certificate Verification

At completion, the installer prints:
1. Your LAN HTTPS URL (for example `https://172.31.255.2/`).
2. The control plane's **self-signed TLS certificate SHA-256 fingerprint**.

Retrieve your one-time 12-character setup code from inside the control container:

```routeros
/container/shell [find comment="tikray:tikray"] cmd="tikray setup-code"
```

1. Open the printed HTTPS URL in your browser and compare the certificate SHA-256 fingerprint against the installer output.
2. Enter the setup code, choose an administrator username, and set a strong password (hashed with Argon2id).
3. You are signed in immediately and land on the **Dashboard**.

---

## 5. Post-Install Verification Checklist

Run a quick check from the Web UI or inside the `tikray` control container:

```sh
tikray status
tikray stats
```

Verify that:
- `routeros.connected` is `true` and `routeros.version` matches your router.
- `active_core` shows your bootstrapped `xray-core` version (e.g. `26.11.9`).
- Your existing LAN internet works normally (default policy starts clean until you add servers and enable `smart` or `full`).

**Next step:** [Protocols & Share Links](Protocols-and-Share-Links.md) to add your first proxy server or subscription!
