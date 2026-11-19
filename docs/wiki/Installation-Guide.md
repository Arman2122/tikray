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

## 2. Obtain or Package a Verified Installer

Every RouterOS installer embeds the exact container archive byte lengths and **16 KiB chunked SHA-512 digests** verified by RouterOS before importing containers.

### Option A — Use a Signed Release Installer
Download the matching `install-<routeros-version>-<arch>.rsc` and `SHA256SUMS` from GitHub Releases and verify its checksum before use.

### Option B — Package Your Own Installer from Signed Archives
Place `tikray-<arch>.tar`, `tikray-<arch>.tar.sig`, `tikray-runner-<arch>.tar`, and `tikray-runner-<arch>.tar.sig` in `./release-images`, obtain `publisher.pub` out-of-band, and run:

```sh
go run ./cmd/tikray-installer \
  -version 7.25.1 \
  -arch arm64 \
  -images ./release-images \
  -key ./publisher.pub \
  -out ./install.rsc
```

- Use `-arch amd64` for x86_64 CHR.
- For one-paste online deployment, pass `-release-base https://<your-release-host>/<release-dir>` pointing to a **non-redirecting HTTPS static host** (such as GitHub Pages or your own static HTTPS server).
  > **Why not `github.com/.../releases/download` directly?** GitHub's release download URLs return HTTP 302 redirects to signed object-storage URLs. Because RouterOS can log redirect `Location` headers and the installer enforces `http-max-redirect-count=0`, the packager rejects redirecting release bases intentionally.

---

## 3. Run the Installer on RouterOS

### Online One-Paste (Trusted Static HTTPS Origin)
Ensure RouterOS trusts the release host's TLS CA, then paste into the RouterOS terminal:

```routeros
{ :local dl [/tool/fetch url="https://<your-release-host>/<release-dir>/install.rsc" check-certificate=yes http-max-redirect-count=0 dst-path=tikray-install.rsc as-value]; :if (($dl->"status") != "finished") do={ :error "Installer download failed" }; /import file-name=tikray-install.rsc }
```

### Customizing Non-Secret Installer Defaults

Override any of these global variables in the **same terminal session** before `/import file-name=tikray-install.rsc`:

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

Example with custom disk, subnet, and interface lists:

```routeros
:global tikrayDisk "usb1"
:global tikraySubnet "172.31.254.0/29"
:global tikrayLanList "HOME-LAN"
:global tikrayWanList "ISP-WAN"
/import file-name=tikray-install.rsc
```

### What the Installer Provisions Safely
- Dedicated private bridge `tikray` (`protocol-mode=none`, `arp=reply-only`, static ARP/FDB bindings, disabled MAC learning & unknown-unicast flooding).
- Scoped `tikray` RouterOS API-SSL account + certificate pinning receipt in `/data/state/routeros.json`.
- Both containers (`tikray:ctl` and `tikray:runner`) mounted to `/data` on your ext4 volume.
- Native `tikray-watchdog` scheduler (1-minute health checks with exponential backoff) and `tikray-emergency-off` script.
- Return-traffic isolation rules above FastTrack and permissive owner rules.
- Preserves your existing RouterOS firewall, NAT, registry, and disk layout (refuses conflicting mounts or ports).

---

## 4. First-Run Setup & Certificate Verification

At completion, the installer prints:
1. Your LAN HTTPS URL (for example `https://192.168.88.1` or the control container's address).
2. The control plane's **self-signed TLS certificate SHA-256 fingerprint**.

Retrieve your one-time 12-character setup code from inside the control container:

```routeros
/container/shell [find comment="tikray:ctl"] cmd="tikray setup-code"
```

1. Open the printed HTTPS URL in your browser and compare the certificate SHA-256 fingerprint against the installer output.
2. Enter the setup code, choose an administrator username, and set a strong password (hashed with Argon2id).
3. You are signed in immediately and land on the **Dashboard**.

---

## 5. Post-Install Verification Checklist

Run a quick check from the Web UI or inside `tikray:ctl`:

```sh
tikray status
tikray stats
```

Verify that:
- `routeros.connected` is `true` and `routeros.version` matches your router.
- `active_core` shows your bootstrapped `xray-core` version (e.g. `26.11.9`).
- Your existing LAN internet works normally (default policy starts clean until you add servers and enable `smart` or `full`).

**Next step:** [Protocols & Share Links](Protocols-and-Share-Links.md) to add your first proxy server or subscription!
