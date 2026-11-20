# Offline & Censored Networks

`tikray` is designed from the ground up for routers deployed behind aggressive firewalls, TLS/SNI filtering, blocked GitHub endpoints, or fully air-gapped LANs.

---

## Why tikray Works Seamlessly Behind Censorship

1. **Zero-CDN Embedded Web UI:** The Svelte 5 interface (~57 KB gzipped) is compiled into the `tikray` binary (`go:embed`). Opening the UI makes **zero external requests** — no Google Fonts, no icon CDNs, no analytics.
2. **Four Fetch Tiers:** Every `xray-core` and Geo update automatically supports:
   - Direct upstream HTTPS fetch
   - **Proxy fallback through your active `xray-core` tunnel** (when GitHub is blocked on WAN)
   - Operator-configured mirrors (`TIKRAY_MIRRORS`, `TIKRAY_INDEX_URLS`)
   - **Authenticated Offline Inbox** (browser upload via Web UI, REST API, or RouterOS Winbox/SFTP)
3. **Full Offline Installation:** Bootstrap both containers and `xray-core` from local disk without touching the WAN.

---

## 1. Full Offline RouterOS Installation

Complete the RouterOS prerequisites from the [Installation Guide](Installation-Guide.md), then stage the required files onto your router's ext4 disk using Winbox, WebFig, or SFTP:

### Required Files on Disk (`disk1/tikray/`)

| File | Destination on Router |
|---|---|
| `install.rsc` | Router root (`install.rsc`) |
| `tikray-<arch>.tar` | `disk1/tikray/images/tikray-<arch>.tar` |
| `tikray-runner-<arch>.tar` | `disk1/tikray/images/tikray-runner-<arch>.tar` |
| `Xray-linux-arm64-v8a.zip` (or `Xray-linux-64.zip`) | `disk1/tikray/data/inbox/` |
| Signed `index.json` + `index.json.sig` (or upstream `.dgst`) | `disk1/tikray/data/inbox/` |
| Independently trusted ECDSA P-256 index public key (`PKIX PEM`) | `disk1/tikray/data/state/index.pub` |

> **Separate trust keys:** The container image publisher key (`publisher.pub`, verified by Cosign + installer SHA-512 chunks) and the `xray-core` hash index key (`index.pub`, ECDSA P-256) are independent keys for separate supply chains.

### Run the Offline Import

Set the exact `xray-core` version you staged and enable `tikrayOffline`:

```routeros
:global tikrayCore "26.11.9"
:global tikrayOffline true
/import file-name=install.rsc
```

The installer verifies the container archive lengths and 16 KiB SHA-512 chunks directly from disk, imports both containers, and bootstraps `xray-core` from `disk1/tikray/data/inbox/`.

---

## 2. Offline Updates After Installation (Web UI Inbox)

Once `tikray` is running, you never need SFTP or Winbox to update `xray-core` or Geo data offline:

### Updating `xray-core` via Browser Inbox
1. Download the matching upstream zip on any internet-connected machine (`Xray-linux-arm64-v8a.zip` for ARM64 routers, or `Xray-linux-64.zip` for x86_64 CHR).
2. Open the tikray Web UI → **Updates & Inbox** → **Offline Inbox Upload**.
3. Upload the zip (streams to `POST /v1/inbox/core/{name}`, symlink-safe `O_NOFOLLOW`, 64 MiB cap).
4. Trigger **Update xray-core** for that version (or run `tikray core update 26.11.9`).
   - If you also staged a signed index or `.dgst`, verification passes automatically.
   - For fully air-gapped self-verified zips without an index/digest, explicitly opt in via `--allow-unverified` (CLI) or the **Allow unverified inbox archive** toggle (Web UI).

### Updating Geo Data via Browser Inbox
Upload `geoip.dat`, `geosite.dat` (or `dlc.dat`), and `domestic-v4.txt` via **Updates & Inbox** (calls `POST /v1/inbox/geo/{profile}/{version}/{name}`), then apply the Geo update for that profile and version:

```sh
tikray geo update 20261119 --profile iran
```

> **Security note:** Named API tokens (`tkr_*`) are intentionally forbidden (`403`) from uploading to `/v1/inbox/*`. Only signed-in admin sessions and the container-local root CLI can stage offline artifacts.

---

## 3. Proxy Fallback & Custom Mirrors

When GitHub is blocked on your ISP's WAN but you already have at least one working proxy server configured:
- `tikray core update latest` and `tikray geo update latest` automatically fall back to fetching through the active `xray-core` SOCKS proxy if direct WAN fetch fails.
- You can also configure private mirrors via container environment variables on the `tikray` control container (`comment="tikray:tikray"`):
  - `TIKRAY_MIRRORS` — Comma-separated mirror base URLs for `xray-core` releases
  - `TIKRAY_INDEX_URLS` — Comma-separated URLs for signed `index.json` / `index.json.sig`
  - `TIKRAY_INDEX_PUBKEY_FILE` — Path to the ECDSA P-256 public key PEM (defaults to `/data/state/index.pub`)

---

## 4. Offline Container Image Updates (`tikray` & `tikray-runner`)

To update container images without outbound internet access on the router:
1. Stage the verified archive (`tikray-<arch>.tar` + `.sig`, or `tikray-runner-<arch>.tar` + `.sig`) into the router's `images/` directory.
2. Queue the verified switch via Web UI (**Updates → Container Images**) or CLI:
   ```sh
   tikray image update tikray v1.0.1
   ```
3. The native RouterOS `tikray-watchdog` performs a blue/green swap for `tikray` (zero traffic drop) or supervised swap for `tikray-runner`, health-checks the new container, and automatically rolls back to the previous image archive if anything fails.
