# M0 hardware benchmark kit

This measures the M0 data path on a real MikroTik router: how fast traffic moves through xray in a container, how much CPU and memory that costs, and whether anything behaves differently from the CHR lab. It installs exactly the setup the lab tests (`../routeros/setup.rsc`), so results are comparable. Everything it adds carries a `tikray:` comment and can be removed again.

It's throwaway spike tooling, not the tikray installer.

## What you need

- An ARM64 MikroTik on RouterOS **stable** or **long-term** v7 (hAP ax³, RB5009, ...), with a **USB stick or NVMe** for container storage.
- A PC on the router's LAN, with `iperf3` installed. Note its LAN IP and give it a static DHCP lease.
- One VPS running an xray server you can connect to (VLESS + Reality is the reference), plus `iperf3 -s` running on the same VPS.
- From this repo, on a Linux machine with Go and Docker (classic image store; `build-images.sh` explains if not):
  - `bash spike/m0/build-images.sh arm64` → `spike/m0/out/runnerproto-arm64.tar` and `ctlproto-arm64.tar`.
  - The official xray-core 26.3.27 (or newer) **linux-arm64-v8a** binary from the XTLS releases page, unzipped, named `xray`.

## 1. Prepare the router

Run these in the RouterOS terminal. Each step is safe to repeat.

1. **Install the container package:** download `all_packages-arm64-<version>.zip` for your exact RouterOS version from mikrotik.com, upload `container-<version>-arm64.npk` through Winbox → Files, then `/system/reboot`.
2. **Enable containers:** `/system/device-mode/update container=yes`, then press the reset button briefly (or power-cycle) within 5 minutes. Check with `/system/device-mode/print` → `container: yes`.
3. **Name the disk disk1:** plug in the USB stick, find it with `/disk/print`, then `/disk/set [find slot=usb1] slot=disk1` (use the slot you saw). If it isn't ext4 yet: `/disk/format [find slot=disk1] file-system=ext4` (this erases it).
4. **Container settings:** `/container/config/set tmpdir=disk1/tikray/tmp`.

## 2. Upload the files

With Winbox → Files (drag and drop), create these paths:

| File | Upload to |
|---|---|
| `runnerproto-arm64.tar` | `disk1/tikray/images/runnerproto-arm64.tar` |
| `ctlproto-arm64.tar` | `disk1/tikray/images/ctlproto-arm64.tar` |
| `xray` | `disk1/tikray/data/cores/26.3.27/xray` |
| `xray-client.hw.json`, after editing (below) | `disk1/tikray/data/run/config.json` |
| `../routeros/setup.rsc` and `bench.rsc`, after editing (below) | the root of Files |

Edit `xray-client.hw.json`: replace every `CHANGE-ME` with your server's details and your ISP's DNS server. Any xray outbound works; replace the whole `proxy` outbound if yours isn't VLESS + Reality.

Edit `bench.rsc`: set `tikrayLanClient` to the PC's IP, `tikrayWanIf` and `tikrayWanGw` to your WAN interface and gateway, and `tikrayApiPass` to any password.

`setup.rsc` adds the lab's "domestic" test range `203.0.113.20/32` (a documentation address); it's harmless on a real network.

## 3. Install and start

```
/import bench.rsc
/container/start [find where comment~"^tikray:"]
```

Wait until `/container/print` shows both containers as `R` (running). Then, from the PC, `http://172.31.255.3:8080/v0/status` should show `"routes_ok":true`.

Check the path: open https://ifconfig.me on the PC. It should show the VPS's IP. If it shows your own, check `/log/print where topics~"container"`.

## 4. Measure

Fill in `results-template.md`. Run each test 3 times:

- **Proxied:** the PC is in `tikray-src-smart-open`, so `iperf3 -c <vps> -t 30` (upload) and `iperf3 -c <vps> -t 30 -R` (download) go through xray.
- **Direct:** turn proxying off for the PC with `/ip/firewall/address-list/disable [find where comment="tikray:src"]`, rerun the same commands, then turn it back on with `enable` instead of `disable`.
- **8 streams:** add `-P 8` to the proxied runs.
- **CPU:** watch `/system/resource/print` (`cpu-load`) during each run, or run `/tool/profile duration=20s` in a second terminal.
- **Memory:** record the values listed in the template.

## 5. Remove everything

Set `:global tikrayBenchUninstall true` at the top of `bench.rsc`, upload it again, and run `/import bench.rsc`. Then delete `disk1/tikray` in Files if you want the space back. The container package and device-mode stay as they are.
