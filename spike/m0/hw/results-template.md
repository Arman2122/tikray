# M0 hardware benchmark results

- **Device:** (model, CPU, RAM)
- **RouterOS:** (version, channel)
- **Storage for /container:** (USB stick, NVMe, internal)
- **VPS:** (location, link speed, RTT from the router)
- **xray outbound:** (protocol, transport, security)

Run each measurement 3 times. Write Mbit/s as reported by iperf3 (sender side for upload, receiver side for download).

| Test | Run 1 | Run 2 | Run 3 | Router CPU % during test |
|---|---|---|---|---|
| Direct, upload: `iperf3 -c <vps> -t 30` | | | | |
| Direct, download: `iperf3 -c <vps> -t 30 -R` | | | | |
| Proxied, upload | | | | |
| Proxied, download | | | | |
| Proxied, 8 streams: `iperf3 -c <vps> -t 30 -P 8` | | | | |
| Proxied, 8 streams, download: `-P 8 -R` | | | | |

| Memory | Value |
|---|---|
| Runner `xray_rss_kb` after the tests (`http://172.31.255.3:8080/v0/status`) | |
| `/container/print` MEMORY-CURRENT, tikray-runner | |
| `/container/print` MEMORY-CURRENT, tikray-ctl | |
| `/system/resource/print` free-memory before install | |
| `/system/resource/print` free-memory during the proxied 8-stream test | |

Notes (anything unexpected, errors in `/log/print where topics~"container"`):
