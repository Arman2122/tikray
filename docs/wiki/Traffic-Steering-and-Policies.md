# Traffic Steering & Policies

`tikray` uses a **hybrid RouterOS + xray-core steering model**: domestic and local LAN traffic stays natively on RouterOS (at full hardware/FastTrack speed), while steered international traffic enters `xray-core` over the private `/29` bridge.

---

## 1. Policy Modes

Every device override (and the LAN default policy) selects one of three modes:

| Mode | Domestic IPs & Domains | International Traffic | Local LAN | Best For |
|---|---|---|---|---|
| **`direct`** | Direct via ISP (FastTrack) | Direct via ISP (FastTrack) | Local | Gaming consoles, IPTV boxes, printers, banking-only devices |
| **`smart`** | **Direct via ISP** (RouterOS domestic list + xray geosite) | **Proxied via `xray-core`** | Local | Everyday laptops, phones, smart TVs (recommended default) |
| **`full`** | **Proxied via `xray-core`** | **Proxied via `xray-core`** | Local | Devices that must exit exclusively through the upstream proxy |

### Kill Switch (`--kill-switch`)
Attachable to `smart` or `full` policies (either globally or per device/CIDR):
- If the tunnel, runner, or upstream exit is down, RouterOS drops non-local egress for kill-switched clients instead of failing open to the ISP.
- Pair with **IPv6 Leak Protection** (automatically reconciled by `tikray`) so dual-stack devices cannot bypass IPv4 steering over native IPv6.
- Before tightening a device's policy or enabling a Kill Switch, `tikray` stages temporary hold guards and purges stale RouterOS conntrack/FastTrack bindings so pre-existing flows cannot escape the new policy.

> **Emergency override:** Running `/system/script/run tikray-emergency-off` in RouterOS deliberately suspends all steering and kill switches immediately if you ever need direct WAN access during an outage.

---

## 2. Managing Default & Per-Device Policies

### Via Web UI
Open **Devices & Leases**:
1. Pick your **Default LAN Policy** card (`Direct`, `Smart`, or `Full`) and optional Kill Switch toggle.
2. Under **RouterOS DHCP Leases**, view live bound LAN devices (`IP`, `MAC`, `Hostname`, `Static/Dynamic` badge).
3. Click **Make Static** on any dynamic DHCP lease to convert it into a permanent RouterOS DHCP reservation (verifies readback on the exact bound LAN lease) so its IP never drifts away from its policy!
4. Assign per-device (`/32`) or per-subnet (`CIDR`, e.g. `192.168.88.128/25`) overrides with one click.

### Via CLI
```sh
# Set default policy for all unlisted LAN devices
tikray policy default smart

# Assign a specific device to Full mode with Kill Switch
tikray device set 192.168.88.25 full --kill-switch --name "Work-Laptop"

# Convert its dynamic RouterOS DHCP lease to a static reservation
tikray device make-static 192.168.88.25

# Bypass proxy completely for a subnet
tikray device set 192.168.88.192/26 direct --name "IoT-Range"

# Inspect or remove overrides
tikray device list
tikray device rm 192.168.88.25
```

---

## 3. Custom Routing Rules, Domestic Bypass & DNS

Under **Routing & DNS** (or `PUT /v1/routing` and `PUT /v1/dns`):
- **Pinned Server:** Lock traffic to a specific server, or leave automatic health-based failover enabled (powered by the continuous health observatory probing your configured `probe_url`).
- **Ordered Custom Rules:** Match domains (`domain:`, `full:`, `keyword:`, `geosite:`) or IPs/CIDRs (`geoip:`, `1.2.3.0/24`) and send them `proxy`, `direct`, or `block`.
- **Domestic Extras & Block List:** Add extra local domains/CIDRs that should always stay direct, or block ads/trackers cleanly at the router.
- **Geo Profiles:** Defaults to `iran` (powered by [Arman2122/IR-Geo-DB](https://github.com/Arman2122/IR-Geo-DB), rebuilt daily with RIPE-corrected Iranian IPv4 ranges, `geosite:ir`, `geoip:ir`, and optional ad/malware/phishing sets), or switch to `v2fly`, `loyalsoldier`, or `custom` — `tikray` keeps both xray's `geoip.dat`/`geosite.dat` and RouterOS's domestic IPv4 address-list synchronized inside a single atomic rollbackable transaction.
- **DNS Configuration:**
  - **Remote DNS** (DoH presets such as Cloudflare/Quad9/Google or custom HTTPS/IPv4 resolvers) resolved safely through the tunnel for proxied destinations.
  - **Domestic DNS** (optional IPv4 resolver) for fast local resolution of domestic domains.

---

## 4. Compatibility with Existing RouterOS NAT & FastTrack Rules

`tikray` coexists safely with your existing MikroTik firewall and NAT configuration, with two golden rules to keep in mind:

1. **Scope your WAN masquerade rule to `out-interface-list=WAN`** (standard RouterOS default). A broad masquerade rule with no `out-interface` / `out-interface-list` would rewrite client LAN IPs before packets enter the runner. `tikray` detects this automatically during device admission and warns you before breaking per-device policies.
2. **Keep `tikray:`-tagged rules above FastTrack and owner NAT rules.** `tikray` installs paired tagged source-NAT exceptions and private-bridge forward guards above permissive rules and continuously verifies their order via `/listen` and periodic reconciliation sweeps.
