# Protocols & Share Links

`tikray` supports modern **`xray-core` 26.x** (`v26.1.18` – `v26.11.9`) outbounds via standard share links, scheduled subscription feeds, and raw `xray-core` JSON — while enforcing strict cryptographic hygiene and zero-secret redaction.

---

## Supported Protocols & Transports

| Protocol | URI Scheme | Transports | Security Modes |
|---|---|---|---|
| **VLESS** | `vless://` | `tcp` (`raw`), `ws`, `grpc`, `httpupgrade`, **`xhttp`** (`splithttp`) | `reality`, `tls`, `none` (private/PQ encrypted only) |
| **VMess** | `vmess://` | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` | `tls`, `none` |
| **Trojan** | `trojan://` | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` | `tls`, `reality` |
| **Shadowsocks & SS-2022** | `ss://` | TCP/UDP (validated key lengths for `2022-blake3-*`) | AEAD / 2022 ciphers (`none`/`plain` refused) |
| **Raw `xray-core` Outbound** | `--json FILE` / UI | Any transport supported by your active `xray-core` | Any policy-compliant security / `finalmask` |

> Legacy/deprecated transports (`kcp`/`mkcp`, `quic`, `h2`/`http`) return a clear `unsupported` error rather than silently generating broken configs.

---

## Modern `xray-core` 26.x Features

### 1. REALITY + Post-Quantum ML-DSA-65 (`pqv`)
Standard REALITY parameters (`pbk`, `sid`, `spx`, `sni`, `fp`) work out of the box, plus post-quantum verification via **`pqv`**:

```text
vless://<uuid>@edge.example.net:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=<public-key>&sid=<short-id>&pqv=<mldsa65-verify-key>#Frankfurt-PQ
```

- `pqv` maps cleanly to `streamSettings.realitySettings.mldsa65Verify`.
- `fp` defaults to `"chrome"` when omitted on REALITY links.
- REALITY is permitted over `tcp`, `grpc`, and `xhttp` (refused on `ws`/`httpupgrade`).

### 2. Post-Quantum VLESS Native Encryption (`encryption`)
`tikray` passes the VLESS `encryption` query parameter through verbatim (defaulting to `"none"` when omitted), enabling modern Xray native post-quantum VLESS encryption strings without falling back to raw JSON.

### 3. XHTTP / SplitHTTP with Advanced `extra` JSON (`extra`)
Full support for `type=xhttp` (or `type=splithttp`), `mode` (`auto`, `packet-up`, `stream-up`, `stream-one`), `host`, `path`, and the **`extra`** JSON object (URL-encoded in the share link):

```text
vless://<uuid>@edge.example.net:443?type=xhttp&mode=auto&path=%2Fx&security=reality&sni=www.example.com&pbk=<pbk>&extra=%7B%22noGRPCHeader%22%3Atrue%2C%22xPaddingBytes%22%3A%22100-500%22%7D#XHTTP-XMUX
```

- Supports **XMUX** (`xmux`), **`downloadSettings`** (split upload/download paths), `noGRPCHeader`, `scMaxEachPostBytes`, `xPaddingBytes`, and custom headers.
- Enforces strict safety guards: `extra` must be a valid JSON object (`<= 16 KiB`), malformed payloads never echo their content in errors, and **`internal/xraypolicy` recursively inspects `extra.downloadSettings` to block nested `allowInsecure: true`**.

### 4. TLS Encrypted Client Hello (`ech`) & Certificate Pinning (`pcs` / `vcn`)
Modern `xray-core` 26.x removes `allowInsecure` (it actively refuses configs containing it). Use **`ech`**, **`pcs`**, and **`vcn`** instead:

| Query Param | Rendered `tlsSettings` Field | Purpose |
|---|---|---|
| `ech` | `echConfigList` | TLS Encrypted Client Hello (ECH) config list |
| `pcs` | `pinnedPeerCertSha256` | Comma-separated SHA-256 hex cert pins (replaces `allowInsecure` safely) |
| `vcn` | `verifyPeerCertByName` | Override hostname checked against the server's TLS certificate |
| `alpn` | `alpn` | Comma-separated ALPN list (e.g. `h2,http/1.1`) |
| `sni` | `serverName` | TLS SNI (falls back to first `host` entry for CDN-fronted links) |

> **What happens if a legacy link has `allowInsecure=1`?**
> `tikray` strips `allowInsecure` during share-link parsing, keeps TLS certificate verification enabled, and attaches a clear warning recommending `pcs` (pinned certificate SHA-256). Raw JSON outbounds containing `allowInsecure: true` anywhere in `tlsSettings` or `tlsConfig` (including nested `xhttpSettings.extra.downloadSettings` and `finalmask`) are refused cleanly with `422 refused`.

---

## Adding Servers

### Web UI (with Live Share-Link Inspector)
Go to **Servers & Subs → Add Server**. As you paste a share link, the **client-side inspector** immediately parses non-secret metadata in your browser and displays capability badges (`VLESS`, `REALITY`, `XTLS-Vision`, `XHTTP+Extra`, `ML-DSA-65`, `PQ-Enc`, `ECH`, `Pinned Cert`, or `allowInsecure` warnings) before you click Add — without ever echoing your UUID or password.

You can also bulk-import multiple links (one per line) or switch to the **Raw JSON** tab to paste a complete `xray-core` outbound object.

### CLI
```sh
# Single share link
tikray server add "vless://..." --name "Frankfurt-01"

# Raw xray-core outbound JSON file
tikray server add --json ./custom-outbound.json --name "Custom-Finalmask"

# Enable / disable / remove (triggers zero-downtime hot reload)
tikray server list
tikray server disable <id>
tikray server enable <id>
tikray server rm <id>
```

---

## Subscriptions

Add Base64, plain-line, or SIP008 subscription feeds with automatic background refresh:

```sh
tikray sub add "https://provider.example/sub" --name main --interval 24h
tikray sub refresh <id>
tikray sub list
```

- Subscription URLs are **stored encrypted-safe in state and never returned by API, CLI, Web UI, logs, or events**.
- Each refresh reports an atomic diff summary: `added`, `updated`, `removed`, `kept`, and `skipped` (with redacted skip reasons if a provider emits an unsupported or insecure entry).
- Updating servers from a subscription automatically uses **hot outbound reload (`xray api`)** so active LAN streams continue uninterrupted.
