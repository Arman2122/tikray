# Geo publishers and release selection

An update fetches a complete geo release into a new slot. The runner trials the selected data and rendered configuration, and the service verifies the associated RouterOS domestic list. The CLI can select an explicit profile or use the configured profile.

```sh
tikray geo update latest                # defaults to --profile iran (Arman2122/IR-Geo-DB)
tikray geo update latest --profile iran
tikray geo rollback
```

`TIKRAY_GEO_PROFILE` selects the publisher used when the profile is omitted. Without an explicit env override, scheduled daily checks follow the managed profile from the active geo slot (a fresh installation with neither selection stays quiet until a geo slot is installed), while explicit `tikray geo update` requests default to `iran`. `TIKRAY_GEO_URL` is the trusted HTTPS root for the custom profile. `TIKRAY_GEO_MIRRORS` is a comma-separated list of HTTPS payload templates containing `{file}`, with optional `{version}` and `{arch}`.

| Profile | Release selector | Payloads and domestic matchers |
|---|---|---|
| `iran` *(default)* | `vYYYY.MM.DD` tag (e.g. `v2026.11.20`), or `latest` | `geoip.dat` and `geosite.dat` verified against `SHA256SUMS` from [Arman2122/IR-Geo-DB](https://github.com/Arman2122/IR-Geo-DB/releases). Uses `geoip:ir` and `geosite:ir` (also includes `geosite:ads`, `geosite:malware`, `geosite:phishing`, `geosite:cryptominers`, `geoip:malware`). |
| `loyalsoldier` | Numeric release tag, or `latest` | Both data files from [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat/releases). Uses `geoip:cn` and `geosite:cn`. |
| `v2fly` | `<geoip-tag>+<domain-list-tag>`, or `latest` | The two independent publishers release on different schedules. Uses `geoip.dat` from [v2fly/geoip](https://github.com/v2fly/geoip/releases) and `dlc.dat` from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/releases), installed as `geosite.dat`. Uses `geoip:cn` and `geosite:cn`. |
| `custom` | A publisher tag, or `latest` | A three-file bundle and its publisher manifest from the configured HTTPS root. The manifest supplies the matchers. |

An `iran` tag uses `vYYYY.MM.DD` (optionally followed by `.N` or `-N` for same-day rebuilds). A numeric tag for `loyalsoldier` / `v2fly` has 8–20 decimal digits. A custom tag has 1–64 ASCII letters, digits, periods, underscores or hyphens, starts with a letter or digit and contains no `..`. For pinned v2fly updates supply **both** tags, for example `202611080027+20261115005626`. The mirror's `{version}` is the tag of the individual upstream asset.

For built-in profiles tikray obtains the release's published `SHA256SUMS` (`iran`) or per-asset `.sha256sum` (`loyalsoldier`, `v2fly`) over HTTPS, directly or through a healthy proxy. It decodes the selected country's IPv4 prefixes from that verified GeoIP file, then records the SHA-256 of the generated domestic text. For every payload the fallback order is publisher, publisher over the healthy proxy, configured mirrors, then the local inbox.

## Custom publisher layout

Serve `latest` as a small text file containing the current tag. Under `<root>/<tag>/` serve these four files:

```text
geoip.dat
geosite.dat
domestic-v4.txt
meta.json
```

`meta.json` contains the tag, arrays of geosite and geoip matchers, and the lowercase SHA-256 of **each exact payload**. Replace the three placeholders below with real 64-digit digests.

```json
{
  "version": "regional-20261115",
  "site": ["geosite:category-ir"],
  "ip": ["geoip:ir"],
  "sha256": {
    "geoip.dat": "<geoip digest>",
    "geosite.dat": "<geosite digest>",
    "domestic-v4.txt": "<domestic list digest>"
  }
}
```

The text file holds one canonical IPv4 CIDR per line. Empty lines and lines starting with `#` are allowed. A verified empty text file intentionally specifies no bundle CIDRs. Both data files must be valid protobuf lists with the referenced codes present. Xray checks the candidate's runtime behavior during its trial.

## Scheduling

`TIKRAY_GEO_MODE` accepts `auto`, `notify` and `manual`. The default is
`auto`. It activates a verified update through the same runner trial and
RouterOS transaction as a manual request. `notify` compares the trusted
publisher's latest release identity with the committed slot. A different
release produces a geo availability event. Payload verification and activation
take place when the owner requests the update. `manual` disables scheduled
publisher checks. Explicit update and rollback commands work in every mode.

`TIKRAY_GEO_WINDOW` can limit scheduled checks to a UTC interval in
`HH:MM-HH:MM` form. For example, `22:00-02:00` opens at 22:00 UTC and ends
at 02:00 UTC the following day. The closing minute is excluded. A check
started in the window can finish after it closes. Use an empty value for
an unrestricted schedule.

A private receipt reserves the check before the publisher is contacted.
Restarting the service or a failed fetch cannot repeat it in that window.
With a configured window the opening UTC date identifies the daily check.
Without a window the minimum interval is 24 hours.

## Offline updates

Use a concrete release selector for an offline update. Place an independently obtained publisher manifest at `/data/state/geo-trust/<profile>/<selector>/meta.json` on the private control volume. Its `version` must equal the requested selector. Custom uses the manifest shown above. For built-ins the checksum map must include `geoip.dat` and `geosite.dat` (the latter holds the digest of upstream `dlc.dat` for v2fly). Built-in matchers and domestic ranges are determined by the profile and its verified binary.

Put payloads in `/data/inbox/geo/<profile>/<selector>/` under their upstream filenames. For v2fly this means `geoip.dat` and `dlc.dat`. For custom include the domestic text. An optional private `/data/state/geo-trust/<profile>/latest` text file names the desired verified selector when the publisher's latest lookup is unavailable. The owner must authenticate the manifest before putting it in the private trust directory. Copying checksums into the payload inbox does not establish trust.

A managed slot has a bounded directory name derived from the publisher, tag and configured custom origin. Raw URLs and owner-supplied strings stay out of result and failure text. The metadata records the profile and release identity, with each payload's digest. `GeoSlotProfile` reads this identity for scheduling. `SameGeo` rechecks local payload integrity before comparing payloads and matchers; corruption prevents a no-op verdict even when both names are identical.
