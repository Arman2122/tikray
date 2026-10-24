# tikray

tikray makes [xray-core](https://github.com/XTLS/Xray-core) a first-class, easy-to-install and safe-to-update client on MikroTik RouterOS v7. It runs in RouterOS containers: a Go control plane (web UI, REST API, CLI, RouterOS reconciler) next to a small data-plane runner that supervises xray. xray-core, geo data and tikray each update on their own schedule, with verification and automatic rollback. See the [design spec](docs/superpowers/specs/2026-10-24-tikray-design.md).
