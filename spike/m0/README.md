# M0 data-path spike (throwaway)

Everything in this directory is throwaway code for the M0 spike in
[the M0 plan](../../docs/superpowers/plans/2026-10-24-m0-data-path-spike.md).
It answers questions about the RouterOS → container → xray TUN data path and
will be deleted in M1, once the real runner covers the same ground. The lab
harness it uses (`test/lab`) is kept.

- `runnerproto/`: stand-in for tikray-runner (sets up routing into xray's TUN interface, supervises xray, reports status).
- `ctlproto/`: stand-in for the tikray control plane (shared-mount writes, a RouterOS API `/listen` probe).
- `images/`, `build-images.sh`: `FROM scratch` container images, exported with `docker save` for `/container/add file=`.
- `config/xray-client.json`: the xray client config the runner prototype runs.
