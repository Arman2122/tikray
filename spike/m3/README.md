# RouterOS capability probe

This lab-only test is the M3 Task 0 approval gate. Run it on a disposable ready-image overlay, serially, as root in WSL Ubuntu. It takes over the existing lab's `tklab-*` network for one VM. Set `TIKRAY_LAB_CACHE` to the cache containing both previously provisioned x86_64 ready images. The test reads each ready-image credential privately and checks the running RouterOS version and architecture.

```sh
umask 077
logdir=$(mktemp -d)
export TIKRAY_LAB_ARCH=x86_64
for version in 7.23.8 7.25; do
    TIKRAY_LAB_CHANNEL="$version" timeout --kill-after=15s 44m \
        go test -tags lab -count=1 -p 1 -v -timeout 42m \
        -run '^TestM3Capabilities$' ./spike/m3/ >"$logdir/$version.log" 2>&1 &
    pid=$!
    if wait "$pid"; then status=0; else status=$?; fi
    printf '%s exit=%s\n' "$version" "$status"
done
```

The owner SSH connection provisions the VM. A second host address on the isolated lab LAN represents the control plane at `172.31.255.2`. The restricted and owner-control clients authenticate over native API-SSL after verifying the certificate exported over the provisioning channel. The restricted group grants exactly `read,write,api`. Owner controls distinguish unsupported syntax and fixture errors from permission failures. The VM and its overlay are disposed of after each run.

`CAP` lines report only the version, capability, verdict and a predefined reason. A failed assertion deliberately gives the test a nonzero exit. Read the verdicts for both versions before deciding whether product work can start. The probe must establish all four claims to open the gate. Never record raw responses, RouterOS errors, console dumps or credentials in the ledger. On external timeout, use the PID from this run's `harness.log`, check that it is QEMU and uses this run's overlay, then terminate that PID only. Confirm the VM, lab interfaces and namespaces are gone.
