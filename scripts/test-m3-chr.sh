#!/usr/bin/env bash
# Run from Ubuntu as root, with the signed bundles and CHR/core caches ready.
set -euo pipefail
umask 077

inside() {
    local binary=$1 pattern=$2 mode=$3 rc=0 pid exe birth link
    local deadline=420m grace=421m
    # Never let SetupNetwork's stale-lab cleanup see another lab's resources.
    [[ $$ == 1 && $(readlink /proc/self/ns/net) != "$lab_parent_net" &&
        $(readlink /proc/self/ns/mnt) != "$lab_parent_mnt" &&
        $(readlink /proc/self/ns/pid) != "$lab_parent_pid" ]]
    mount -t tmpfs -o size=32m,mode=0755 tmpfs /run
    mkdir -p /run/netns /run/lock
    mount -t tmpfs -o size=8m,mode=0755 tmpfs /run/netns
    mount -t tmpfs -o size=4g,mode=1777 tmpfs /tmp
    mount -t sysfs sysfs /sys
    mount --bind "$TIKRAY_LAB_CACHE" "$TIKRAY_LAB_CACHE"
    if [[ $mode == cache ]]; then
        deadline=50m grace=51m
    else
        mount -o remount,bind,ro "$TIKRAY_LAB_CACHE"
    fi
    [[ -z $(ip netns list) && ! -e /sys/class/net/tklab-wan ]]
    ip link set lo up

    timeout --kill-after=15s "$grace" "$binary" -test.v -test.count=1 -test.timeout="$deadline" -test.run "$pattern" || rc=$?
    # On a timeout Go cleanups may not run. Only a verified QEMU in our new
    # PID namespace is eligible; recheck its birth time before escalation.
    for link in /proc/[0-9]*/exe; do
        exe=$(readlink "$link") || continue
        case ${exe##*/} in qemu-system-x86_64|qemu-system-aarch64) ;; *) continue ;; esac
        pid=${link#/proc/}; pid=${pid%/exe}
        birth=$(cut -d' ' -f22 "/proc/$pid/stat") || continue
        echo "Cleaning up lab QEMU PID $pid"
        kill -TERM "$pid" || true
        for _ in 1 2 3 4 5; do [[ -e /proc/$pid/stat ]] || break; sleep 1; done
        if [[ $(readlink "$link" 2>/dev/null || true) == "$exe" &&
              $(cut -d' ' -f22 "/proc/$pid/stat" 2>/dev/null || true) == "$birth" ]]; then
            kill -KILL "$pid" || true
        fi
        rc=1
    done
    if [[ -n $(ip netns list) || -e /sys/class/net/tklab-wan || -e /sys/class/net/tklab-lan ]]; then
        echo "The test left lab networking behind in its disposable namespace"
        rc=1
    fi
    return "$rc"
}

if [[ ${1:-} == --isolated-child ]]; then
    inside "$2" "$3" acceptance
    exit
fi
if [[ ${1:-} == --cache-child ]]; then
    inside "$2" "^TestBootReadyCHR$" cache
    exit
fi
if [[ $# -lt 2 || $# -gt 3 || $EUID != 0 ]]; then
    echo 'usage (root): scripts/test-m3-chr.sh VERSION ARCH [Go test regex]' >&2
    exit 2
fi
export TIKRAY_LAB_CHANNEL=$1 TIKRAY_LAB_ARCH=$2
case "$1-$2" in 7.25-x86_64|7.23.8-x86_64|7.25-arm64) ;; *) echo "Unsupported lab target" >&2; exit 2 ;; esac
pattern=${3:-'^(TestM3Install|TestM3Routing|TestM3Uninstall)$'}
project=$(cd "$(dirname "$0")/.." && pwd)
cd "$project"
script=$project/scripts/test-m3-chr.sh
export TIKRAY_LAB_XRAY=${TIKRAY_LAB_XRAY:-v26.10.31}
TIKRAY_LAB_CACHE=$(realpath "${TIKRAY_LAB_CACHE:-$HOME/.cache/tikray-lab}")
export TIKRAY_LAB_CACHE
export PATH="$TIKRAY_LAB_CACHE/tools:$PATH"
# The privileged lab compiles test helpers from the owner's checkout. Image
# revision stamps come from the separately built, verified release archives.
export GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false"
bundle=${TIKRAY_LAB_IMAGES:-$project/out/m3-install/$1-$2}
export TIKRAY_LAB_IMAGES
TIKRAY_LAB_IMAGES=$(realpath "$bundle")
export TIKRAY_LAB_INSTALLER=${TIKRAY_LAB_INSTALLER:-$TIKRAY_LAB_IMAGES/install.rsc}
export TIKRAY_LAB_UNINSTALLER=${TIKRAY_LAB_UNINSTALLER:-$TIKRAY_LAB_IMAGES/uninstall.rsc}
results=${TIKRAY_LAB_RESULTS:-$project/test/e2e/results}
mkdir -p "$results"
exec 9>"$TIKRAY_LAB_CACHE/.m3-lab.lock"
flock -n 9 || { echo "Another matrix run owns the CHR lab lock" >&2; exit 1; }
run=$(mktemp -d "/var/tmp/tikray-m3-$1-$2.XXXXXX")
export TIKRAY_LAB_RESULTS=$run/results
mkdir "$TIKRAY_LAB_RESULTS"
export TMPDIR=/tmp GOTMPDIR=/tmp
go test -c -tags lab -o "$run/e2e.test" ./test/e2e
mapfile -t tests < <("$run/e2e.test" -test.list "${pattern%%/*}")
if [[ ${#tests[@]} == 0 ]]; then echo "No matching acceptance suite" >&2; exit 1; fi
for name in "${tests[@]}"; do
    case "$name" in TestM3Install|TestM3Routing|TestM3Watchdog|TestM3Outage|TestM3Uninstall|TestService|TestAuth|TestHot) ;;
        *) echo "The selection includes an unrecognized acceptance suite" >&2; exit 2 ;; esac
done
lab_parent_net=$(readlink /proc/self/ns/net)
lab_parent_mnt=$(readlink /proc/self/ns/mnt)
lab_parent_pid=$(readlink /proc/self/ns/pid)
export lab_parent_net lab_parent_mnt lab_parent_pid
echo "Running CHR $1 $2. Private log: $run/harness.log"
timeout --kill-after=30s 423m unshare --mount --net --pid --fork --kill-child --mount-proc --propagation private \
    bash "$script" --isolated-child "$run/e2e.test" "$pattern" >"$run/harness.log" 2>&1 &
worker=$!
trap 'kill -TERM "$worker" 2>/dev/null || true; wait "$worker" || true; exit 130' HUP INT TERM
rc=0
wait "$worker" || rc=$?
trap - HUP INT TERM
printf '%s\n' "$rc" >"$run/exit"
if ((rc != 0)); then
    echo "CHR suite failed (exit $rc); see the private log" >&2
    grep -oE 'm3-(runner|control)-update-phase=(prepare|before-healthy-request|healthy-request|healthy-completion|healthy-runtime|healthy-owner|healthy-reimport|reimported-owner|explicit-rollback|unhealthy-update|retained-wan|fresh-dns|alternate-wan|automatic-rollback|restored-trial|retained-proxy)$' "$run/harness.log" >&2 || true
    if [[ $pattern == *TestM3Watchdog* ]]; then
        grep -oE '(active owner (LAN|bridge) API|owner (LAN|bridge) API (baseline|readback)): (session changed|command timed out|command unavailable|missing affirmative reply)$' "$run/harness.log" >&2 || true
        grep -oE 'independent image witness: owner_session=(true|false) native_row=(true|false) row_id=(true|false) image=(true|false) process=(true|false) selection=(true|false)$' "$run/harness.log" >&2 || true
        grep -oE 'packaged installer import failed: (installer acknowledgement missing|private installer execution failed)$' "$run/harness.log" >&2 || true
        grep -oE '(original owner LAN SSH transport was lost|owner LAN SSH command failed|the unrelated stream did not receive two fresh UDP replies|cannot verify the current committed runner selection)$' "$run/harness.log" >&2 || true
        grep -oE 'unrelated connection continuity failed: monitor=(true|false) read=(true|false) api_id=(true|false) ssh_id=(true|false)( (api|ssh)_counts=\[[0-9 ]+\]->\[[0-9 ]+\]){2}$' "$run/harness.log" >&2 || true
        grep -oE '(missing or ambiguous (runner|control-start) control-side witness \([0-9]+ received bytes\)|private file returned no complete size-checked witness)$' "$run/harness.log" >&2 || true
    fi
    if [[ $pattern != */* ]]; then
        # These files are written from the fixed Go catalogue. The case
        # positions identify failures without exposing even their text.
        python3 - "$TIKRAY_LAB_RESULTS" "$1-$2" <<'PY_DIAGNOSTICS'
import json, pathlib, sys
base, target = pathlib.Path(sys.argv[1]), sys.argv[2]
for suite, count in (("m3-install", 6), ("m3-routing", 10), ("m3-outage", 6), ("m3-uninstall", 4), ("m3-watchdog", 5)):
    try:
        rows = json.loads((base / f"{target}-{suite}-partial.json").read_bytes())
        if not isinstance(rows, list) or not 0 < len(rows) <= count:
            continue
        for n, row in enumerate(rows, 1):
            if isinstance(row, dict) and row.get("pass") is False:
                print(f"Failed {suite} check {n}", file=sys.stderr)
    except (OSError, ValueError):
        continue
PY_DIAGNOSTICS
    fi
    exit "$rc"
fi

partial=
[[ $pattern != */* ]] || partial=-partial
# Require fresh, nonempty results from every selected top-level test. Validate
# the entire set before replacing any prior evidence. Only public paths and
# counts are printed, regardless of the content of a failed test.
python3 - "$TIKRAY_LAB_RESULTS" "$results" "$1-$2" "$partial" "${tests[@]}" <<'PY'
import json, os, pathlib, sys, tempfile
src, dst = map(pathlib.Path, sys.argv[1:3])
prefix, partial = sys.argv[3:5]
suites = {"TestM3Install": ("m3-install", 6), "TestM3Routing": ("m3-routing", 10),
          "TestM3Watchdog": ("m3-watchdog", 5), "TestM3Outage": ("m3-outage", 6), "TestM3Uninstall": ("m3-uninstall", 4), "TestService": ("m2b", 8),
          "TestAuth": ("m2c-auth", 6), "TestHot": ("m2c-hot", 4)}
ready = {}
for name in sys.argv[5:]:
    suite, count = suites[name]
    file = f"{prefix}-{suite}{partial}.json"
    try:
        data = (src / file).read_bytes()
        rows = json.loads(data)
        valid = (isinstance(rows, list) and 0 < len(rows) <= count and (partial or len(rows) == count)
                 and all(r["pass"] is True and r["detail"] for r in rows)
                 and len({r["id"] for r in rows}) == len(rows))
    except (OSError, ValueError, KeyError, TypeError):
        valid = False
    if not valid:
        sys.exit("Missing or incomplete acceptance evidence")
    ready[file] = data
for file, data in ready.items():
    with tempfile.NamedTemporaryFile(dir=dst, delete=False) as f:
        f.write(data)
        f.flush()
        os.fchmod(f.fileno(), 0o644)
        os.fsync(f.fileno())
    os.replace(f.name, dst / file)
    print(f"PASS {file}")
PY
