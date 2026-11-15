#!/usr/bin/env bash
# Build the signed baseline + labelled healthy/unavailable releases used by
# TestM3Watchdog. Requires the same classic Docker store as make images.
# All selected architectures use one ephemeral P-256 QA identity.
set -euo pipefail
umask 077
bundle_root=${1:?usage: build-watchdog-lab.sh NEW-DIRECTORY [amd64|arm64|both]}
choice=${2:-both}
case $choice in
    amd64|arm64) arches=("$choice") ;;
    both) arches=(amd64 arm64) ;;
    *) echo "Unsupported QA architecture" >&2; exit 2 ;;
esac
mkdir "$bundle_root"
bundle_root=$(cd "$bundle_root" && pwd)
cd "$(dirname "$0")/.."
if [[ $bundle_root == "$PWD"/* ]] && ! git check-ignore -q "$bundle_root/test-output"; then
    echo "Place QA bundles in an ignored output directory or outside the checkout" >&2
    exit 1
fi
if [[ -n $(git status --porcelain) ]]; then
    echo "Build a signed QA release from a clean source revision" >&2
    exit 1
fi
rev=$(git rev-parse HEAD)
private=$(mktemp -d /dev/shm/tikray-image-sign.XXXXXX)
work=$(mktemp -d)
original=
tag=
ctr=
cleanup() {
    if [[ -n $ctr ]]; then docker rm "$ctr" >/dev/null; fi
    if [[ -n $original && -n $tag ]]; then docker tag "$original" "$tag"; fi
    rm -rf -- "$private" "$work"
}
trap cleanup EXIT
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$private/key"
openssl pkey -in "$private/key" -pubout -out "$work/cosign.pub"
sign() {
    openssl dgst -sha256 -sign "$private/key" "$1" | openssl base64 -A >"$1.sig"
    cosign verify-blob --key "$work/cosign.pub" --signature "$1.sig" --offline --insecure-ignore-tlog "$1" >/dev/null 2>&1
}
go build -o "$work/packager" ./cmd/tikray-installer
for arch in "${arches[@]}"; do
    baseline="$work/$arch"
    mkdir "$baseline"
    scripts/build-images.sh "$arch" "$baseline"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "$baseline/offline" ./test/e2e/testdata/image-offline
    for role in tikray tikray-runner; do
        tag=tikray/$role:$arch
        original=$(docker image inspect --format '{{.Id}}' "$tag")
        binary=/tikray-runner
        [[ $role != tikray ]] || binary=/usr/local/bin/tikray
        ctr=$(docker create --platform "linux/$arch" "$tag")
        docker cp "$ctr:$binary" "$baseline/verified-$role"
        docker rm "$ctr" >/dev/null
        ctr=
        info=$(go version -m "$baseline/verified-$role")
        grep -Fq "vcs.revision=$rev" <<<"$info"
        grep -Fq "vcs.modified=false" <<<"$info"
        grep -Fq "GOARCH=$arch" <<<"$info"
        grep -Fq "GOOS=linux" <<<"$info"
        sign "$baseline/$role-$arch.tar"
        for version in 6.0.1 6.0.2; do
            fixture="$baseline/$version"
            ctx="$work/$arch-$role-$version"
            mkdir -p "$ctx" "$fixture"
            echo "$version" >"$ctx/revision"
            {
                echo "FROM $tag"
                echo "LABEL org.opencontainers.image.version=$version"
                echo "COPY revision /m3-qa-image-version"
                if [[ $version == 6.0.2 ]]; then
                    cp "$baseline/offline" "$ctx/offline"
                    executable=/tikray-runner
                    [[ $role != tikray ]] || executable=/usr/local/bin/tikray
                    echo "COPY offline $executable"
                fi
            } >"$ctx/Dockerfile"
            docker buildx build --load -q --platform "linux/$arch" -t "$tag" "$ctx" >/dev/null
            [[ $(docker image inspect -f '{{.Architecture}}' "$tag") == "$arch" ]]
            docker save -o "$fixture/$role-$arch.tar" "$tag"
            sign "$fixture/$role-$arch.tar"
            docker tag "$original" "$tag"
        done
        original=
    done
    ros_arch=x86_64
    versions=(7.25 7.23.8)
    if [[ $arch == arm64 ]]; then ros_arch=arm64; versions=(7.25); fi
    for release in "${versions[@]}"; do
        dest="$bundle_root/$release-$ros_arch"
        mkdir -p "$dest/updates/6.0.1" "$dest/updates/6.0.2"
        cp "$work/cosign.pub" "$dest/"
        cp "$baseline/"*.tar{,.sig} "$dest/"
        for v in 6.0.1 6.0.2; do cp "$baseline/$v/"*.tar{,.sig} "$dest/updates/$v/"; done
        "$work/packager" -version "$release" -arch "$arch" -images "$dest" -key "$dest/cosign.pub" -out "$dest/install.rsc" -uninstall-out "$dest/uninstall.rsc"
        echo "$rev" >"$dest/SOURCE_COMMIT"
        (cd "$dest" && sha256sum cosign.pub install.rsc uninstall.rsc SOURCE_COMMIT *.tar{,.sig} updates/*/*.tar{,.sig} >SHA256SUMS)
        echo "Verified signed image fixtures for $release $ros_arch"
    done
done
