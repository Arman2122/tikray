# The control plane: one static binary and a CA bundle, so that it can fetch
# releases and subscriptions over HTTPS, on busybox, so that /container/shell
# has an `sh` to run the CLI from. The binary is /usr/local/bin/tikray, which is
# on the base's PATH, so that `tikray status` works at that shell's prompt. Built
# by scripts/build-images.sh, which puts the binary and the bundle next to this
# file's build context.
#
# The default command is `serve`, the long-running service. The other commands
# (`server add`, `status`, `apply`, `core update` and the rest) are the
# entrypoint with other arguments, and the ones that change the state talk to
# the service over its API. M1 ran it as a one-shot CLI, by `/container/set
# cmd=`; the entrypoint takes the arguments, and a `cmd` replaces `serve`.
# RouterOS keeps CMD as the container's default-cmd and runs it while cmd is
# unset. `cmd=""` is not unset: the entrypoint then runs without `serve`, and
# tikray prints its usage and exits 2. `/container/unset <container> cmd` goes
# back to `serve` (CHR 7.25, M2b).
#
# The base is pinned by the digest of its multi-arch index, so that the amd64
# and the arm64 build take their variants of the same release: busybox
# 1.37.0-musl (the newest 1.37 tag when this was pinned; the busybox 1.38 tags
# are newer and not used). Nothing here runs in the build (COPY only), so the
# arm64 image builds without emulation. To move to a newer base, pull the tag
# and put the digest of `docker buildx imagetools inspect busybox:<tag>` here.
FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
COPY tikray /usr/local/bin/tikray
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/usr/local/bin/tikray"]
CMD ["serve"]
