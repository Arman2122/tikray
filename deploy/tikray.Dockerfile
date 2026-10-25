# The control plane: one static binary and a CA bundle, so that it can fetch
# releases over HTTPS. Built by scripts/build-images.sh, which puts both next to
# this file's build context. The default command is `serve`, the long-running
# service; the other commands (`server add`, `status`, `apply`, `core update`
# and the rest) are the entrypoint with other arguments, and the ones that
# change the state talk to the service over its API. M1 ran it as a one-shot
# CLI, by `/container/set cmd=`; the entrypoint takes the arguments.
FROM scratch
COPY tikray /tikray
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/tikray"]
