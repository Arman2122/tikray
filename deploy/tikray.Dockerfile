# The control plane: one static binary and a CA bundle, so that it can fetch
# releases over HTTPS. Built by scripts/build-images.sh, which puts both next to
# this file's build context. M1 runs it as a one-shot CLI, by `/container/set
# cmd=`; the entrypoint takes the arguments.
FROM scratch
COPY tikray /tikray
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/tikray"]
