# The data-plane runner: one static binary and a root CA bundle, with no shell,
# no xray and no geo data (those live on the router's disk). Built by
# scripts/build-images.sh, which puts both files next to this build context.
# xray-core executes inside this FROM scratch namespace and reads
# /etc/ssl/certs/ca-certificates.crt to verify TLS outbounds, DoH resolvers and
# HTTPS observatory probes.
FROM scratch
ENV GOMEMLIMIT=24MiB
COPY tikray-runner /tikray-runner
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/tikray-runner"]
