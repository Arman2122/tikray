# The data-plane runner: one static binary, no xray and no geo data (those live
# on the router's disk). Built by scripts/build-images.sh, which puts the
# binary next to this file's build context.
FROM scratch
ENV GOMEMLIMIT=24MiB
COPY tikray-runner /tikray-runner
ENTRYPOINT ["/tikray-runner"]
