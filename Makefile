.PHONY: test race ui build installer lab-deps lab images

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

test:
	go vet ./... && go test ./...

race:
	go test -race -count=1 ./cmd/... ./internal/...

# Type-check and rebuild the embedded Svelte 5 Web UI into internal/ui/dist/.
# Requires Node.js 20+ and npm.
ui:
	cd web && npm run check && npm run build

# Build static Linux binaries for the host architecture into out/.
build:
	mkdir -p out
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.buildVersion=$(VERSION)" -o out/tikray ./cmd/tikray
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o out/tikray-runner ./cmd/tikray-runner
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o out/tikray-installer ./cmd/tikray-installer

# Generate the standalone RouterOS uninstaller script into out/uninstall.rsc.
installer:
	mkdir -p out
	go run ./cmd/tikray-installer -uninstall-out out/uninstall.rsc

lab-deps:
	scripts/lab-deps.sh

# Lab tests share one host network and QEMU taps, so packages run one at a
# time (-p 1), never from the test cache (-count=1: results depend on the
# current RouterOS channels and the newest xray release), with room for arm64
# emulation. -v shows the harness's notes, such as a push it had to retry, in
# a run that passes: they are t.Logf lines, and harness.log goes with the work
# dir on a pass. Needs root.
lab:
	go test -tags lab -p 1 -count=1 -v -timeout 420m ./test/lab/... ./spike/m0/... ./test/e2e/...

# RouterOS image archives for both architectures, in out/. Needs Docker with
# the classic image store (see scripts/build-images.sh).
images:
	scripts/build-images.sh amd64
	scripts/build-images.sh arm64
