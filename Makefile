.PHONY: test lab-deps lab images

test:
	go vet ./... && go test ./...

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
