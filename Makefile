.PHONY: test lab-deps lab

test:
	go vet ./... && go test ./...

lab-deps:
	scripts/lab-deps.sh

lab:
	go test -tags lab -timeout 180m ./test/lab/... ./spike/m0/...
