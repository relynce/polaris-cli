.PHONY: build install clean test test-short scanner-acceptance

GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	go build -ldflags "-X main.version=$(GIT_VERSION) -X main.gitHash=$(GIT_HASH)" -o rvl ./cmd/rvl

install: build
	sudo cp rvl /usr/local/bin/rvl
	@echo "Installed rvl CLI to /usr/local/bin/rvl"

clean:
	rm -f rvl

# Default test target: short tests across all packages, no acceptance harness.
test test-short:
	go test -short ./...

# Acceptance test: builds the rvl binary, runs it against the Phase 1 fixture,
# and asserts the PRD's integration acceptance criteria. Gated under the
# `acceptance` build tag so `go test -short ./...` does not invoke it.
scanner-acceptance:
	go test -tags=acceptance -v ./internal/scanner/...
