.PHONY: build install clean

GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	go build -ldflags "-X main.version=$(GIT_VERSION) -X main.gitHash=$(GIT_HASH)" -o polaris ./cmd/polaris

install: build
	sudo cp polaris /usr/local/bin/polaris
	@echo "Installed polaris CLI to /usr/local/bin/polaris"

clean:
	rm -f polaris
