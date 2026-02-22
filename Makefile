.PHONY: build install clean

GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

build:
	go build -ldflags "-X main.gitHash=$(GIT_HASH)" -o polaris .

install: build
	sudo cp polaris /usr/local/bin/polaris
	@echo "Installed polaris CLI to /usr/local/bin/polaris"

clean:
	rm -f polaris
