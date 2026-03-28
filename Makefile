GO ?= go
BIN ?= secssh
PKG ?= ./...
OUT_DIR ?= bin
DIST_DIR ?= dist
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
PLATFORM ?=
LDFLAGS ?= -s -w -X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT)' -X 'main.buildTime=$(BUILD_TIME)'

.PHONY: help fmt test vet build build-one build-cross release run tidy clean

help:
	@echo "Targets:"
	@echo "  make fmt         - gofmt all Go files"
	@echo "  make test        - run all tests"
	@echo "  make vet         - run go vet"
	@echo "  make build       - build local binary to ./$(OUT_DIR)/$(BIN)-$(VERSION)"
	@echo "  make build-one   - build one platform (PLATFORM=os/arch or GOOS/GOARCH)"
	@echo "  make build-cross - cross-compile for PLATFORMS to ./$(DIST_DIR)"
	@echo "  make release     - clean + build-cross"
	@echo "  make run         - run secssh (interactive mode)"
	@echo "  make tidy        - tidy go modules"
	@echo "  make clean       - remove build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make build-one PLATFORM=linux/amd64"
	@echo "  make build-one GOOS=darwin GOARCH=arm64 VERSION=v0.1.0"
	@echo "  make build-cross VERSION=v0.1.0"

fmt:
	@$(GO) fmt $(PKG)

test:
	@$(GO) test $(PKG)

vet:
	@$(GO) vet $(PKG)

build:
	@mkdir -p $(OUT_DIR)
	@out="$(OUT_DIR)/$(BIN)-$(VERSION)"; \
	echo "==> local $(GOOS)/$(GOARCH) -> $$out"; \
	CGO_ENABLED=0 GOOS="$(GOOS)" GOARCH="$(GOARCH)" $(GO) build -ldflags "$(LDFLAGS)" -o "$$out" .

build-one:
	@set -e; \
	if [ -n "$(PLATFORM)" ]; then \
		os="$${PLATFORM%/*}"; \
		arch="$${PLATFORM#*/}"; \
	else \
		os="$(GOOS)"; \
		arch="$(GOARCH)"; \
	fi; \
	ext=""; \
	if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
	mkdir -p "$(DIST_DIR)"; \
	out="$(DIST_DIR)/$(BIN)-$(VERSION)-$$os-$$arch$$ext"; \
	echo "==> $$os/$$arch -> $$out"; \
	CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GO) build -ldflags "$(LDFLAGS)" -o "$$out" .

build-cross:
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for platform in $(PLATFORMS); do \
		os="$${platform%/*}"; \
		arch="$${platform#*/}"; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="$(DIST_DIR)/$(BIN)-$(VERSION)-$$os-$$arch$$ext"; \
		echo "==> $$os/$$arch -> $$out"; \
		GOOS="$$os" GOARCH="$$arch" CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o "$$out" .; \
	done

release: clean build-cross

run:
	@$(GO) run .

tidy:
	@$(GO) mod tidy

clean:
	@rm -rf $(OUT_DIR) $(DIST_DIR)
