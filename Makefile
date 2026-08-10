# cinc-zero build automation

BINARY      := cinc-server-ng
CMD_PKG     := ./cmd/cinc-server-ng
LDFLAGS_PKG := main
DIST_DIR    ?= dist
PLATFORMS   := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

# Build metadata — override on the command line if needed.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%d)

LDFLAGS := -X $(LDFLAGS_PKG).version=$(VERSION) \
           -X $(LDFLAGS_PKG).commit=$(COMMIT) \
           -X $(LDFLAGS_PKG).buildDate=$(BUILD_DATE)

.PHONY: all build dist install test conformance differential vet fmt tidy clean run run-dev dev-db dev-db-reset run-dev-sqlite help

all: build

## build: compile the cinc-zero binary with version metadata
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_PKG)

## dist: build release archives for Linux and macOS
dist:
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)
	for platform in $(PLATFORMS); do \
		goos=$${platform%/*}; \
		goarch=$${platform#*/}; \
		name="$(BINARY)_$(VERSION)_$${goos}_$${goarch}"; \
		mkdir -p "$(DIST_DIR)/$$name"; \
		CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch go build -trimpath -ldflags "$(LDFLAGS) -s -w" -o "$(DIST_DIR)/$$name/$(BINARY)" $(CMD_PKG); \
		tar -C "$(DIST_DIR)" -czf "$(DIST_DIR)/$$name.tar.gz" "$$name"; \
		rm -rf "$(DIST_DIR)/$$name"; \
	done
	cd "$(DIST_DIR)" && shasum -a 256 *.tar.gz > SHA256SUMS

## install: install cinc-zero into the Go bin directory
install:
	go install -ldflags "$(LDFLAGS)" $(CMD_PKG)

## test: run the test suite
test:
	go test ./... -race -cover

## conformance: drive the real knife CLI (from Cinc Workstation) against
## cinc-zero; needs knife installed (see https://omnitruck.cinc.sh/install.sh)
conformance:
	CINC_ZERO_REQUIRE_CONFORMANCE=1 go test -tags conformance ./conformance/ -v

## differential: compare responses against a real Chef Infra Server. Needs both
## servers running and DIFF_* configured; see .github/workflows/differential.yml.
differential:
	go test -tags differential ./differential/ -v -timeout 30m

## vet: run go vet across all packages
vet:
	go vet ./...

## fmt: format all Go source
fmt:
	gofmt -w .

## tidy: tidy go module dependencies
tidy:
	go mod tidy

## clean: remove build artifacts
clean:
	rm -rf $(BINARY) $(DIST_DIR)
	go clean

## run: build and run cinc-zero (pass flags via ARGS="...")
run: build
	./$(BINARY) $(ARGS)

## run-dev: build and run cinc-zero pre-loaded with the dev/test-repo seed (no auth, key written to ./dev-admin.pem)
run-dev: build
	./$(BINARY) --no-auth --state dev/test-repo --key-out dev-admin.pem $(ARGS)

DEV_DB   ?= dev/cinc-dev.db
SEED_GEN ?= dev/seed.gen

## dev-db: bake the committed base seed plus the generated expansion into $(DEV_DB),
## additively — re-running preserves the existing pivotal key (so a console's webui
## key keeps working) and any runtime data. Use dev-db-reset for a clean rebuild.
dev-db: build
	./$(BINARY) --storage sqlite --db $(DEV_DB) --state dev/test-repo --key-out dev-admin.pem --init
	rm -rf $(SEED_GEN)
	go run ./cmd/seedgen -base dev/test-repo -out $(SEED_GEN)
	./$(BINARY) --storage sqlite --db $(DEV_DB) --state $(SEED_GEN) --key-out dev-admin.pem --init
	@sqlite3 $(DEV_DB) "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true

## dev-db-reset: delete the dev DB and rebuild it from scratch (rotates the pivotal key)
dev-db-reset: build
	rm -f $(DEV_DB) $(DEV_DB)-wal $(DEV_DB)-shm
	$(MAKE) dev-db

## run-dev-sqlite: serve the dev SQLite database (auth on, for cinc-console); builds it first if missing
run-dev-sqlite: build
	@test -f $(DEV_DB) || $(MAKE) dev-db
	./$(BINARY) --storage sqlite --db $(DEV_DB) --key-out dev-admin.pem $(ARGS)

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
