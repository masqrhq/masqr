# masqr — developer Makefile
#
# Mirrors what CI runs so `make all` locally catches the same issues that
# would fail on PR. Most targets are thin wrappers; the value is having
# one canonical command per check so contributors don't have to remember
# the exact flag combination.

# Override on the command line if needed: `make BIN=foo build`.
BIN ?= masqr

GO       ?= go
GOFMT    ?= gofmt
GOFLAGS  ?=
LDFLAGS  ?= -s -w
TESTARGS ?= -race -count=1 -timeout 5m

# Stamp main.version. Release builds pass the git tag via -ldflags
# (-X main.version=<tag>); locally we derive a descriptive version from git
# (e.g. v0.3.0-1-ga1fbfde) so `make build` isn't a bare "dev". Falls back to
# "dev" outside a git checkout (tarball builds, no tags yet).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: help all build demo test vet fmt fmt-check lint tidy clean lfs-check lfs-pull

help:	## Show this list of targets
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ \
	  { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

all: vet fmt-check test build  ## Run vet + fmt-check + test, then build the binary

build: lfs-check	## Compile ./masqr
	$(GO) build $(GOFLAGS) \
	  -trimpath \
	  -ldflags '$(LDFLAGS) -X main.version=$(VERSION)' \
	  -o $(BIN) .

lfs-check:	## Fail if the .ocr/ Git LFS objects are still pointer stubs
	@stubs=$$(grep -rlIs '^version https://git-lfs.github.com/spec/' .ocr 2>/dev/null); \
	if [ -n "$$stubs" ]; then \
	  echo "Git LFS objects are still pointer stubs — not pulled:"; \
	  echo "$$stubs" | sed 's/^/  /'; \
	  echo "go:embed would bake these ~130-byte stubs into the binary and OCR"; \
	  echo "fails silently at runtime. Run 'make lfs-pull' (or git lfs pull)."; \
	  exit 1; \
	fi

lfs-pull:	## Install LFS hooks and fetch the real .ocr/ models + runtime libs
	git lfs install
	git lfs pull

demo:	## Compile ./demo/demo (log-replay tool)
	$(GO) build $(GOFLAGS) -o demo/demo ./demo

test:	## Run the full test suite (race, no cache)
	$(GO) test $(TESTARGS) ./...

vet:	## go vet
	$(GO) vet ./...

fmt:	## Auto-format every .go file in place
	$(GOFMT) -w .

fmt-check:	## Fail if any .go file isn't gofmt-clean
	@unformatted=$$($(GOFMT) -l .); \
	if [ -n "$$unformatted" ]; then \
	  echo "gofmt found unformatted files:"; \
	  echo "$$unformatted"; \
	  exit 1; \
	fi

lint:	## staticcheck (assumes it's on PATH; install: go install honnef.co/go/tools/cmd/staticcheck@latest)
	@command -v staticcheck >/dev/null 2>&1 || { \
	  echo "staticcheck not installed; run: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	  exit 1; \
	}
	staticcheck ./...

tidy:	## go mod tidy + verify it didn't change anything in CI
	$(GO) mod tidy
	@git diff --exit-code go.mod go.sum > /dev/null 2>&1 || { \
	  echo "go.mod / go.sum changed after 'go mod tidy' — commit the result"; \
	  exit 1; \
	}

clean:	## Remove built binaries
	rm -f $(BIN) demo/demo
	rm -rf dist/
