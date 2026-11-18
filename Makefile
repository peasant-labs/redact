.PHONY: check test test-nore2 bench lint fmt vet release-check verify-tidy check-unstring unstring-update

# Static guard against stringly-typed values. Pin the published tool here.
# The binary it scans with is ast-grep 0.51.2 on PATH.
UNSTRING ?= go run github.com/peasant-labs/infra/unstring/cmd/unstring@v0.0.4

# Full quality gate. The guard runs last and fails the gate when the tree
# is not the committed baseline.
check: fmt vet test test-nore2 check-unstring

release-check: check
	CGO_ENABLED=0 go test ./...
	@test "$$(go list -m)" = "github.com/peasant-labs/redact"
	@test "$$(go list -m -f '{{.Version}}' github.com/peasant-labs/schema)" = "v0.1.0"
	@! go list -deps ./... | grep -E '^github.com/peasant-labs/peasant($$|/)' >/dev/null
	$(MAKE) verify-tidy

# Run all tests with race detector
test:
	go test -race ./...

# Exercise the stdlib fallback independently and in every quality gate
test-nore2:
	go test -tags no_re2 -race ./...

# Reproducible synthetic constructor and first-detection measurements
bench:
	go test -run '^$$' -bench 'Benchmark(RedactorConstruction|FirstDetection)$$' -benchmem -count=6

# Run go vet
vet:
	go vet ./...

# Check formatting
fmt:
	@set -e; \
	files="$$(git ls-files -z -- '*.go' | xargs -0 gofmt -l --)"; \
	if [ -n "$$files" ]; then \
		echo "Files not formatted:"; \
		printf '%s\n' "$$files"; \
		exit 1; \
	fi

# Auto-format all files
fmt-fix:
	git ls-files -z -- '*.go' | xargs -0 gofmt -w --

# Build (verify compilation)
build:
	go build ./...

# Clean test cache
clean:
	go clean -testcache

# Tidy module
tidy:
	go mod tidy

# Compare the tree with the committed unstring baseline.
check-unstring:
	$(UNSTRING) check

# Lower a baseline count, drop an empty entry, or follow a rename. Never raises.
unstring-update:
	$(UNSTRING) update

# Verify go.sum is current
verify-tidy:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	cp go.mod go.sum "$$tmp/"; \
	go mod tidy; \
	if ! cmp -s go.mod "$$tmp/go.mod" || ! cmp -s go.sum "$$tmp/go.sum"; then \
		echo "::error::go.mod or go.sum is dirty after go mod tidy"; \
		diff -u "$$tmp/go.mod" go.mod || true; \
		diff -u "$$tmp/go.sum" go.sum || true; \
		exit 1; \
	fi
