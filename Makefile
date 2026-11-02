.PHONY: check test test-race bench perf lint fmt vet release-check verify-tidy

# Full quality gate
check: fmt vet test

release-check: check
	CGO_ENABLED=0 go test ./...
	@test "$$(go list -m)" = "github.com/peasant-labs/redact"
	@test "$$(go list -m -f '{{.Version}}' github.com/peasant-labs/schema)" = "v0.1.0"
	@! go list -deps ./... | grep -E '^github.com/peasant-labs/peasant($$|/)' >/dev/null
	$(MAKE) verify-tidy

# Run all tests
test:
	go test ./...

# Run all tests with the race detector (manual or CI only)
test-race:
	go test -race ./...

# Reproducible synthetic constructor and first-detection measurements
bench:
	go test -run '^$$' -bench 'Benchmark(RedactorConstruction|FirstDetection)$$' -benchmem -count=6

# Timings are a required local release gate; CI uses allocation-only budgets
# because routed runners do not share a stable CPU (see docs/performance.md).
perf:
	go run ./cmd/engine-perf $(PERF_ARGS)

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
