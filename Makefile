.PHONY: check test lint fmt vet release-check verify-tidy

# Full quality gate
check: fmt vet test

release-check: check
	CGO_ENABLED=0 go test ./...
	@test "$$(go list -m)" = "github.com/peasant-labs/redact"
	@! go list -deps ./... | grep -E '^github.com/peasant-labs/peasant($$|/)' >/dev/null
	$(MAKE) verify-tidy

# Run all tests with race detector
test:
	go test -race ./...

# Run go vet
vet:
	go vet ./...

# Check formatting
fmt:
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "Files not formatted:"; \
		gofmt -l .; \
		exit 1; \
	fi

# Auto-format all files
fmt-fix:
	gofmt -w .

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
