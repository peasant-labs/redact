.PHONY: check test lint fmt vet

# Full quality gate
check: fmt vet test

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
	go mod tidy
	@if ! git diff --quiet go.mod go.sum; then \
		echo "::error::go.mod or go.sum is dirty after go mod tidy"; \
		git diff go.mod go.sum; \
		exit 1; \
	fi
