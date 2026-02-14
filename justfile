# Default recipe
default: build

# Build the binary
build:
    mkdir -p bin
    go build -o bin/timebound-iam ./cmd/timebound-iam

# Run all tests
test:
    go test -v -count=1 ./...

# Run tests with coverage
cover:
    go test -coverprofile=coverage.out ./...
    go tool cover -func=coverage.out

# Format code
fmt:
    gofmt -w .
    goimports -w .

# Lint
vet:
    go vet ./...

# Clean build artifacts
clean:
    rm -rf bin coverage.out
