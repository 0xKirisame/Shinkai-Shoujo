.PHONY: all build test clean run-init help

BINARY      := shinkai-shoujo
CMD         := cmd/shinkai-shoujo/main.go
BUILD_FLAGS := -trimpath

all: build

## build: Compile the binary
build:
	go build $(BUILD_FLAGS) -o $(BINARY) $(CMD)

## test: Run all tests
test:
	go test ./...

## test-verbose: Run all tests with verbose output
test-verbose:
	go test -v ./...

## test-race: Run tests with race detector
test-race:
	go test -race ./...

## tidy: Tidy go.mod and go.sum
tidy:
	go mod tidy

## vet: Run go vet
vet:
	go vet ./...

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)

## run-init: Initialize default config
run-init:
	go run $(CMD) init

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //'
