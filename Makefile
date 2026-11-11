VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X main.Version=$(VERSION)

.PHONY: build build-mac test e2e clean

# Build for this machine
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/hat ./cmd/hat

# Build the Apple Silicon binary (works from Linux or macOS)
build-mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/hat-darwin-arm64 ./cmd/hat

test:
	go vet ./...
	go test -race -short ./...

# End-to-end VM test with a fake vfkit (Linux only)
e2e:
	go test -count=1 ./internal/e2e/

clean:
	rm -rf dist
