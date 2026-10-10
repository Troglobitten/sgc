# Build and check commands for SGC. Run them on Linux (the build box or CI).
#
#   make check   format check, static analysis and tests
#   make build   binaries for PC (amd64) and Raspberry Pi (arm64) in bin/

# Static binaries with no C dependencies: one file that runs on any Debian
# install of the right architecture.
export CGO_ENABLED := 0

# -trimpath keeps local folder names out of the binary; -s -w drops debug
# symbols to keep the download small.
BUILD_FLAGS := -trimpath -ldflags "-s -w"

.PHONY: build check fmt-check vet test clean

build:
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o bin/sgc-linux-amd64 ./cmd/sgc
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o bin/sgc-linux-arm64 ./cmd/sgc

check: fmt-check vet test

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf bin
