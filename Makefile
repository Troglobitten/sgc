# Build and check commands for SGC. Run them on Linux (the build box or CI).
#
#   make check   format check, static analysis, shell script checks and tests
#   make build   binaries for PC (amd64) and Raspberry Pi (arm64) in bin/
#   make dist    the files that make up a release, in dist/

# Static binaries with no C dependencies: one file that runs on any Debian
# install of the right architecture.
export CGO_ENABLED := 0

# -trimpath keeps local folder names out of the binary; -s -w drops debug
# symbols to keep the download small.
BUILD_FLAGS := -trimpath -ldflags "-s -w"

SHELL_SCRIPTS := installer/install.sh scripts/*.sh test/e2e/vm/*.sh test/e2e/installer/*.sh

.PHONY: build dist check fmt-check vet shellcheck test clean

build:
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o bin/sgc-linux-amd64 ./cmd/sgc
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o bin/sgc-linux-arm64 ./cmd/sgc

# Run through bash explicitly: files committed from Windows carry no
# executable bit.
dist:
	bash scripts/dist.sh dist

check: fmt-check vet shellcheck test

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	go vet ./...

shellcheck:
	shellcheck $(SHELL_SCRIPTS)

test:
	go test ./...

clean:
	rm -rf bin dist
