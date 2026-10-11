# Build and check commands for SGC. Run them on Linux (the build box or CI).
#
#   make check   format check, static analysis, shell script checks and tests
#   make web     the browser interface, into web/dist (embedded into sgc)
#   make build   programs for PC (amd64) and Raspberry Pi (arm64) in bin/
#   make dist    the files that make up a release, in dist/

# Static binaries with no C dependencies: one file that runs on any Debian
# install of the right architecture.
export CGO_ENABLED := 0

# -trimpath keeps local folder names out of the binary; -s -w drops debug
# symbols to keep the download small.
BUILD_FLAGS := -trimpath -ldflags "-s -w"

# Named explicitly rather than "./...": that would also walk through the
# thousands of files in web/node_modules.
GO_PACKAGES := . ./cmd/... ./internal/... ./web
GO_SOURCES := cmd internal web/embed.go version.go version_test.go

SHELL_SCRIPTS := installer/install.sh scripts/*.sh test/e2e/vm/*.sh test/e2e/installer/*.sh

.PHONY: build web dist check fmt-check vet shellcheck test clean

# Scripts are run through bash explicitly: files committed from Windows carry
# no executable bit.
web:
	bash scripts/build-web.sh

build: web
	for arch in amd64 arm64; do \
		for program in sgc sgc-helper; do \
			GOOS=linux GOARCH=$$arch go build $(BUILD_FLAGS) -o bin/$$program-linux-$$arch ./cmd/$$program || exit 1; \
		done; \
	done

dist:
	bash scripts/dist.sh dist

check: fmt-check vet shellcheck test

fmt-check:
	@unformatted="$$(gofmt -l $(GO_SOURCES))"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	go vet $(GO_PACKAGES)

shellcheck:
	shellcheck $(SHELL_SCRIPTS)

test:
	go test $(GO_PACKAGES)

clean:
	rm -rf bin dist
