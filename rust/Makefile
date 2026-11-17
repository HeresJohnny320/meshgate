VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
# Output goes to the repository's top-level dist/, shared with the Go build.
DIST := ../dist
WINTUN := 0.14.1
export MESHGATE_VERSION := $(VERSION)

# Release targets per asset name. Linux builds are static (musl), like Go's
# CGO_ENABLED=0 binaries, so they run on any distribution.
LINUX := amd64:x86_64-unknown-linux-musl arm64:aarch64-unknown-linux-musl arm:arm-unknown-linux-musleabihf
FREEBSD := amd64:x86_64-unknown-freebsd arm64:aarch64-unknown-freebsd
WINDOWS := amd64:x86_64-pc-windows-gnu arm64:aarch64-pc-windows-gnullvm

.PHONY: build test lab release release-assets clean

build:
	cargo build --release --locked
	mkdir -p $(DIST) && cp target/release/meshgate $(DIST)/meshgate

test:
	cargo fmt --check
	cargo clippy --locked -- -D warnings
	cargo test --locked

# End-to-end test with real WireGuard in network namespaces. The phone
# simulator is the Go one (the phone core stays Go).
lab: build
	cd ../go && go build -o $(abspath $(DIST))/phonesim ./mobile/phonesim
	unshare -r -n -m sh ../test/e2e/lab.sh $(abspath $(DIST)/meshgate) $(abspath $(DIST)/phonesim)

# Needs `cross` (cargo install cross) and Docker or Podman.
release:
	mkdir -p $(DIST)
	for p in $(LINUX) $(FREEBSD); do \
		arch=$${p%%:*}; target=$${p#*:}; \
		case $$target in *freebsd*) os=freebsd;; *) os=linux;; esac; \
		cross build --release --locked --target $$target && \
		cp target/$$target/release/meshgate $(DIST)/meshgate-$$os-$$arch || exit 1; \
	done
	test -f $(DIST)/wintun.zip || curl -fsSL -o $(DIST)/wintun.zip https://www.wintun.net/builds/wintun-$(WINTUN).zip
	for p in $(WINDOWS); do \
		arch=$${p%%:*}; target=$${p#*:}; \
		cross build --release --locked --target $$target && \
		rm -rf $(DIST)/win-$$arch && mkdir -p $(DIST)/win-$$arch && \
		cp target/$$target/release/meshgate.exe $(DIST)/win-$$arch/ && \
		unzip -q -j -o $(DIST)/wintun.zip wintun/bin/$$arch/wintun.dll -d $(DIST)/win-$$arch && \
		(cd $(DIST)/win-$$arch && zip -q -9 ../meshgate-windows-$$arch.zip meshgate.exe wintun.dll) || exit 1; \
	done

# Rebuilds only the given release files over the Go ones, e.g.
# make release-assets ASSETS="meshgate-linux-amd64 meshgate-freebsd-amd64"
release-assets:
	case "$(VERSION)" in v[0-9]*) ;; *) echo "VERSION must be a release tag (vX.Y.Z), got '$(VERSION)'"; exit 1;; esac
	mkdir -p $(DIST)
	for a in $(ASSETS); do \
		target=$$(./target-for.sh $$a) || exit 1; \
		cross build --release --locked --target $$target && \
		cp target/$$target/release/meshgate $(DIST)/$$a || exit 1; \
	done

clean:
	cargo clean
