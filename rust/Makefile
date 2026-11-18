VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
# Output goes to the repository's top-level dist/, shared with the Go build.
DIST := ../dist
WINTUN := 0.14.1
export MESHGATE_VERSION := $(VERSION)
# Shared files under go/ that the binary embeds (see build.rs, Cross.toml).
export MESHGATE_GO_DIR := $(abspath ../go)

# Release targets per asset name. Linux builds are static (musl), like Go's
# CGO_ENABLED=0 binaries, so they run on any distribution.
LINUX := amd64:x86_64-unknown-linux-musl arm64:aarch64-unknown-linux-musl arm:arm-unknown-linux-musleabihf
FREEBSD := amd64:x86_64-unknown-freebsd arm64:aarch64-unknown-freebsd
WINDOWS := amd64:x86_64-pc-windows-gnu arm64:aarch64-pc-windows-gnullvm

# Builds $$target and sets $$out to the folder with the binary: cross for most
# targets, build-extra.sh for the two cross has no image for (pfSense arm64,
# Windows arm64). Each cross target gets its own target dir: the images have
# different glibc versions, and build scripts compiled in one do not run in
# the next.
XBUILD = case $$target in \
	aarch64-unknown-freebsd|aarch64-pc-windows-gnullvm) ./build-extra.sh $$target && out=target/$$target/release;; \
	*) cross build --release --locked --target $$target --target-dir target/cross-$$target && \
		out=target/cross-$$target/$$target/release;; esac

.PHONY: build test lab release release-darwin android-core ios-core clean

build:
	cargo build --release --locked
	mkdir -p $(DIST) && cp target/release/meshgate $(DIST)/meshgate

test:
	cargo fmt --check
	cargo clippy --locked -- -D warnings
	cargo test --locked

# End-to-end test with real WireGuard in network namespaces, with the phone
# engine run by the phone simulator.
lab: build
	cargo build --release --locked --bin phonesim
	cp target/release/phonesim $(DIST)/phonesim
	unshare -r -n -m sh ../test/e2e/lab.sh $(abspath $(DIST)/meshgate) $(abspath $(DIST)/phonesim)

# Every Linux, FreeBSD/pfSense and Windows release file (the same names the
# Go build used, so nodes update to them). Needs `cross` (cargo install cross)
# and Docker or Podman, plus clang, lld and llvm-ar for build-extra.sh.
release:
	mkdir -p $(DIST)
	for p in $(LINUX) $(FREEBSD); do \
		arch=$${p%%:*}; target=$${p#*:}; \
		case $$target in *freebsd*) os=freebsd;; *) os=linux;; esac; \
		{ $(XBUILD); } && \
		cp $$out/meshgate $(DIST)/meshgate-$$os-$$arch || exit 1; \
	done
	test -f $(DIST)/wintun.zip || curl -fsSL -o $(DIST)/wintun.zip https://www.wintun.net/builds/wintun-$(WINTUN).zip
	for p in $(WINDOWS); do \
		arch=$${p%%:*}; target=$${p#*:}; \
		{ $(XBUILD); } && \
		mkdir -p $(DIST)/win-$$arch && \
		cp $$out/meshgate.exe $(DIST)/win-$$arch/ && \
		unzip -q -j -o $(DIST)/wintun.zip wintun/bin/$$arch/wintun.dll -d $(DIST)/win-$$arch && \
		(cd $(DIST)/win-$$arch && zip -q -9 -FS ../meshgate-windows-$$arch.zip meshgate.exe wintun.dll) || exit 1; \
	done

# macOS release files (new with the Rust port; the Go build had none). Needs
# macOS with Xcode and both Rust darwin targets.
release-darwin:
	mkdir -p $(DIST)
	for p in amd64:x86_64-apple-darwin arm64:aarch64-apple-darwin; do \
		arch=$${p%%:*}; target=$${p#*:}; \
		MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --locked --target $$target && \
		cp target/$$target/release/meshgate $(DIST)/meshgate-darwin-$$arch || exit 1; \
	done

# The Android app's engine (libmeshcore.so per ABI). Needs cargo-ndk
# (cargo install cargo-ndk), ANDROID_NDK_HOME and the Rust Android targets.
JNILIBS := ../go/mobile/android/app/src/main/jniLibs
ANDROID_ABIS := arm64-v8a armeabi-v7a x86_64 x86
android-core:
	cargo ndk $(foreach a,$(ANDROID_ABIS),-t $(a)) -P 26 build --release --locked -p meshcore
	for abi in $(ANDROID_ABIS); do \
		case $$abi in arm64-v8a) t=aarch64-linux-android;; armeabi-v7a) t=armv7-linux-androideabi;; \
			x86_64) t=x86_64-linux-android;; x86) t=i686-linux-android;; esac; \
		mkdir -p $(JNILIBS)/$$abi && cp target/$$t/release/libmeshcore.so $(JNILIBS)/$$abi/ || exit 1; \
	done

# The iOS app's engine: Meshcore.xcframework (static libmeshcore.a plus the
# C header and module map; Swift wrappers in go/mobile/ios/Shared/Meshcore.swift).
# Needs macOS with Xcode and the Rust iOS targets.
XCFRAMEWORK := ../go/mobile/ios/Meshcore.xcframework
ios-core:
	for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do \
		IPHONEOS_DEPLOYMENT_TARGET=16.0 cargo build --release --locked -p meshcore --target $$t || exit 1; \
	done
	mkdir -p target/ios-sim
	lipo -create target/aarch64-apple-ios-sim/release/libmeshcore.a target/x86_64-apple-ios/release/libmeshcore.a \
		-output target/ios-sim/libmeshcore.a
	rm -rf $(XCFRAMEWORK)
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libmeshcore.a -headers meshcore/include \
		-library target/ios-sim/libmeshcore.a -headers meshcore/include \
		-output $(XCFRAMEWORK)

clean:
	cargo clean
	rm -rf $(JNILIBS) $(XCFRAMEWORK)
