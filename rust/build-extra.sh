#!/bin/sh
# Builds the release targets that `cross` has no image for, on Linux x86_64:
#   aarch64-unknown-freebsd     pfSense arm64 (Netgate 1100/2100). A tier 3
#                               Rust target: pinned nightly + build-std,
#                               clang/lld against a FreeBSD base.txz sysroot.
#   aarch64-pc-windows-gnullvm  Windows arm64, linked with llvm-mingw.
# Needs curl, tar, xz, sha256sum, clang, lld and llvm-ar (apt: clang lld llvm).
# Downloads are pinned and checked against SHA-256. The binary lands where
# cargo puts it: target/<target>/release/.
set -eu

NIGHTLY=nightly-2026-11-01
FREEBSD=14.4-RELEASE
FREEBSD_BASE_SHA=c456bf75ee3d0b4da0b0b527402b0a9e61497f02756b2cc5801b51e80b3f90c4
LLVM_MINGW=20261104
LLVM_MINGW_SHA=919380403de87dca3c581c2053230cd298af5e891286628ba0613b7fed370926

target=${1:?usage: build-extra.sh <target>}
cd "$(dirname "$0")"
tc=$PWD/target/toolchains
mkdir -p "$tc"

# fetch <url> <sha256> <file>: download once, refuse a wrong checksum.
fetch() {
	if [ ! -f "$3" ]; then
		curl -fsSL -o "$3.part" "$1"
		mv "$3.part" "$3"
	fi
	echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch: $1" >&2; exit 1; }
}

case "$target" in
aarch64-unknown-freebsd)
	root=$tc/freebsd-arm64-$FREEBSD
	if [ ! -d "$root/usr/lib" ]; then
		fetch "https://download.freebsd.org/releases/arm64/aarch64/$FREEBSD/base.txz" \
			"$FREEBSD_BASE_SHA" "$tc/freebsd-arm64-$FREEBSD-base.txz"
		mkdir -p "$root"
		# Hard links to files outside these folders make tar exit non-zero;
		# what the build needs is libc and the headers.
		tar -xJf "$tc/freebsd-arm64-$FREEBSD-base.txz" -C "$root" \
			--wildcards './lib/*' './usr/lib/*' './usr/include/*' ||
			{ test -f "$root/usr/lib/libc.so" && test -f "$root/usr/include/stdio.h"; }
	fi
	cc=$tc/aarch64-unknown-freebsd-clang
	cat >"$cc" <<EOF
#!/bin/sh
exec clang --target=aarch64-unknown-freebsd14 --sysroot=$root -fuse-ld=lld "\$@"
EOF
	chmod +x "$cc"
	rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src
	CARGO_TARGET_AARCH64_UNKNOWN_FREEBSD_LINKER=$cc \
	CC_aarch64_unknown_freebsd=$cc \
	AR_aarch64_unknown_freebsd=llvm-ar \
		cargo "+$NIGHTLY" build -Zbuild-std=std,panic_abort --release --locked --target "$target"
	;;
aarch64-pc-windows-gnullvm)
	dir=$tc/llvm-mingw-$LLVM_MINGW-ucrt-ubuntu-22.04-x86_64
	if [ ! -d "$dir/bin" ]; then
		fetch "https://github.com/mstorsjo/llvm-mingw/releases/download/$LLVM_MINGW/llvm-mingw-$LLVM_MINGW-ucrt-ubuntu-22.04-x86_64.tar.xz" \
			"$LLVM_MINGW_SHA" "$tc/llvm-mingw-$LLVM_MINGW.tar.xz"
		tar -xJf "$tc/llvm-mingw-$LLVM_MINGW.tar.xz" -C "$tc"
	fi
	rustup target add "$target"
	PATH=$dir/bin:$PATH \
	CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER=aarch64-w64-mingw32-clang \
	CC_aarch64_pc_windows_gnullvm=aarch64-w64-mingw32-clang \
	AR_aarch64_pc_windows_gnullvm=llvm-ar \
		cargo build --release --locked --target "$target"
	;;
*)
	echo "build-extra.sh: $target is built with cross" >&2
	exit 1
	;;
esac
