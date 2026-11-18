#!/bin/sh
# Prints the Rust target that builds a release file (asset name).
case "$1" in
meshgate-linux-amd64) echo x86_64-unknown-linux-musl ;;
meshgate-linux-arm64) echo aarch64-unknown-linux-musl ;;
meshgate-linux-arm) echo arm-unknown-linux-musleabihf ;;
meshgate-freebsd-amd64) echo x86_64-unknown-freebsd ;;
meshgate-freebsd-arm64) echo aarch64-unknown-freebsd ;;
meshgate-windows-amd64.zip) echo x86_64-pc-windows-gnu ;;
meshgate-windows-arm64.zip) echo aarch64-pc-windows-gnullvm ;;
*)
	echo "no Rust build for $1 yet (see PARITY.md)" >&2
	exit 1
	;;
esac
