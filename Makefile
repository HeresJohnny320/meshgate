# meshgate is built from rust/; releases are the Rust build only. The old Go
# version stays in go/ for comparing (go, mixed-lab, upgrade-test, bench).

.PHONY: build test lab release bench go rust rust-lab mixed-lab upgrade-test clean

build test lab release:
	$(MAKE) -C rust $@

# Both builds side by side in dist/, for comparing.
go:
	$(MAKE) -C go build
	cp dist/meshgate dist/meshgate-go

rust:
	$(MAKE) -C rust build
	cp dist/meshgate dist/meshgate-rust

# The end-to-end lab against the Rust build.
rust-lab:
	$(MAKE) -C rust lab

# The lab with Go and Rust nodes in one mesh (both ways round).
mixed-lab: go rust
	test/e2e/mixed.sh dist/meshgate-go dist/meshgate-rust

# A running Go node switches to Rust in place (and back).
upgrade-test: go rust
	unshare -r -n -m sh test/e2e/upgrade.sh $(abspath dist/meshgate-go) $(abspath dist/meshgate-rust)

# RAM and CPU of the Go build against the Rust build (see bench/bench.sh).
bench: go rust
	bench/bench.sh compare dist/meshgate-go dist/meshgate-rust

clean:
	$(MAKE) -C go clean
	-$(MAKE) -C rust clean
