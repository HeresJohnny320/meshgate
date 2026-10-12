VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/heresjohnny320/meshgate/internal/agent.Version=$(VERSION)
DIST := dist
WINTUN := 0.14.1

.PHONY: build test lab release android-core ios-core clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/meshgate ./cmd/meshgate

test:
	go vet ./...
	go test ./...

# End-to-end test with real WireGuard in network namespaces (no root needed
# on kernels that allow unprivileged user namespaces).
lab: build
	go build -o $(DIST)/phonesim ./mobile/phonesim
	unshare -r -n -m sh test/e2e/lab.sh $(abspath $(DIST)/meshgate) $(abspath $(DIST)/phonesim)

release:
	for arch in amd64 arm64 arm; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/meshgate-linux-$$arch ./cmd/meshgate; \
	done
	# FreeBSD / pfSense (Netgate appliances are amd64 or arm64)
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=freebsd GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/meshgate-freebsd-$$arch ./cmd/meshgate; \
	done
	# Windows: zip with the signed wintun.dll next to meshgate.exe
	test -f $(DIST)/wintun.zip || curl -fsSL -o $(DIST)/wintun.zip https://www.wintun.net/builds/wintun-$(WINTUN).zip
	for arch in amd64 arm64; do \
		rm -rf $(DIST)/win-$$arch && mkdir -p $(DIST)/win-$$arch && \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/win-$$arch/meshgate.exe ./cmd/meshgate && \
		unzip -q -j -o $(DIST)/wintun.zip wintun/bin/$$arch/wintun.dll -d $(DIST)/win-$$arch && \
		(cd $(DIST)/win-$$arch && zip -q -9 ../meshgate-windows-$$arch.zip meshgate.exe wintun.dll); \
	done

# Mobile cores (need gomobile: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init)
android-core:
	gomobile bind -target=android -androidapi 26 -javapkg=dev.meshgate -ldflags '$(LDFLAGS)' -o mobile/android/app/libs/meshcore.aar ./mobile/core

ios-core:
	gomobile bind -target=ios -iosversion 16.0 -ldflags '$(LDFLAGS)' -o mobile/ios/Meshcore.xcframework ./mobile/core

clean:
	rm -rf $(DIST) mobile/android/app/libs/meshcore.aar mobile/ios/Meshcore.xcframework
