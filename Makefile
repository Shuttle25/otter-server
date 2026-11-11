BUF := go run github.com/bufbuild/buf/cmd/buf@v1.75.0
export PATH := $(shell go env GOPATH)/bin:$(PATH)

VERSION ?=
GOOS_HOST := $(shell go env GOOS)
GOARCH_HOST := $(shell go env GOARCH)
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: gen check test vet build release
gen:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	$(BUF) lint
	$(BUF) generate
vet:
	go vet ./...
test:
	go test -race -count=1 ./...
check: vet test
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=dev-$$(git rev-parse --short HEAD)" -o bin/ ./cmd/...
release:
	@test -n "$(VERSION)" || { echo "set VERSION=x.y.z"; exit 1; }
	mkdir -p dist
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
	    -o dist/otter-node_$(VERSION)_linux_$$arch ./cmd/otter-node || exit 1; \
	done
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" \
	  -o dist/otter-admin_$(VERSION)_$(GOOS_HOST)_$(GOARCH_HOST) ./cmd/otter-admin
	cd dist && sha256sum otter-*_* > SHA256SUMS
