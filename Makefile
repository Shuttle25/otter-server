BUF := go run github.com/bufbuild/buf/cmd/buf@v1.75.0
export PATH := $(shell go env GOPATH)/bin:$(PATH)

.PHONY: gen check test vet build
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
	CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...
