# otter-server

The OtterMSG node and admin tooling (Go module `ottermsg/server`). It owns the shared protobuf schemas in `proto/` and the cross-language test vectors in `testdata/vectors/`. Run `make gen` to regenerate protobuf code (via buf), `make check` to vet and test, and `make build` to build the binaries into `bin/`. Design and protocol specs are in [`../docs`](../docs).
