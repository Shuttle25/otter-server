# otter-server

The OtterMSG node and admin tooling (Go module `ottermsg/server`). It owns the shared protobuf schemas in `proto/` and the cross-language test vectors in `testdata/vectors/`. Run `make gen` to regenerate protobuf code (via buf), `make check` to vet and test, and `make build` to build the binaries into `bin/`. Design and protocol specs are in [`../docs`](../docs).

## Local development

`scripts/dev-node.sh` creates a throwaway network in `.dev/` (gitignored) with one node advertising a plain `ws://` endpoint at `10.0.2.2:8080` (the Android emulator's alias for this machine), imports the signed manifest and a bootstrap invite, prints the invite link and a QR code, and runs the node in the foreground (Ctrl-C stops it). Paste or scan the link in the app on the emulator to register the first member.

- `scripts/dev-node.sh --keep` reuses the existing `.dev/` network and just runs the node.
- `scripts/dev-node.sh --host 192.168.x.y` advertises your PC's LAN IP instead, for a real phone on the same Wi-Fi.

This setup is for development only: traffic is unencrypted and the admin passphrase is fixed.
