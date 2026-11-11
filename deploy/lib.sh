# Shared helpers for admin-side deploy scripts. Source it; do not run it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADMIN_DIR="${OTTER_ADMIN_DIR:-$HOME/.otter-admin}"
ADMIN_BIN="${OTTER_ADMIN_BIN:-$ROOT/bin/otter-admin}"
NODE_BIN="${OTTER_NODE_BIN:-$ROOT/bin/otter-node}"   # host-arch otter-node for probes (make build)
SSH_PORT="${OTTER_SSH_PORT:-22}"
read -r -a SSH_EXTRA <<< "${OTTER_SSH_OPTS:-}"
say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
admin() { "$ADMIN_BIN" --dir "$ADMIN_DIR" "$@"; }
remote() { local target=$1; shift; ssh -p "$SSH_PORT" "${SSH_EXTRA[@]}" "$target" "$@"; }
upload() { local target=$1 src=$2 dst=$3; scp -q -P "$SSH_PORT" "${SSH_EXTRA[@]}" "$src" "$target:$dst"; }
node_env() { local env; env=$(admin node env --label "$1") || die "unknown node $1"; eval "$env"; }
[[ -x "$ADMIN_BIN" && -x "$NODE_BIN" ]] || die "build the tools first: make build"
