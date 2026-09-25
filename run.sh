#!/usr/bin/env bash
# Build lsnet, install it to ~/.local/bin, and run it.
# Any arguments are passed through: ./run.sh -v, ./run.sh --json, ...
set -euo pipefail

cd "$(dirname "$0")"
bin_dir="$HOME/.local/bin"

cargo build --release --quiet
mkdir -p "$bin_dir"
install -m 755 target/release/lsnet "$bin_dir/lsnet"

exec "$bin_dir/lsnet" "$@"
