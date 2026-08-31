#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
arithmetic_dir="$repo_dir/examples/arithmetic"
bitwise_dir="$repo_dir/examples/bitwise"
proof_path="$arithmetic_dir/target/arithmetic.binius"
tampered_path="$arithmetic_dir/target/arithmetic-tampered.binius"
bitwise_proof_path="$bitwise_dir/target/bitwise.binius"

(cd "$arithmetic_dir" && nargo execute)
(cd "$bitwise_dir" && nargo execute)

cargo run --release --manifest-path "$repo_dir/Cargo.toml" -- \
  info -b "$arithmetic_dir/target/arithmetic.json"
cargo run --release --manifest-path "$repo_dir/Cargo.toml" -- \
  info -b "$bitwise_dir/target/bitwise.json"

cargo run --release --manifest-path "$repo_dir/Cargo.toml" -- \
  prove -b "$arithmetic_dir/target/arithmetic.json" \
  -w "$arithmetic_dir/target/arithmetic.gz" -o "$proof_path"
cargo run --release --manifest-path "$repo_dir/Cargo.toml" -- \
  verify -b "$arithmetic_dir/target/arithmetic.json" -p "$proof_path"
cargo run --release --manifest-path "$repo_dir/Cargo.toml" -- \
  prove -b "$bitwise_dir/target/bitwise.json" \
  -w "$bitwise_dir/target/bitwise.gz" -o "$bitwise_proof_path"
cargo run --release --manifest-path "$repo_dir/Cargo.toml" -- \
  verify -b "$bitwise_dir/target/bitwise.json" -p "$bitwise_proof_path"

cp "$proof_path" "$tampered_path"
last_byte="$(tail -c 1 "$tampered_path" | od -An -tu1)"
replacement=$((last_byte ^ 1))
printf "\\$(printf '%03o' "$replacement")" | \
  dd of="$tampered_path" bs=1 seek=$(($(wc -c < "$tampered_path") - 1)) conv=notrunc status=none
if cargo run --release --manifest-path "$repo_dir/Cargo.toml" -- \
  verify -b "$arithmetic_dir/target/arithmetic.json" -p "$tampered_path"; then
  echo "tampered proof unexpectedly verified" >&2
  exit 1
fi

echo "arithmetic, bitwise, and tamper-rejection checks passed"
