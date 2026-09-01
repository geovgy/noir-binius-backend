#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
backend="$repo_dir/target/release/noir-binius"

run_timed() {
  local label="$1"
  shift
  local TIMEFORMAT="$label took %3R seconds"
  time "$@"
}

cargo build --release --manifest-path "$repo_dir/Cargo.toml"

fixtures=(
  arithmetic
  bitwise
  brillig
  memory
  folded
  folded_predicate
  folded_predicate_false
  aes128
  hashes
  poseidon2
  ecdsa_k1
  ecdsa_r1
  embedded_curve
)

for fixture in "${fixtures[@]}"; do
  fixture_dir="$repo_dir/examples/$fixture"
  artifact="$fixture_dir/target/$fixture.json"
  witness="$fixture_dir/target/$fixture.gz"
  proof="$fixture_dir/target/$fixture.binius"

  if [[ "${SKIP_NARGO:-0}" != "1" ]]; then
    (cd "$fixture_dir" && nargo execute)
  fi
  "$backend" info -b "$artifact"
  run_timed "$fixture prove" \
    "$backend" prove -b "$artifact" -w "$witness" -o "$proof"
  run_timed "$fixture verify" \
    "$backend" verify -b "$artifact" -p "$proof"
done

inner_dir="$repo_dir/examples/arithmetic"
recursive_dir="$repo_dir/examples/recursive_aggregation"
"$backend" recursive-inputs \
  -b "$inner_dir/target/arithmetic.json" \
  -p "$inner_dir/target/arithmetic.binius" \
  --toml -o "$recursive_dir/Prover.toml"
if [[ "${SKIP_NARGO:-0}" != "1" ]]; then
  (cd "$recursive_dir" && nargo execute)
fi
"$backend" info -b "$recursive_dir/target/recursive_aggregation.json"
run_timed "recursive_aggregation prove" \
  "$backend" prove \
  -b "$recursive_dir/target/recursive_aggregation.json" \
  -w "$recursive_dir/target/recursive_aggregation.gz" \
  -o "$recursive_dir/target/recursive_aggregation.binius"
run_timed "recursive_aggregation verify" \
  "$backend" verify \
  -b "$recursive_dir/target/recursive_aggregation.json" \
  -p "$recursive_dir/target/recursive_aggregation.binius"

echo "all pinned ACIR opcode and black-box fixtures proved and verified"
