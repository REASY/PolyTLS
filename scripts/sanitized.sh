#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <leak|address> <run|test> [additional cargo args...]

Examples:
  $0 leak run -- --config config/example.toml
  $0 address test
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

MODE=$1
CMD=$2
shift 2

case "$MODE" in
  leak)
    export CFLAGS="-fsanitize=leak"
    export CXXFLAGS="-fsanitize=leak"
    export RUSTFLAGS="-Z sanitizer=leak"
    ;;
  address)
    export CFLAGS="-fsanitize=address"
    export CXXFLAGS="-fsanitize=address"
    export RUSTFLAGS="-Z sanitizer=address"
    ;;
  *)
    echo "Unknown mode: $MODE"
    usage
    exit 1
    ;;
esac

echo "Running \`cargo +nightly $CMD\` with $MODE sanitizer and target x86_64-unknown-linux-gnu..."

# We always use the target `x86_64-unknown-linux-gnu`
exec cargo +nightly "$CMD" --target x86_64-unknown-linux-gnu "$@"
