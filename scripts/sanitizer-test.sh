#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run unit tests under a Rust sanitizer (nightly).

Usage:
  scripts/sanitizer-test.sh <asan|lsan|tsan> [cargo-cmd] [cargo args...]

Examples:
  scripts/sanitizer-test.sh asan
  scripts/sanitizer-test.sh asan test raw_ssl_cert_decompress_zstd
  scripts/sanitizer-test.sh asan run -- --config config/example.toml
  scripts/sanitizer-test.sh asan test -Zbuild-std raw_ssl_cert_decompress_zstd

Notes (macOS):
  The sanitizer runtime must be preloaded into rustc (proc-macro dylibs are dlopen'ed),
  and Apple sanitizer runtimes strip DYLD_INSERT_LIBRARIES for child processes by default.
  This script sets *SAN_OPTIONS=strip_env=0 to keep the preload active.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

san="$1"
shift

cargo_cmd="test"
if [[ $# -gt 0 ]]; then
  case "$1" in
    bench | build | check | clippy | run | test)
      cargo_cmd="$1"
      shift
      ;;
  esac
fi

has_build_std=false
prev=""
for arg in "$@"; do
  if [[ "$arg" == "-Zbuild-std" || "$arg" == "-Zbuild-std="* ]]; then
    has_build_std=true
  elif [[ "$prev" == "-Z" && "$arg" == "build-std"* ]]; then
    has_build_std=true
  fi
  prev="$arg"
done

case "$san" in
  asan)
    rust_san="address"
    rt_suffix="asan"
    opt_var="ASAN_OPTIONS"
    ;;
  lsan)
    rust_san="leak"
    rt_suffix="lsan"
    opt_var="LSAN_OPTIONS"
    ;;
  tsan)
    rust_san="thread"
    rt_suffix="tsan"
    opt_var="TSAN_OPTIONS"
    ;;
  *)
    echo "error: unknown sanitizer '$san' (expected: asan, lsan, tsan)" >&2
    exit 2
    ;;
esac

target_libdir="$(rustc +nightly --print target-libdir)"
sysroot="$(rustc +nightly --print sysroot)"

preload_var="LD_PRELOAD"
preload_sep=" "
rt_ext="so"
if [[ "${OSTYPE:-}" == darwin* ]]; then
  preload_var="DYLD_INSERT_LIBRARIES"
  preload_sep=":"
  rt_ext="dylib"
fi

rt_path="${target_libdir}/librustc-nightly_rt.${rt_suffix}.${rt_ext}"
if [[ ! -f "$rt_path" ]]; then
  echo "error: sanitizer runtime not found: $rt_path" >&2
  echo "hint: ensure 'nightly' toolchain is installed and supports '$san' on this target" >&2
  exit 1
fi

# TSan requires the standard library to be built with the same sanitizer to
# avoid ABI mismatch errors (build scripts and proc-macros depend on std/core).
if [[ "$san" == "tsan" && "$has_build_std" != "true" ]]; then
  set -- -Zbuild-std "$@"
  has_build_std=true
fi

if [[ "$has_build_std" == "true" ]]; then
  if [[ ! -d "${sysroot}/lib/rustlib/src/rust/library" ]]; then
    echo "error: rust-src is required for -Zbuild-std but is not installed for nightly" >&2
    echo "hint: run: rustup component add rust-src --toolchain nightly" >&2
    exit 1
  fi
fi

# Keep the preload active for child processes (rustc is a child of cargo).
opt_val="${!opt_var:-}"
if [[ "$opt_val" != *"strip_env="* ]]; then
  if [[ -n "$opt_val" ]]; then
    opt_val="${opt_val}:strip_env=0"
  else
    opt_val="strip_env=0"
  fi
fi
export "${opt_var}=${opt_val}"

preload_val="${!preload_var:-}"
if [[ -n "$preload_val" ]]; then
  export "${preload_var}=${rt_path}${preload_sep}${preload_val}"
else
export "${preload_var}=${rt_path}"
fi

export RUSTFLAGS="-Zsanitizer=${rust_san} ${RUSTFLAGS:-}"

exec cargo +nightly "$cargo_cmd" "$@"
