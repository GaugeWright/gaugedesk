#!/usr/bin/env bash
# Build the browser's wasm artifacts, packaged for the web client:
#
#   tunnel     — the wasm32 half of gaugedesk-relay-transport, which carries the
#                pinned session a page has no socket for (DESK-7, ADR 0130).
#   directory  — gaugedesk-directory-protocol's signature verifier, which a page
#                needs to check the root-signed route record (DESK-5g, ADR 0133).
#
# The verifier is built from the crate that owns the canonical signing bytes
# rather than reimplemented in TypeScript, precisely so no second implementation
# can drift from them — a drifting verifier fails open (ADR 0132).
#
# `ring` compiles C for wasm32, so this needs a clang toolchain (ADR 0130 §4).
# The output is generated, not source: it is gitignored, and the loader in
# control-plane-client fails with a clear message when it is absent rather than
# silently degrading a Home to unreachable.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/web/packages/control-plane-client/src/generated"
profile="${1:-release}"

# Debian and Ubuntu install LLVM's binaries under versioned names — `llvm-ar-21`
# in `/usr/lib/llvm-21/bin` — and only the unversioned `llvm` package adds the
# plain `llvm-ar`. `clang` is usually there under its plain name and `llvm-ar`
# usually is not, so a machine with a complete, working toolchain failed this
# check and was told to install what it already had. CI installs `clang llvm`
# and so never saw it; every fresh worktree here did.
#
# So look for the plain names first, and fall back to the newest versioned
# directory that carries *both*. Both, because pairing one release's compiler
# with another's archiver is a harder failure to read than either being absent.
llvm_toolchain_dir() {
  local dir
  # `sort -V` so llvm-9 does not sort above llvm-21.
  for dir in $(ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -Vr); do
    if [ -x "$dir/clang" ] && [ -x "$dir/llvm-ar" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

# An explicit override always wins: a caller naming a tool has a reason, and
# discovering a different one behind their back is worse than failing. Only the
# tools that are both unset and unresolvable are discovered, and only those are
# reported — a message naming a toolchain the build did not actually take sends
# the next reader to the wrong LLVM.
discovered=()
if { [ -z "${CC_wasm32_unknown_unknown:-}" ] && ! command -v clang >/dev/null; } \
  || { [ -z "${AR_wasm32_unknown_unknown:-}" ] && ! command -v llvm-ar >/dev/null; }; then
  llvm_dir="$(llvm_toolchain_dir || true)"
  if [ -n "$llvm_dir" ]; then
    if [ -z "${CC_wasm32_unknown_unknown:-}" ] && ! command -v clang >/dev/null; then
      CC_wasm32_unknown_unknown="$llvm_dir/clang"
      discovered+=(clang)
    fi
    if [ -z "${AR_wasm32_unknown_unknown:-}" ] && ! command -v llvm-ar >/dev/null; then
      AR_wasm32_unknown_unknown="$llvm_dir/llvm-ar"
      discovered+=(llvm-ar)
    fi
    if [ ${#discovered[@]} -gt 0 ]; then
      echo "using ${discovered[*]} from $llvm_dir" >&2
    fi
  fi
fi

: "${CC_wasm32_unknown_unknown:=clang}"
: "${AR_wasm32_unknown_unknown:=llvm-ar}"
export CC_wasm32_unknown_unknown AR_wasm32_unknown_unknown

if ! command -v "$CC_wasm32_unknown_unknown" >/dev/null; then
  echo "error: $CC_wasm32_unknown_unknown not found — ring needs clang for wasm32 (ADR 0130 §4)" >&2
  echo "       looked for clang on PATH and for /usr/lib/llvm-*/bin holding both clang and llvm-ar" >&2
  echo "       install clang and llvm, or set CC_wasm32_unknown_unknown" >&2
  exit 1
fi
# The archiver is checked alongside the compiler because ring needs both, and
# only one of them fails legibly. A missing `llvm-ar` surfaces as a cc-rs error
# buried under a page of `cargo:rerun-if-env-changed` lines, which reads as a
# broken crate rather than a missing tool — it cost a build in the Console lane
# before this check existed.
if ! command -v "$AR_wasm32_unknown_unknown" >/dev/null; then
  echo "error: $AR_wasm32_unknown_unknown not found — ring needs an LLVM archiver for wasm32 (ADR 0130 §4)" >&2
  echo "       looked for llvm-ar on PATH and for /usr/lib/llvm-*/bin holding both clang and llvm-ar" >&2
  echo "       Debian and Ubuntu ship it as llvm-ar-<version>; the unversioned name comes from the llvm package" >&2
  echo "       install llvm, or set AR_wasm32_unknown_unknown" >&2
  exit 1
fi
if ! command -v wasm-bindgen >/dev/null; then
  echo "error: wasm-bindgen not found — cargo install wasm-bindgen-cli --version 0.2.126" >&2
  exit 1
fi
if ! command -v wasm-opt >/dev/null; then
  echo "error: wasm-opt not found — install binaryen" >&2
  exit 1
fi
# An old optimizer does not fail; it emits a module that cannot be instantiated.
# Binaryen 108 (what Ubuntu noble packages) produces a fixed-size function table,
# and wasm-bindgen's glue grows that table at startup — so the module dies on
# load with `WebAssembly.Table.grow(): failed to grow table by 4`, which reads as
# a corrupt build rather than as a stale tool. Worse, it is silent everywhere
# that never loads the module. 120 is the oldest version verified here; the CI
# lane pins a release rather than taking the distribution's.
minimum_binaryen=120
binaryen_version="$(wasm-opt --version | grep -oE '[0-9]+' | head -n1)"
if [ "${binaryen_version:-0}" -lt "$minimum_binaryen" ]; then
  echo "error: wasm-opt is binaryen ${binaryen_version:-unknown}; ${minimum_binaryen} or newer is required" >&2
  echo "       older releases emit a module whose function table cannot grow, and it fails at load, not here" >&2
  exit 1
fi

flags=()
[ "$profile" = "release" ] && flags+=(--release)

rm -rf "$out"
mkdir -p "$out"

# One module per crate. Kept separate rather than merged because they load on
# different occasions: the verifier is needed on any signed-in load, the tunnel
# only when someone opens a relay-only Home.
build_module() {
  local crate="$1" artifact="$2" name="$3"
  shift 3
  cargo build -p "$crate" --target wasm32-unknown-unknown "${flags[@]}" "$@"
  local wasm="$root/target/wasm32-unknown-unknown/$profile/$artifact.wasm"
  [ -f "$wasm" ] || { echo "error: $wasm was not produced" >&2; exit 1; }
  # `--target web` emits an init() taking the module URL, which is what a bundler
  # and a strict CSP both want: no eval, no inline blob.
  wasm-bindgen "$wasm" --target web --out-dir "$out" --out-name "$name"
  # Binaryen rewrites the module rather than compressing it: whole-program dead
  # code elimination, inlining, and dropping the name/debug sections.
  # Semantically identical, materially smaller, cheap enough for every build.
  local before after
  before=$(stat -c%s "$out/${name}_bg.wasm")
  wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int \
    "$out/${name}_bg.wasm" -o "$out/${name}_bg.opt.wasm"
  mv "$out/${name}_bg.opt.wasm" "$out/${name}_bg.wasm"
  after=$(stat -c%s "$out/${name}_bg.wasm")
  printf 'built %s (wasm %d -> %d bytes, %d%%)\n' "$out/$name.js" "$before" "$after" \
    "$(( after * 100 / before ))"
}

build_module gaugedesk-relay-transport gaugedesk_relay_transport tunnel
build_module gaugedesk-directory-protocol gaugedesk_directory_protocol directory --features wasm
