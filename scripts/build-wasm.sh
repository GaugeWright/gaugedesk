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

: "${CC_wasm32_unknown_unknown:=clang}"
: "${AR_wasm32_unknown_unknown:=llvm-ar}"
export CC_wasm32_unknown_unknown AR_wasm32_unknown_unknown

if ! command -v "$CC_wasm32_unknown_unknown" >/dev/null; then
  echo "error: $CC_wasm32_unknown_unknown not found — ring needs clang for wasm32 (ADR 0130 §4)" >&2
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
