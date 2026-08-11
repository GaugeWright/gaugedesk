#!/usr/bin/env bash
# Build the browser tunnel (DESK-7): the wasm32 half of gaugedesk-relay-transport,
# packaged for the web client.
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
cargo build -p gaugedesk-relay-transport --target wasm32-unknown-unknown "${flags[@]}"

wasm="$root/target/wasm32-unknown-unknown/$profile/gaugedesk_relay_transport.wasm"
[ -f "$wasm" ] || { echo "error: $wasm was not produced" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out"
# `--target web` emits an init() taking the module URL, which is what a bundler
# and a strict CSP both want: no eval, no inline blob.
wasm-bindgen "$wasm" --target web --out-dir "$out" --out-name tunnel

# Binaryen rewrites the module rather than compressing it: whole-program dead
# code elimination, inlining, and dropping the name/debug sections. Semantically
# identical, materially smaller, and cheap enough to run on every build.
before=$(stat -c%s "$out/tunnel_bg.wasm")
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int \
  "$out/tunnel_bg.wasm" -o "$out/tunnel_bg.opt.wasm"
mv "$out/tunnel_bg.opt.wasm" "$out/tunnel_bg.wasm"
after=$(stat -c%s "$out/tunnel_bg.wasm")
printf 'built %s (wasm %d -> %d bytes, %d%%)\n' "$out/tunnel.js" "$before" "$after" \
  "$(( after * 100 / before ))"
