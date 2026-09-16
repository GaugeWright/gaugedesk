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

# Where cargo will actually put the artifact. This script used to assume
# `$root/target`, which is wrong exactly when the org's own worktree rule is
# followed: that rule says to give each worktree its own CARGO_TARGET_DIR, and
# under it cargo wrote where it was told while this looked where it guessed, so
# a correct build failed with "was not produced" naming a path nothing had
# reason to write. A relative value is resolved by cargo against the invoking
# directory, so it is resolved the same way here rather than against $root.
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  target_dir="$(cd "$(dirname "$CARGO_TARGET_DIR")" 2>/dev/null && pwd)/$(basename "$CARGO_TARGET_DIR")" \
    || target_dir="$CARGO_TARGET_DIR"
else
  target_dir="$root/target"
fi

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
  # Homebrew keeps its LLVM off PATH deliberately, so that a Mac's `clang` stays
  # Apple's. That makes the Homebrew prefix the one place on a Mac where a
  # wasm32-capable toolchain is expected to be, and it is checked first: on a
  # Mac the versioned Debian layout below cannot match, and on Linux this cannot.
  for dir in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
    if [ -x "$dir/clang" ] && [ -x "$dir/llvm-ar" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  # `sort -V` so llvm-9 does not sort above llvm-21.
  for dir in $(ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -Vr); do
    if [ -x "$dir/clang" ] && [ -x "$dir/llvm-ar" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

# Whether a compiler can actually emit wasm32, which is not the same question as
# whether it exists — and on macOS the two answers differ. Apple's clang is
# always on PATH and always fails this: its LLVM carries only the Apple-platform
# targets and rejects the triple outright. Discovery keyed on absence therefore
# never fired on a Mac, and the build went to a compiler that cannot do the job.
# Asking the compiler beats keeping a list of which clangs were built with which
# targets.
targets_wasm32() {
  command -v "$1" >/dev/null 2>&1 \
    && printf 'int main(void){return 0;}\n' \
      | "$1" --target=wasm32-unknown-unknown -x c -c -o /dev/null - >/dev/null 2>&1
}

# An explicit override always wins: a caller naming a tool has a reason, and
# discovering a different one behind their back is worse than failing. Only the
# tools that are both unset and unresolvable are discovered, and only those are
# reported — a message naming a toolchain the build did not actually take sends
# the next reader to the wrong LLVM.
discovered=()
if { [ -z "${CC_wasm32_unknown_unknown:-}" ] && ! targets_wasm32 clang; } \
  || { [ -z "${AR_wasm32_unknown_unknown:-}" ] && ! command -v llvm-ar >/dev/null; }; then
  llvm_dir="$(llvm_toolchain_dir || true)"
  if [ -n "$llvm_dir" ]; then
    if [ -z "${CC_wasm32_unknown_unknown:-}" ] && ! targets_wasm32 clang; then
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

# Capability, not presence. A compiler that exists but has no wasm32 target
# fails ~90 seconds later inside ring's build script, where the error is about C
# and names neither this variable nor the compiler it chose — which is what
# every Mac saw, because Apple's clang is present and cannot target wasm32.
if ! targets_wasm32 "$CC_wasm32_unknown_unknown"; then
  if command -v "$CC_wasm32_unknown_unknown" >/dev/null; then
    echo "error: $CC_wasm32_unknown_unknown cannot target wasm32 — ring needs one that can (ADR 0130 §4)" >&2
    echo "       Apple's clang is built without the wasm32 target; Homebrew's llvm carries it" >&2
    echo "       install llvm (brew install llvm), or set CC_wasm32_unknown_unknown" >&2
  else
    echo "error: $CC_wasm32_unknown_unknown not found — ring needs clang for wasm32 (ADR 0130 §4)" >&2
    echo "       looked for clang on PATH, for Homebrew's llvm prefix, and for" >&2
    echo "       /usr/lib/llvm-*/bin holding both clang and llvm-ar" >&2
    echo "       install clang and llvm, or set CC_wasm32_unknown_unknown" >&2
  fi
  exit 1
fi
# The archiver is checked alongside the compiler because ring needs both, and
# only one of them fails legibly. A missing `llvm-ar` surfaces as a cc-rs error
# buried under a page of `cargo:rerun-if-env-changed` lines, which reads as a
# broken crate rather than a missing tool — it cost a build in the Console lane
# before this check existed.
if ! command -v "$AR_wasm32_unknown_unknown" >/dev/null; then
  echo "error: $AR_wasm32_unknown_unknown not found — ring needs an LLVM archiver for wasm32 (ADR 0130 §4)" >&2
  echo "       looked for llvm-ar on PATH, for Homebrew's llvm prefix, and for" >&2
  echo "       /usr/lib/llvm-*/bin holding both clang and llvm-ar" >&2
  echo "       Debian and Ubuntu ship it as llvm-ar-<version>; the unversioned name comes from the llvm package" >&2
  echo "       macOS keeps Homebrew's llvm off PATH by design; installing it is enough" >&2
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
  local wasm="$target_dir/wasm32-unknown-unknown/$profile/$artifact.wasm"
  if [ ! -f "$wasm" ]; then
    # Name where it looked and why it looked there. The old message named a
    # path and left the reader to work out which of cargo and this script was
    # wrong about it.
    echo "error: $wasm was not produced" >&2
    echo "       target directory: $target_dir${CARGO_TARGET_DIR:+ (from CARGO_TARGET_DIR)}" >&2
    echo "       if cargo wrote somewhere else, that is the disagreement to fix" >&2
    exit 1
  fi
  # `--target web` emits an init() taking the module URL, which is what a bundler
  # and a strict CSP both want: no eval, no inline blob.
  wasm-bindgen "$wasm" --target web --out-dir "$out" --out-name "$name"
  # Binaryen rewrites the module rather than compressing it: whole-program dead
  # code elimination, inlining, and dropping the name/debug sections.
  # Semantically identical, materially smaller, cheap enough for every build.
  # `wc -c <` rather than `stat`, whose size flag is spelled `-c%s` by GNU and
  # `-f%z` by BSD: the GNU spelling exits non-zero on macOS, and because this
  # runs under `set -e` it takes the whole build down *after* the first module
  # is already written — so the failure reads as a broken second module rather
  # than as a line that only ever worked on Linux.
  local before after
  before=$(( $(wc -c < "$out/${name}_bg.wasm") ))
  wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int \
    "$out/${name}_bg.wasm" -o "$out/${name}_bg.opt.wasm"
  mv "$out/${name}_bg.opt.wasm" "$out/${name}_bg.wasm"
  after=$(( $(wc -c < "$out/${name}_bg.wasm") ))
  printf 'built %s (wasm %d -> %d bytes, %d%%)\n' "$out/$name.js" "$before" "$after" \
    "$(( after * 100 / before ))"
}

build_module gaugedesk-relay-transport gaugedesk_relay_transport tunnel
build_module gaugedesk-directory-protocol gaugedesk_directory_protocol directory --features wasm
