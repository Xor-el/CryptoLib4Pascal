#!/usr/bin/env bash
# Constant-time taint gate (ctgrind / Valgrind), Linux x86_64 FORCE_SCALAR leg.
#
# Runs AFTER the standard build step of the linux-x64-scalar job, so the CryptoLib
# / HashLib / SimpleBase packages are already compiled (with CRYPTOLIB_FORCE_SCALAR)
# into their lib/<target> unit dirs. We compile CTValgrind against those prebuilt
# .ppu (no from-source rebuild), poison each primitive's secret, and assert:
#   * every constant-time SUBJECT runs clean under Memcheck, and
#   * every known-leaky CONTROL makes Memcheck report an error (a non-firing
#     control means the detector is not sensitive -> the run is INVALID, not a pass).
#
# Opt out with MAKE_RUN_CT_VALGRIND=false. Needs root apt (GitHub runners have it)
# for valgrind + libc6-dbg (glibc debug symbols, required for Memcheck's loader
# redirect on a dynamically linked binary).

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/shared/common.sh"
ci_init_paths
ci_export_toolchain_path

if [ "${MAKE_RUN_CT_VALGRIND:-true}" != "true" ]; then
  echo "MAKE_RUN_CT_VALGRIND != true - skipping the constant-time Valgrind gate."
  exit 0
fi

: "${FPC_TARGET:?FPC_TARGET is required (e.g. x86_64-linux)}"
CPU="${FPC_TARGET%-*}"
OS="${FPC_TARGET#*-}"

BENCH_LAZ="$REPO_ROOT/CryptoLib.Benchmark/Lazarus"
BENCH_CORE="$REPO_ROOT/CryptoLib.Benchmark/src/Core"
SUPP="$BENCH_LAZ/ct.supp"

echo "==> installing valgrind + glibc debug symbols"
sudo apt-get update
sudo apt-get install -y valgrind libc6-dbg gcc

echo "==> building the taint shim (ct_poison.o)"
gcc -O2 -c "$BENCH_CORE/ct_poison.c" -o "$BENCH_LAZ/ct_poison.o"

# Locate the prebuilt package unit dirs (each package outputs to <pkg>/lib/<target>).
# Discover by a known .ppu so we do not hard-code layout that varies per package.
find_units_dir() {
  local match f
  f="$(find "$REPO_ROOT" "$(dirname "$REPO_ROOT")" "$HOME" -type f -path "$1" 2>/dev/null | head -1 || true)"
  [ -n "$f" ] && dirname "$f"
}
CRYPTO_UNITS="$(find_units_dir "*/lib/$FPC_TARGET/ClpAesEngine.ppu")"
HASH_UNITS="$(find_units_dir "*HashLib*/*$FPC_TARGET/*.ppu")"
SB_UNITS="$(find_units_dir "*SimpleBase*/*$FPC_TARGET/*.ppu")"

for pair in "CryptoLib:$CRYPTO_UNITS" "HashLib:$HASH_UNITS" "SimpleBase:$SB_UNITS"; do
  name="${pair%%:*}"; dir="${pair#*:}"
  if [ -z "$dir" ] || [ ! -d "$dir" ]; then
    echo "::error::could not locate prebuilt $name units for $FPC_TARGET (was the build step run first?)"
    exit 1
  fi
  echo "    $name units: $dir"
done

echo "==> compiling CTValgrind against the prebuilt scalar packages"
BUILD_DIR="$(mktemp -d)"
( cd "$BENCH_LAZ" && fpc "-T$OS" "-P$CPU" -MDelphi -O3 \
    -dCRYPTOLIB_FORCE_SCALAR -dHASHLIB_FORCE_SCALAR \
    -Fu"$CRYPTO_UNITS" -Fu"$HASH_UNITS" -Fu"$SB_UNITS" -Fu"$BENCH_CORE" \
    -Fl"$BENCH_LAZ" -FU"$BUILD_DIR" -oCTValgrind \
    CTValgrind.lpr )
BIN="$BENCH_LAZ/CTValgrind"
chmod +x "$BIN"

# ct.supp starts empty (masks nothing). Only pass it if it has real entries.
VG=(valgrind --error-exitcode=1 --track-origins=yes)
if [ -s "$SUPP" ] && grep -qvE '^\s*(#|$)' "$SUPP"; then
  VG+=(--suppressions="$SUPP")
fi

FAIL=0
run_target() {  # <target> <clean|fire>
  local t="$1" expect="$2" log="/tmp/vg_$1.log" ec=0
  "${VG[@]}" "$BIN" "$t" >"$log" 2>&1 || ec=$?
  if [ "$expect" = "clean" ]; then
    if [ "$ec" -eq 0 ]; then
      echo "  PASS  subject $t: clean under Memcheck"
    else
      echo "::error::subject $t reported a secret-dependent access (constant-time violation, OR unsuppressed RTL noise)"
      grep -E "Conditional jump|uninitialised|depends on|ERROR SUMMARY" "$log" | head -20 || true
      echo "  (if these frames are FPC RTL - fpc_*/SYSTEM_*/libc startup - add them to ct.supp;"
      echo "   regenerate with: valgrind --gen-suppressions=all $BIN $t)"
      FAIL=1
    fi
  else
    if [ "$ec" -ne 0 ]; then
      echo "  PASS  control $t: fired (Memcheck reported the expected secret-dependent access)"
    else
      echo "::error::control $t did NOT fire - the detector is not sensitive, this run is INVALID"
      FAIL=1
    fi
  fi
}

echo "==> running the gate"
run_target x25519        clean
run_target aes-bitsliced clean
run_target ghash-basic   clean
run_target aes-ttable    fire
run_target ghash-4k      fire

if [ "$FAIL" -ne 0 ]; then
  echo "GATE: FAIL - see errors above."
  exit 1
fi
echo "GATE: PASS - all controls fired and all subjects stayed clean."
