# Constant-time leak detection (instrumented / measured)

Two independent, self-hosted legs that turn "designed constant-time, source-reviewed"
into **measured** constant-time, each paired with a **known-leaky control** so the
detector is proven to fire on a real leak before any subject is trusted.

| Leg | What it does | Where it runs | Kind of leak it catches |
|-----|--------------|---------------|--------------------------|
| **dudect** (`CTLeakDetect`) | fix-vs-random timing test, Welch's t-test, `|t|>4.5` | Windows x86_64, Linux x86_64 (WSL2) | control-flow / iteration-count (mean-separating) |
| **ctgrind / Valgrind** (`CTValgrind`) | marks the secret "undefined", reports any secret-dependent branch or memory index | native Linux x86_64 + AArch64 (CI gate) | data-dependent memory access / branch (deterministic) |

The two legs split the leaky controls by leak *type* and each constant-time subject
is proven clean by whichever leg attributes cleanly:

* **dudect** proves the control-flow leaks: **wNAF** (P-256), **tau-NAF** (sect283k1)
  and **variable-time Euclid** modular inverse separate by a large mean, so their
  controls fire; the CT subjects stay clean - fixed-window, F2m ladder, and safegcd
  measured **both** at the `TMod` core (`mod-inv (core)`) **and** end-to-end through
  the full `TBigInteger` wrapper the ECDSA signer actually calls, `ModOddInverse(n,k)`
  (`mod-inv (wrapper)`), so the nonce inverse is measurement-verified end-to-end.
* **Valgrind** proves the memory-access leaks deterministically: **T-table AES** and
  **4k-table GHASH** index tables by secret-derived bytes and fire; X25519,
  bit-sliced AES and ImplMul64 GHASH stay clean.

AES and GHASH run as **clean subjects only** under dudect: their leaky counterparts
are fine cache/table access-timing effects that stay below dudect's noise floor on a
hot-L1 microbenchmark, so they are caught in the Valgrind leg instead. EC and modular
inverse are **not** taint-checked in Valgrind: byte-poisoning their scalar would flag
the non-constant-time `TBigInteger` front-end rather than the multiplier/inverter,
so their controls live in the dudect leg.

## Quick start

The Valgrind leg runs automatically in CI (native x86_64 + AArch64 Linux) - you only
need local runs for the dudect leg or ad-hoc checks. All commands assume the repo
root as CWD and FPC/Lazarus on `PATH`; see the sections below for the full detail.

**Both legs first need scalar dispatch on** (else the tools refuse to run): in
`CryptoLib/src/Include/CryptoLib.inc` uncomment `{$DEFINE CRYPTOLIB_FORCE_SCALAR}`,
and **re-comment it when done** (rebuild the package back to normal afterwards).

**dudect (Windows x86_64 - swap `win64`->`linux` and run in WSL2 for the Linux cell):**
```
lazbuild -B --cpu=x86_64 --os=win64 CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk
lazbuild -B --cpu=x86_64 --os=win64 CryptoLib.ConstantTime/Lazarus/CTLeakDetect.lpi
CryptoLib.ConstantTime/Lazarus/CTLeakDetect          # expect: GATE: PASS
#   --quick (fast smoke run) | --row=<substr> (one row, e.g. --row=wrapper)
```

**ctgrind / Valgrind (Linux; needs `sudo apt-get install valgrind libc6-dbg gcc`):**
```
gcc -O2 -c CryptoLib.ConstantTime/src/Core/ct_poison.c -o CryptoLib.ConstantTime/Lazarus/ct_poison.o
lazbuild -B --cpu=x86_64 --os=linux CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk
lazbuild -B --cpu=x86_64 --os=linux CryptoLib.ConstantTime/Lazarus/CTValgrind.lpi
cd CryptoLib.ConstantTime/Lazarus
for t in x25519 aes-bitsliced ghash-basic aes-ttable ghash-4k; do \
  valgrind --error-exitcode=1 --track-origins=yes ./CTValgrind $t; done
# subjects clean (exit 0), controls aes-ttable/ghash-4k must fire (exit 1)
```

## Prerequisite: force scalar dispatch (BOTH legs)

Everything must be built so the **software** kernels execute (bit-sliced AES,
`ImplMul64` GHASH, CT scalar mults) - otherwise AES-NI / PCLMUL run and the
measurement is meaningless. `CRYPTOLIB_FORCE_SCALAR` is a **compile-time** define
consumed by the library units, so the library **package** must be rebuilt with it,
not just the tool. Both programs read the runtime SIMD level at startup and **refuse
to run** if hardware kernels are live.

1. In `CryptoLib/src/Include/CryptoLib.inc`, uncomment:
   `{$DEFINE CRYPTOLIB_FORCE_SCALAR}`
2. Rebuild the package, then the tool (commands below).
3. When finished, **re-comment** the define and rebuild the package back to normal.

## Leg 1 - dudect (`CTLeakDetect`)

### Windows x86_64

```
lazbuild -B --cpu=x86_64 --os=win64 CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk
lazbuild -B --cpu=x86_64 --os=win64 CryptoLib.ConstantTime/Lazarus/CTLeakDetect.lpi
CryptoLib.ConstantTime\Lazarus\CTLeakDetect.exe            # full run
CryptoLib.ConstantTime\Lazarus\CTLeakDetect.exe --quick    # fast smoke run
```

For the sharpest signal: close background apps, fix the CPU frequency
(disable turbo/boost), and pin the process to one core (`start /affinity 1`).

### Linux x86_64 (WSL2)

Cross-build from Windows with the cross compiler, then run natively in WSL2 (no
Valgrind needed for this leg):

```
"C:/LazFPCWithCrossCompiler/lazarus/lazbuild.exe" -B --cpu=x86_64 --os=linux CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk
"C:/LazFPCWithCrossCompiler/lazarus/lazbuild.exe" -B --cpu=x86_64 --os=linux CryptoLib.ConstantTime/Lazarus/CTLeakDetect.lpi
# in WSL2:
cd /mnt/c/Repos/Personal/CryptoLib4Pascal/CryptoLib.ConstantTime/Lazarus
chmod +x CTLeakDetect
taskset -c 2 ./CTLeakDetect          # optional core pin; WSL2 adds VM jitter
```

CLI: `--quick` (reduced budgets), `--row=<substr>` (run only matching rows).

### Gate / exit codes

* `0` PASS - every control fired (`|t|>4.5`) AND every subject stayed below 4.5.
* `2` INVALID - a control failed to fire (measurement not sensitive; a non-firing
  control is **not** a pass), or hardware kernels were live.
* `1` FAIL - a subject showed a data-dependent timing signal.

The per-row seeds are fixed, so runs are reproducible.

## Leg 2 - ctgrind / Valgrind (`CTValgrind`)

Deterministic taint check. One target per invocation; `ExpectLeak` controls MUST
make Memcheck report an error, subjects MUST be clean.

### Build

`ct_poison.o` (the taint shim) is built in WSL2 with Valgrind's headers; the FPC
program is cross-built from Windows and links it:

```
# 1) in WSL2 - build the C shim (needs valgrind headers; see setup below):
cd /mnt/c/Repos/Personal/CryptoLib4Pascal/CryptoLib.ConstantTime/Lazarus
gcc -O2 -c ../src/Core/ct_poison.c -I <valgrind-include> -o ct_poison.o

# 2) from Windows - cross-build the linux ELF (links ct_poison.o):
"C:/LazFPCWithCrossCompiler/lazarus/lazbuild.exe" -B --cpu=x86_64 --os=linux CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk
"C:/LazFPCWithCrossCompiler/lazarus/lazbuild.exe" -B --cpu=x86_64 --os=linux CryptoLib.ConstantTime/Lazarus/CTValgrind.lpi
```

(A Windows compile-check of the Pascal is available with `-dCT_VALGRIND_STUB`, which
stubs the poison calls to no-ops.)

### Run (WSL2)

```
cd /mnt/c/Repos/Personal/CryptoLib4Pascal/CryptoLib.ConstantTime/Lazarus
chmod +x CTValgrind
for t in x25519 aes-bitsliced aes-ttable ghash-basic ghash-4k; do
  echo "== $t =="
  valgrind --error-exitcode=1 --track-origins=yes --suppressions=ct.supp ./CTValgrind $t
done
```

Clean = no "Conditional jump or move depends on uninitialised value(s)" /
"uninitialised value was used". **Positive control:** `aes-ttable` and `ghash-4k`
MUST report errors (non-zero exit); the subjects must be clean. A control that does
NOT fire means the run is invalid, not a pass.

`ct.supp` starts empty (masks nothing). On the first successful run, generate
suppressions for the **FPC RTL frames only** (`--gen-suppressions=all`), paste the
verified blocks in, and confirm the controls still fire with them applied. Never
suppress a `Clp*` crypto frame.

### Valgrind setup

* **Normal (root):** `sudo apt-get install valgrind libc6-dbg gcc`. This is the
  path used in CI (the `linux-x64-scalar` and `linux-arm64-scalar` jobs).
* **No-root (deb extract):**
  ```
  cd ~ && mkdir -p ctvg && cd ctvg
  apt-get download valgrind libc6-dbg
  dpkg-deb -x valgrind_*.deb vg
  dpkg-deb -x libc6-dbg_*.deb dbg
  export VALGRIND_LIB=$HOME/ctvg/vg/usr/libexec/valgrind
  alias vg="$HOME/ctvg/vg/usr/bin/valgrind"
  gcc -O2 -c .../ct_poison.c -I $HOME/ctvg/vg/usr/include -o ct_poison.o
  ```
  NOTE (stock WSL2 loader quirk): Valgrind must redirect `strlen` in the system
  dynamic loader, which requires glibc debug symbols on Valgrind's **default** debug
  path (`/usr/lib/debug`). On a stock WSL2 image the loader is stripped and that path
  is root-owned, so `--extra-debuginfo-path` to an extracted `libc6-dbg` does not
  satisfy the very-early loader redirect - Valgrind aborts at startup for **every**
  binary (verified with a trivial C program). Two fixes:
    * On a normal Linux box / CI runner, `sudo apt-get install libc6-dbg` puts the
      symbols on `/usr/lib/debug` and it just works (this is the CI path).
    * With no root, build `CTValgrind` **statically** (add `-Xt` to its
      CustomOptions, with static libs `libc.a`/`libm.a` available at link) - a static
      binary has no dynamic loader for Valgrind to redirect, so it runs regardless of
      `libc6-dbg`. `-Xt` static works with a NATIVE FPC/gcc-ld on Linux; the Windows
      cross linker in this repo mis-selects the glibc static startup and produces a
      broken binary, so build the static variant natively (in WSL2/CI), not via the
      cross compiler. The default `.lpi` builds a dynamic binary (validated to build
      and run); switch to static only for the no-root Valgrind case.

## Coverage matrix

| Cell | dudect (timing) | Valgrind (taint) |
|------|-----------------|-------------------|
| FPC x86_64 Windows | **PASS** (local) | n/a (Valgrind is Linux-only) |
| FPC x86_64 Linux | **PASS** (local, WSL2) | **PASS** (CI, `linux-x64-scalar`) |
| FPC aarch64 Linux | advisory / real-hw (not yet run) | **PASS** (CI, `linux-arm64-scalar`) |
| FPC aarch64 macOS | not pursued | n/a (Valgrind unsupported on modern macOS) |

Notes:
* **PASS = every control fired and every subject stayed clean.** dudect runs
  locally (statistical + shared-runner noise makes it a poor CI gate); Valgrind is
  the CI gate.
* **aarch64 Linux dudect** is the only open cell: it would be *advisory* on the CI
  runner (log-only, never fails) or a *manual run on real AArch64 hardware* with the
  frequency-pinning hygiene above. The control-flow leaks (wNAF / tau-NAF / Euclid)
  are large-signal, so even a noisy AArch64 dudect run shows the controls firing.
  The higher-value AArch64 memory-access cell (Valgrind) is already live in CI.
* **aarch64 macOS is not pursued:** Valgrind has no modern-macOS support, so macOS
  could only add a dudect leg, and the Linux coverage (x86_64 dudect + x86_64 *and*
  AArch64 Valgrind) is judged sufficient. The residual gap is macOS-specific codegen
  (Mach-O / Clang-backed FPC on `aarch64-darwin`) - a manual Apple-Silicon run if an
  auditor wants that cell; it blocks nothing.
* Nothing is run under QEMU (emulation distorts both timing and Valgrind).

### ECDSA nonce inverse - end-to-end measured

The signer computes `k^-1 mod n` via `TBigIntegerUtilities.ModOddInverse(n, k)`
(`ClpECDsaSigner`). The `mod-inv (wrapper)` dudect row measures **that exact call**
- the full `TBigInteger` wrapper (FromBigInteger -> `TMod` core -> ToBigInteger),
not just the core - with `k` a nonce in `[1, n-1]` and allocation-symmetric setup.
Result: subject clean on both x86_64 cells (Windows and Linux), var-time control
fires. So the nonce inverse is **measurement-verified constant-time end-to-end**,
not merely core-measured + wrapper-CT-by-construction. (Were the subject to fire,
that would be a real leak - the wrapper's magnitude-dependent marshalling - not a
harness artifact, and the fix would be to marshal `k` to a fixed-width `Nat` in the
signer and call the CT core directly.)

**CI wiring (done):** the Valgrind leg runs in **both** the `linux-x64-scalar` and
`linux-arm64-scalar` jobs via `.github/workflows/ci/valgrind-ct.sh` (step
"Constant-time Valgrind gate"). Both are **native** runners (`ubuntu-latest` /
`ubuntu-24.04-arm`) - no emulation - and the script is architecture-generic (keys
off `FPC_TARGET`). It `apt-get install`s `valgrind` + `libc6-dbg` (root on the
runner), compiles `CTValgrind` against the scalar packages the build step just
produced, then asserts the subjects run clean AND the leaky controls (`aes-ttable`,
`ghash-4k`) fire - a non-firing control fails the job as INVALID. Opt out with
`MAKE_RUN_CT_VALGRIND=false` (applies to both jobs).
`ct.supp` starts empty; if a subject trips over FPC-RTL uninitialised-value noise on
the first run, the step prints the offending frames and the `--gen-suppressions=all`
command - add the RTL-only frames to `ct.supp` (never a `Clp*` frame) and re-run.
dudect is intentionally NOT a CI gate (statistical + shared-runner noise = flaky);
run it locally/manually per the runbook above and record the numbers in the PR.

## Claim discipline

Once both legs pass with controls firing on a given cell, docs/changelog/SECURITY may
state **"constant-time verified by dudect + ctgrind on {the cells actually run}"**,
scoped to those cells. Until a cell is run with its controls firing, the wording stays
"designed constant-time, source-reviewed; instrumented verification pending."

Neither leg is a proof: dudect is a statistical confidence bound; ctgrind/Valgrind is
dynamic (covers the paths exercised on the built binary). Fiat-style *proven*
constant-time arithmetic is out of scope for Pascal.

## Files

* `src/Core/CtClock.pas` - portable high-resolution monotonic timer.
* `src/Core/CtDudect.pas` - dudect statistical core (Welford, percentile crops, Welch t).
* `src/Core/CtSubjects.pas` - the paired subject/control registry.
* `Lazarus/CTLeakDetect.lpr` / `.lpi` - dudect gate program.
* `src/Core/ct_poison.c` - Valgrind taint shim.
* `Lazarus/CTValgrind.lpr` / `.lpi` - ctgrind/Valgrind program.
* `Lazarus/ct.supp` - RTL-only suppression file (starts empty).
