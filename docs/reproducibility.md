# Reproducibility notes (release artifact)

## Construction mode
The release builds, by default, the construction analyzed in the paper:
one SHARED FIPS-204 matrix seed for all periods (`EVMLDSA_LEGACY=1` in
`src/evmldsa/ev_params.h`). Every CSV under `results/` was produced in this
mode. The experimental per-period variant (rho_p = H(0x07 || rho || p)),
which decouples leaf instances at one extra hash per verification, is
available via `make CONSTRUCTION=0` and is NOT covered by the paper.

## Environment of the published measurements
- CPU: Intel Core Ultra 9 275HX (benchmarks pinned to a single core)
- OS: Ubuntu 22.04 under WSL2, kernel 6.6.87
- Compiler: gcc 11.4.0, -O3 -Wall -Wextra
- Upstream commits: see ../third-party/MANIFEST.md
- Timing: CLOCK_MONOTONIAN-based harnesses; medians and distribution
  statistics reported (see paper Section VII-A for the measurement
  conventions, including the batch-mean vs per-call-median regimes).

## Known-cause deviations when re-running
- Absolute timings shift with CPU frequency scaling and load; pin cores and
  compare medians, not means.
- KeyGen at T=2^20 is a single ~95 s one-time setup run in the published
  data (n=1); smaller sizes used n=5/5/3/3/3.
- The archive (2^10..2^20 x3 runs) and distance (13 distances x100) sweeps
  take several minutes each.

## Changelog relative to the development tree
- ev_c4_selftest.c: fixed an assertion bug in the erasure check (the
  previous version also required the CURRENT leaf seed to be absent, which
  is wrong by definition; it now requires absence only for past leaves and
  strict ancestors). All tests pass in both construction modes; the
  implementation itself was not changed.
- ev_params.h: release default set to the paper's shared-matrix
  construction.
