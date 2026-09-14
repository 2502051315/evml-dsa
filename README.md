# evML-DSA — Reference Implementation and Measurement Artifact

This repository contains the C reference implementation, benchmark harnesses,
and all raw measurement data for **evML-DSA**, a forward-secure key-evolving
signature whose per-period signing keys are standard FIPS 204 ML-DSA keys,
designed for long-lived digital evidence.

> **Paper**: *Forward-Secure ML-DSA: Key-Evolving Post-Quantum Signatures for
> Long-Lived Digital Evidence* (IEEE TIFS submission). Citation/DOI to be
> added upon acceptance.

evML-DSA derives a fresh, reusable (many-time) ML-DSA leaf key for every
period under one shared FIPS-204 matrix seed, commits all leaf verification
values under a Merkle root inside a fixed 68-byte public key, and advances a
punctured GGM seed-tree state with derive-and-discard erasure, so that
exposure of the current signing state does not recover past-period signing
capability.

## Repository layout

```
├── src/
│   ├── evmldsa/            core implementation + all evML-DSA benchmarks
│   │   ├── ev_sha3.c       standalone SHA3-256 (tested vectors)
│   │   ├── ev_seedtree.c   GGM puncturable seed tree (derive-and-discard)
│   │   ├── ev_merkle.c     Merkle tree with domain-separated hashing
│   │   ├── evmldsa.c       leaf-key integration on pq-crystals ML-DSA
│   │   ├── ev_selftest.c   unit tests (hash vectors, tree, Merkle, tamper)
│   │   ├── ev_test.c       protocol-level tests (cross-period forgery, ...)
│   │   ├── ev_c4_selftest.c end-to-end lifetime tests + erasure invariant
│   │   ├── bench.c               E2: operation costs vs T
│   │   ├── figdata_bench.c       op-scaling data (Fig. 3a; 7 T-points)
│   │   ├── breakdown_bench.c     Sign/Verify decomposition (Fig. 3b/3c)
│   │   ├── bench_workload.c      batch throughput + archive + stability
│   │   ├── bench_rechain.c       Dilithium-rechain baseline
│   │   ├── extended_bench.c      archive scaling (11 sizes) + distance sweep
│   │   └── sizeof_check.c        serialized size checks
│   └── baselines/          LMS (hash-sigs) and XMSS (xmss-reference) drivers;
│                           build commands documented in each file header
├── third-party/            vendored dependencies (no VCS metadata), see
│   └── MANIFEST.md         pinned upstream commits and license notes
├── results/                every raw CSV/TXT behind the paper's numbers
│   ├── raw/                E2/E5E6 operation + workload CSVs, B1/B2/B4 baselines
│   ├── fig3/ fig4/ fig5/   per-figure data as plotted
├── figures/                matplotlib scripts that render Figs. 3–5
└── docs/                   reproducibility notes, FIPS-204 security provenance
```

## Requirements

- gcc (tested: 11.4) and GNU make
- For the LMS baseline only: OpenSSL development headers (`libssl-dev`)
- For figures: python3 with matplotlib

## Build and test

```bash
cd src/evmldsa
make            # builds all tests and benchmarks
make check      # runs the full self-test suite; expected: ALL PASS (x4)
```

The default build is the **paper construction**: one shared FIPS-204 matrix
seed for all periods (`EVMLDSA_LEGACY=1`, see `ev_params.h`). All result
files in `results/` were produced in this mode on the hardware below. An
experimental per-period variant (`rho_p = H(0x07 || rho || p)`, one extra
hash per verification) can be built with `make CONSTRUCTION=0`; it is not
covered by the paper's measurements.

## Reproducing the paper's numbers

Reference machine: Intel Core Ultra 9 275HX, Ubuntu 22.04 (WSL2), gcc 11.4
`-O3`, benchmarks pinned to a single core (`taskset -c 2`). Absolute timings
vary with hardware and load; medians and scaling behavior should reproduce.

| Paper item | Command (from `src/evmldsa`) | Data in `results/` |
|---|---|---|
| Fig. 3(a) op scaling, Table III sizes | `taskset -c 2 ./figdata_bench` | `fig3/operation_scaling_raw.csv` |
| Fig. 3(b)/(c) decomposition | `taskset -c 2 ./breakdown_bench` | `fig3/fig3_{sign,verify}_breakdown.csv` |
| Fig. 5(a) throughput (ev + plain) | `taskset -c 2 ./bench_workload` | `fig4/batch_throughput_raw.csv`, `fig4/plainbatch_raw.csv` |
| Fig. 5(b) archive scan (2^10–2^20) | `./extended_bench archive` (see `run_archive.sh`) | `fig4/archive_scaling_extended_raw.csv` |
| Fig. 5(c) distance sweep (d=0–128) | `./extended_bench distance` | `fig4/rechain_distance_extended_raw.csv` |
| Fig. 4 cross-scheme table | `taskset -c 2 ./bench`, `./bench_rechain`, baselines | `fig5/*.csv`, `raw/B*.txt` |
| LMS baseline (Table IV) | see header of `src/baselines/bench_lms.c` | `raw/B1_lms.txt` |
| XMSS baseline (Table IV) | see header of `src/baselines/bench_xmss.c` | `raw/B2_xmss.txt` |
| 256-period stability walk | included in `bench_workload` | `raw/E5E6_workload.csv` |

Notes:
- KeyGen at `T=2^20` takes on the order of 95 s single-core (one-time setup).
- Archive runs write large outputs; the harness scripts show the exact
  invocations used for the published data.
- FROG numbers in the paper are literature-reported values only and are not
  reproduced here.

## Security-relevant implementation notes

- **Erasure semantics**: every retained seed-tree node is zeroed as soon as
  its children are derived (`memset` in `ev_seedtree.c`), including on
  `Evolve`. The end-to-end erasure invariant (no past ancestor or past leaf
  seed retained after evolution) is asserted adversarially by
  `ev_c4_selftest.c` for every tested lifetime.
- **Domain separation**: all hash domains carry explicit one-byte labels
  (`0x01`–`0x07`, see `ev_params.h`), matching the paper's Supplement A.
- The benchmark prototype retains the full public commitment tree (~67 MB at
  `T=2^20`); this is public caching convenience, not secret key material
  (paper §V-C).

## Third-party code

Vendored under `third-party/` at the pinned commits recorded in
`third-party/MANIFEST.md`, each with its upstream license intact:

- [pq-crystals/dilithium](https://github.com/pq-crystals/dilithium) — ML-DSA
  leaf layer (reference implementation, CC0-licensed files)
- [cisco/hash-sigs](https://github.com/cisco/hash-sigs) — LMS/HSS baseline
  (BSD-3-Clause)
- [XMSS/xmss-reference](https://github.com/XMSS/xmss-reference) — XMSS
  baseline (CC0-1.0)

No upstream file was modified.

## License

The evML-DSA implementation, benchmarks, scripts, and data in this
repository are released under the MIT License (see `LICENSE`). Third-party
components keep their upstream licenses.

## Citation

```bibtex
@misc{evmldsa-artifact,
  title  = {evML-DSA: Reference Implementation and Measurement Artifact},
  author = {evML-DSA authors},
  year   = {2026},
  note   = {Source code accompanying the paper "Forward-Secure ML-DSA:
            Key-Evolving Post-Quantum Signatures for Long-Lived Digital
            Evidence"}
}
```
