# Third-Party Code Manifest (all cloned 2026-09-05; builds verified this date)

| Repo | URL | Commit | License | Build | Test/Bench status | Used for |
|---|---|---|---|---|---|---|
| pq-crystals/dilithium | github.com/pq-crystals/dilithium | d35ba3fe5449bee3e6d43e1f296c3ca818bd36be (2026-06-03) | CC0/Apache-2/GPL (per LICENSE; we use the CC0-licensed reference files) | ref: make ✓ (avx2 not used) | test_dilithium2 PASS (pk 1312 / sig 2420 verified); test_speed2 runs | evML-DSA leaf layer (integrated in evmldsa.c); B3 anchors; B4 rechain |
| cisco/hash-sigs | github.com/cisco/hash-sigs | 44e6c7de934c05942bf17cc819a81e765cfe67d7 (2026-09-04) | BSD-3-Clause (license.txt, Cisco Systems 2017 — verified: redistribution w/ notice OK) | make ✓ (-lcrypto -lpthread; OpenSSL dev present) | bench via scripts/bench_lms.c → raw_results/B1_lms.txt | B1 LMS baseline (LMS_SHA256_N32_H20 — NOTE: plan's M24_H20 macro does not exist in this commit; N32_H20 is the standard set used) |
| XMSS/xmss-reference | github.com/XMSS/xmss-reference | 171ccbd26f098542a67eb5d2b128281c80bd71a6 (2021-03-16) | CC0-1.0 (README + LICENSE) | make ✓ (warnings only) | bench via scripts/bench_xmss.c → raw_results/B2_xmss.txt | B2 XMSS baseline (XMSS-SHA2_10_256; REFERENCE implementation — marked reference-class in paper) |
| Threshold-ML-DSA (not cloned) | github.com/Threshold-ML-DSA/Threshold-ML-DSA | (recon only: fca21f80ed observed 2026-09-05) | **NO LICENSE** | — | — | context citation only; NO code use (per license gate) |

Notes:
- randombytes: pq-crystals ref randombytes.c used as-is (works in WSL2 via getrandom).
- No modifications to any upstream file; our code links them as-is.
- bench_lms.c / bench_xmss.c authored in-project (scripts/), headers document build commands.
