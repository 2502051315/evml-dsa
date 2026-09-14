# FIPS-204 / ML-DSA security-figure verification — Theorem 2 (archive_paper1)

Date: 2026-09-07. All primary sources downloaded and full-text checked (PDFs kept in `C:\Users\Suzeyan\fips204_verify\`).

**Sources**

| ID | Source | URL |
|---|---|---|
| SPEC-r3v31 | CRYSTALS-Dilithium spec v3.1 (round 3, 2021-02-08) | https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf |
| SPEC-r3v30 | CRYSTALS-Dilithium spec v3.0 (round 3, initial) | https://pq-crystals.org/dilithium/data/dilithium-specification-round3.pdf |
| SPEC-r2 | CRYSTALS-Dilithium spec round 2 (2019-03-30) | https://pq-crystals.org/dilithium/data/dilithium-specification-round2.pdf |
| KLS18 | Kiltz–Lyubashevsky–Schaffner, EUROCRYPT 2018 | https://eprint.iacr.org/2017/916 |
| FIPS204 | FIPS 204 final (published 2024-08-13) | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf (DOI 10.6028/NIST.FIPS.204) |

**Reference values — SPEC-r3v31 Table 1, p. 8 (identical in v3.0); header "NIST Security Level 2 / 3 / 5"**

| Parameter set (= ML-DSA) | MLWE classical core-SVP | MLWE quantum core-SVP | MSIS classical core-SVP (paren. = strong-unforgeable variant) | MSIS quantum (SUF) | refined analysis, log2 classical gates (App. C.5) |
|---|---|---|---|---|---|
| Dilithium2 (= ML-DSA-44, Cat 2) | **123** | 112 | 123 (121) | 112 (110) | 159 |
| Dilithium3 (= ML-DSA-65, Cat 3) | **182** | 165 | 186 (176) | 169 (159) | 217 |
| Dilithium5 (= ML-DSA-87, Cat 5) | 252 | 229 | 265 (253) | 241 (230) | 285 |

## Verification table

| # | Claimed (manuscript, Thm 2) | Verified against primary source | Source (URL + section/table) | Verdict |
|---|---|---|---|---|
| 1 | ML-DSA-44 "core-SVP strength ... ≈2^123 classical" | MLWE classical core-SVP = **2^123** (quantum 2^112; MSIS 2^123 / 2^121-SUF). NIST level 2. | SPEC-r3v31 Table 1, p. 8 (https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf) | **CONFIRMED** |
| 2 | "Adv^euf-cma(ML-DSA-44) ≤ 2^-118 for ≤2^60 hash/signing queries — conservative reading of the round-3 concrete analysis, 5 bits of slack" | Round-3 concrete analysis (SPEC §6.2, Eq. 6): Adv^SUF-CMA ≤ Adv^MLWE + Adv^SelfTargetMSIS + Adv^MSIS + 2^-254, with reduction loss "within a small multiplicative factor" (tight). **No Q_H/Q_S-dependent term exists at any query bound** — the 2^-118 bound is valid and conservative (the tight reading supports ≈2^-122/2^-123). However, the "5 bits of query slack" attribution is wrong: in KLS18 the generic ROM loss is *linear* in Q_H (QROM: quadratic, 8(Q_H+1)^2·ε_ls + m·Q_S·ε_zk + 2^-p+1, Thm 3.1/3.2), which for Dilithium's parameters is entirely absorbed into the 2^-254 residual; the only query loss in the classical ROM is the *non-tight* forking reduction SelfTargetMSIS→MSIS, which costs a full factor Q_H (= 60 bits at 2^60) and is explicitly rejected by the spec for parameter setting ("not particularly useful ... due to its lack of tightness"). So the slack is 5 bits of *arbitrary margin*, not a query penalty. | SPEC-r3v31 §6.2 Eq. (6) + text after Eq. (8); KLS18 https://eprint.iacr.org/2017/916 Thm 3.1–3.2 (incl. note "In the classical ROM ... linearly on Q_H, instead of quadratic") and §4.5.1 (forking loss 1/Q_H) | **CONFIRMED (bound) / CORRECTED (justification: cite Eq. (6) tightness, not "query slack")** |
| 3 | KLS concrete analysis cited as "Kiltz–Lyubashevsky–Schaffner, ePrint 2017/633" | ePrint **2017/633 is a different paper**: "CRYSTALS – Dilithium: Digital Signatures from Module Lattices" (Ducas, Lepoint, Lyubashevsky, Schwabe, Seiler, Stehlé). The KLS concrete ROM/QROM treatment is "A Concrete Treatment of Fiat-Shamir Signatures in the Quantum Random-Oracle Model" = **ePrint 2017/916**, EUROCRYPT 2018 — same paper the round-3 spec cites as [KLS18] and FIPS-204 as ref [16]. | https://eprint.iacr.org/2017/633 vs https://eprint.iacr.org/2017/916; FIPS-204 ref [16] | **CORRECTED-TO ePrint 2017/916** |
| 4 | ML-DSA-65 "core-SVP figure ≈2^189 classical" (Dilithium3) | **2^189 appears in no pq-crystals Dilithium specification** (checked round-2 2019, round-3 v3.0, round-3 v3.1). Round-3 table (v3.0 = v3.1): MLWE classical core-SVP = **2^182** (quantum 2^165); MSIS classical = **2^186** (2^176 for the strong-unforgeable variant); refined gate-count estimate 2^217 classical. NIST level 3. | SPEC-r3v31 Table 1, p. 8 (also SPEC-r3v30, same values); SPEC-r2 Table (round 2 uses a "best-known-attack-cost" scale: 141/174 classical — no 189) | **CORRECTED-TO 2^182 (MLWE classical core-SVP); 2^186 only if the MSIS/SUF figure is meant** |
| 5 | "ML-DSA-65: leaf bound 2^-160 → composite 2^-139" | Externally checkable input is only the hardness figure (row 4). Re-based on 2^182, the leaf's margin over classical core-SVP is 22 bits (not 29); 2^-160 < 2^-182 still holds, so the leaf bound remains conservative. The composite 2^-139 is a paper-internal composition step — not verifiable against primary sources. | — (derivation internal to archive_paper1) | **SUPPORTED after re-basing on 182; margins must be restated** |
| 6 | FIPS-204 final (Aug 2024) as restatement of security strength | Yes — and it is the better cite for strength *categories*, not bits: FIPS-204 §4, Table 1 "ML-DSA parameter sets", last row: "Claimed security strength: Category 2 / Category 3 / Category 5" for ML-DSA-44/65/87; §4 text: "ML-DSA-44 is claimed to be in security strength category 2, ML-DSA-65 ... category 3, and ML-DSA-87 ... category 5 [6]" (ref [6] = Dilithium v3.1 spec). FIPS-204 contains **no core-SVP bit figures** — keep the round-3 Table 1 as the cite for 2^123 / 2^182. Caution: categories are **2/3/5**, not "L1/L3/L5" (Category 1 = AES-128 key search; Category 2 = SHA-256-collision level, SP 800-57 Pt.1 §5.6). Also §3.6.1: with a 128-bit-strength RBG, ML-DSA-44's claim drops Category 2 → Category 1. ML-DSA ≈ Dilithium v3.1 + editorial changes (FIPS-204 App. D) that do not affect MLWE/MSIS hardness. | FIPS-204 §4 (Table 1), §3.6.1, App. D (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) | **CONFIRMED — cite FIPS-204 for "Category 2/3", round-3 Table 1 for bit figures** |
| 7 | (context, not in manuscript) Proof-validity caveat post-round-3 | Barbosa, Barthe, Doczkal, Don, Fehr, Grégoire, Huang, Hülsing, Lee, Wu, "Fixing and Mechanizing the Security Proof of Fiat-Shamir with Aborts and Dilithium" (ePrint 2023/246) found a gap in the CMA→NMA step of KLS18-style ROM/QROM proofs and repaired it; security conclusions for Dilithium unchanged. Cite proactively if a reviewer questions the KLS18 proof. | https://eprint.iacr.org/2023/246 | NOTE |

## Theorem-2 edit required

**Edit:** replace "core-SVP ≈2^189 classical" with "2^182 classical core-SVP (MLWE; 2^186 for MSIS)" for ML-DSA-65 and restate the margin (22, not 29, bits above the 2^-160 leaf; 2^-139 composite unchanged if re-derived against 182); re-cite KLS as ePrint **2017/916** (2017/633 is the Dilithium scheme paper); reword the ML-DSA-44 clause from "5 bits of query slack" to "tight reduction per round-3 spec Eq. (6) — Adv ≤ Adv^MLWE + Adv^SelfTargetMSIS + Adv^MSIS + 2^-254, no query-dependent loss at Q ≤ 2^60 — leaving ≥5 bits of margin below the 2^123 classical core-SVP figure"; optionally cite FIPS-204 §4 Table 1 for the Category 2/3 designations (never "L1/L3/L5").
