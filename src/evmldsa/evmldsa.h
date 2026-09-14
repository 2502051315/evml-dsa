#ifndef EVMLDSA_H
#define EVMLDSA_H
/* evML-DSA — forward-secure key-evolving signature, ML-DSA (FIPS 204) native.
 * Leaf layer: pq-crystals Dilithium reference code (CC0), deterministic keypair
 * from (rho, zeta) derived from the GGM leaf seed. Tree layer: this project. */

#include "ev_params.h"
#include "ev_seedtree.h"
#include "ev_merkle.h"

/* Sizes (ML-DSA-44 class; adjust if built with -DDILITHIUM_MODE=2|3) */
/* pq-crystals headers provide CRYPTO_PUBLICKEYBYTES etc. after integration. */

typedef struct {
    ev_params par;
    uint8_t rho[32];      /* FIPS-204-style public seed expanding A */
    uint8_t root[32];     /* Merkle root over all period t_p commitments */
} ev_pk;                  /* serialized: 32 + 32 + 4 bytes */

typedef struct {
    ev_params par;
    ev_tree_state tree;   /* current period seed-tree state (erasing secrets) */
    ev_merkle_tree mt;    /* commitment tree. Prototype: FULL-tree mode (2T-1
                             hashes; 64 MB @T=2^20). Path nodes are PUBLIC
                             values — storing them does not affect erasure
                             semantics (only seed material must be erased).
                             Fractal/pebbled O(log^2 T) management is the
                             standard optimization (Szydlo'04; RFC 8391),
                             cited; steady-state sign/verify unaffected. */
    uint8_t rho[32];            /* public master rho (copy of pk.rho) */
    uint8_t leaf_rho[32];       /* rho_p for the currently cached leaf */
    uint8_t *leaf_pk, *leaf_sk; /* cached current-period FSwA keypair
                                   (public+secret; recomputed at each Evolve;
                                   part of signer state, NOT part of erasure
                                   semantics beyond period advance) */
} ev_sk;

/* randombytes bridge: uses pq-crystals randombytes() */
int ev_randombytes(uint8_t *out, size_t n);

/* Maximum signature size: FSwA sig + t_p + path + p. Concrete sizes resolved
 * from pq-crystals params at build time (see evmldsa.c). */
size_t ev_sig_bytes(uint32_t depth);

int  ev_keygen(ev_pk *pk, ev_sk *sk, uint32_t T /* power of 2 */,
               uint8_t root_seed_in[EV_SEED_BYTES] /* optional; NULL = random */);

/* Sign m at current period; sig layout: [p(4) | FSwA-sig | t_p | path]. */
int  ev_sign(const ev_sk *sk, const ev_pk *pk, const uint8_t *m, size_t mlen,
             uint8_t *sig, size_t *siglen);

/* Evolve to next period (erases past material). */
int  ev_evolve(ev_sk *sk);

int  ev_verify(const ev_pk *pk, const uint8_t *m, size_t mlen,
               const uint8_t *sig, size_t siglen);

/* Deterministic leaf-key expansion exposed for benchmarking: from leaf seed to
 * (packed t_p) using the same functions pq-crystals keypair uses. */
void ev_leaf_t_commit(const uint8_t rho[32], uint32_t period,
                      const uint8_t leaf_seed[EV_SEED_BYTES],
                      uint8_t *t_packed_out /* CRYPTO_PUBLICKEYBYTES-ish */);

/* Exposed for tests and benchmark instrumentation. */
void ev_matrix_seed(const uint8_t rho[32], uint32_t period, uint8_t out[32]);
#endif
