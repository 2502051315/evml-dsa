#ifndef EV_HASH_H
#define EV_HASH_H
#include <stdint.h>
#include <stddef.h>

/* SHA3-256 wrapper. Implementation links against fips202.c (pq-crystals,
 * CC0) when built with -DEV_USE_FIPS202; otherwise a bundled standalone
 * SHA3-256 (public-domain style, self-tested against known vectors in
 * ev_selftest.c) is used. Interface identical either way. */
void ev_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);

/* H(dom || seed): GGM child derivation. Inputs are exactly 33 bytes. */
void ev_derive_child(const uint8_t seed[EV_SEED_BYTES], uint8_t dom, uint8_t out[EV_SEED_BYTES]);

/* Merkle inner node: H(0x04 || L || R) */
void ev_hash_node(const uint8_t L[32], const uint8_t R[32], uint8_t out[32]);

/* H(0x07 || rho || p_be32), the public per-period matrix seed. */
void ev_period_rho(const uint8_t rho[32], uint32_t period, uint8_t out[32]);
#endif
