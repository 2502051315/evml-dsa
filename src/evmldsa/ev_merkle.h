#ifndef EV_MERKLE_H
#define EV_MERKLE_H
#include "ev_params.h"

/* Merkle tree over the T period commitment values (each value = packed t_p
 * bytes, arbitrary length; leaf hash = SHA3-256(0x06 || value), while inner
 * nodes use SHA3-256(0x04 || L || R).
 *
 * Two management modes (both reported honestly in the paper):
 *   EV_MERKLE_FULL  : whole tree in memory (2T-1 hashes) — used for T<=2^16
 *                     in benchmarks; also used at KeyGen for any T.
 *   EV_MERKLE_RECOMPUTE: no tree storage; auth path for leaf p recomputed on
 *                     demand by re-deriving the sibling subtrees from the GGM
 *                     seed-tree state (cost reported; fractal/pebbling is the
 *                     standard asymptotic optimization, cited, not needed for
 *                     the prototype's steady-state benchmarks). */

typedef struct {
    ev_params par;
    uint8_t *levels;        /* (2T-1) * 32 bytes, level-order; NULL in RECOMPUTE */
    int mode;
} ev_merkle_tree;

/* Build a full tree from T leaf values (values already hashed into 32B leaf
 * digests by caller or here via values/valuelens). */
int ev_merkle_build(ev_merkle_tree *mt, const ev_params *par,
                    const uint8_t * const leaf_digests /* T * 32 */);

/* Auth path for leaf p (writes depth*32 bytes). Requires FULL mode or
 * recompute callback supply. */
int ev_merkle_path(const ev_merkle_tree *mt, uint32_t p, uint8_t *out_path);

/* Verifier-side: check path. leaf_digest = SHA3-256(0x06 || value). */
int ev_merkle_verify(const uint8_t root[32], const ev_params *par, uint32_t p,
                     const uint8_t leaf_digest[32], const uint8_t *path);

void ev_merkle_free(ev_merkle_tree *mt);

/* helper: hash a value of any length to its leaf digest */
void ev_merkle_leafdigest(const uint8_t *val, size_t vlen, uint8_t out[32]);

#endif
