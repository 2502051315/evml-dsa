#ifndef EV_SEEDTREE_H
#define EV_SEEDTREE_H
#include "ev_params.h"

/* GGM puncturable binary seed tree over T = 2^depth periods (leaf p = period p).
 * State kept by the signer:
 *   - path[]     : seed of each node on the CURRENT path root->leaf p  (depth+1 entries)
 *   - future[][] : seed of the RIGHT sibling of each path node whose subtree
 *                  contains only periods > p (i.e., future frontier)
 * Erasure semantics: when advancing to leaf p+1, all state allowing
 * re-derivation of periods <= p is discarded (left-side nodes dropped);
 * past seeds are information-theoretically unrecoverable from the state. */

typedef struct {
    ev_params par;
    uint32_t current;                    /* current period index (0-based) */
    uint8_t path[EV_MAX_DEPTH+1][EV_SEED_BYTES];      /* node seeds on current path */
    uint8_t future[EV_MAX_DEPTH][EV_SEED_BYTES];      /* right-sibling frontier (valid per active mask) */
    int      future_valid[EV_MAX_DEPTH];             /* which frontier entries are live */
} ev_tree_state;

/* Initialize at period 0 from the root seed (KeyGen). */
void ev_tree_init(ev_tree_state *st, const ev_params *par, const uint8_t root_seed[EV_SEED_BYTES]);

/* Derive the leaf seed of the CURRENT period (deterministic; no state change). */
void ev_tree_leaf(const ev_tree_state *st, uint8_t out[EV_SEED_BYTES]);

/* Advance to period p+1 (Evolve). Discards past-derivable material.
 * Returns 0 on success, -1 if already at last period. */
int ev_tree_advance(ev_tree_state *st);

/* Total number of one-way derivations needed to reach leaf p from root
 * (diagnostics; O(depth) after init). */
size_t ev_tree_descents(const ev_tree_state *st);

#endif
