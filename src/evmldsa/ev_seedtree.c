#include "ev_seedtree.h"
#include "ev_hash.h"

/* Leaf index bit-navigation: leaf p's path is determined by the depth bits of p
 * (MSB first). current path node at level L covers leaves
 * [ (p >> (depth-L)) << (depth-L), ... + 2^(depth-L) ). */

static uint32_t level_index(uint32_t leaf, uint32_t depth, uint32_t level) {
    /* node index (within its level) on the path to `leaf` */
    return leaf >> (depth - level);
}

void ev_tree_init(ev_tree_state *st, const ev_params *par, const uint8_t root_seed[EV_SEED_BYTES]) {
    memset(st, 0, sizeof(*st));
    st->par = *par;
    st->current = 0;
    memcpy(st->path[0], root_seed, EV_SEED_BYTES);
    /* descend from root to leaf 0, deriving right siblings on the way.
     * ERASURE CRITICAL: each path node seed is zeroed as soon as its two
     * children are derived (derive-and-discard / GGM puncture semantics).
     * Retained secrets = current leaf seed + right-side future frontier
     * ONLY — no ancestor of any (past) leaf remains in the state. */
    for (uint32_t lvl = 0; lvl < par->depth; lvl++) {
        ev_derive_child(st->path[lvl], EV_DOM_LEFT,  st->path[lvl+1]);
        ev_derive_child(st->path[lvl], EV_DOM_RIGHT, st->future[lvl]);
        st->future_valid[lvl] = 1;
        memset(st->path[lvl], 0, EV_SEED_BYTES);   /* discard parent */
    }
}

void ev_tree_leaf(const ev_tree_state *st, uint8_t out[EV_SEED_BYTES]) {
    memcpy(out, st->path[st->par.depth], EV_SEED_BYTES);
}

int ev_tree_advance(ev_tree_state *st) {
    uint32_t p = st->current;
    uint32_t depth = st->par.depth;
    if (p + 1 >= st->par.T) return -1;

    /* Branch point = SHALLOWEST level where path-node indices of p and p+1
     * differ (i.e., below the longest common prefix of their bit paths).
     * Scan top-down; first mismatch at level `diff_level` means the child edge
     * (diff_level-1)->diff_level turns RIGHT there. */
    uint32_t diff_level = depth;
    for (uint32_t lvl = 1; lvl <= depth; lvl++) {
        if (level_index(p, depth, lvl) != level_index(p+1, depth, lvl)) {
            diff_level = lvl;
            break;
        }
    }
    /* Erase everything below the branch point on the current path, then take
     * the stored FUTURE sibling at diff_level-1 as the new path node. */
    uint32_t parent = diff_level - 1;
    if (!st->future_valid[parent]) return -2;  /* state corruption guard */
    memcpy(st->path[diff_level], st->future[parent], EV_SEED_BYTES);
    st->future_valid[parent] = 0;              /* consumed */
    memset(st->future[parent], 0, EV_SEED_BYTES);
    /* ERASURE CRITICAL: all common ancestors of p and p+1 (path nodes above
     * the branch point) are exactly the nodes from which PAST leaf seeds
     * (including any leaf in p's subtree) can be re-derived. Discard them. */
    for (uint32_t lvl = 0; lvl < diff_level; lvl++)
        memset(st->path[lvl], 0, EV_SEED_BYTES);
    /* descend to the new leftmost leaf, deriving-and-discarding as in init */
    for (uint32_t lvl = diff_level; lvl < depth; lvl++) {
        ev_derive_child(st->path[lvl], EV_DOM_LEFT,  st->path[lvl+1]);
        ev_derive_child(st->path[lvl], EV_DOM_RIGHT, st->future[lvl]);
        st->future_valid[lvl] = 1;
        memset(st->path[lvl], 0, EV_SEED_BYTES);   /* discard parent */
    }
    st->current = p + 1;
    return 0;
}

size_t ev_tree_descents(const ev_tree_state *st) {
    /* number of GGM derivations from root to reach current leaf state */
    size_t n = 0;
    for (uint32_t lvl = 0; lvl < st->par.depth; lvl++)
        if (st->future_valid[lvl]) n += 2;   /* left + right derivations */
    return n;
}
