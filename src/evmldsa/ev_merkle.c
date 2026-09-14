#include "ev_merkle.h"
#include "ev_hash.h"
#include <stdlib.h>

/* Level-order layout: levels[0] = root, then level 1 (2 nodes), ...
 * Node at (level l, index i) lives at offset (2^l - 1 + i)*32.
 * Leaf p = node (depth, p). Parent(l,i) -> (l-1, i>>1); children hash pairs. */

static size_t node_off(uint32_t level, uint32_t idx) {
    return (((size_t)1 << level) - 1 + idx) * 32;
}

void ev_merkle_leafdigest(const uint8_t *val, size_t vlen, uint8_t out[32]) {
    uint8_t *buf = malloc(vlen + 1);
    if (!buf) {
        memset(out, 0, 32);
        return;
    }
    buf[0] = EV_DOM_LEAF;
    memcpy(buf + 1, val, vlen);
    ev_sha3_256(buf, vlen + 1, out);
    memset(buf, 0, vlen + 1);
    free(buf);
}

int ev_merkle_build(ev_merkle_tree *mt, const ev_params *par,
                    const uint8_t * const leaf_digests) {
    size_t total_nodes = 2 * ((size_t)1 << par->depth) - 1;
    mt->levels = malloc(total_nodes * 32);
    if (!mt->levels) return -1;
    mt->par = *par;
    mt->mode = 1;
    /* copy leaves into the deepest level */
    size_t leaf_base = node_off(par->depth, 0);
    memcpy(mt->levels + leaf_base, leaf_digests, ((size_t)1 << par->depth) * 32);
    /* build upward */
    for (uint32_t l = par->depth; l > 0; l--) {
        uint32_t cnt = 1u << l;
        for (uint32_t i = 0; i < cnt; i += 2) {
            ev_hash_node(mt->levels + node_off(l, i),
                         mt->levels + node_off(l, i+1),
                         mt->levels + node_off(l-1, i>>1));
        }
    }
    return 0;
}

int ev_merkle_path(const ev_merkle_tree *mt, uint32_t p, uint8_t *out_path) {
    if (!mt->levels) return -1;
    uint32_t idx = p;
    for (uint32_t l = mt->par.depth; l > 0; l--) {
        uint32_t sib = idx ^ 1u;
        memcpy(out_path + (l-1)*32, mt->levels + node_off(l, sib), 32);
        idx >>= 1;
    }
    return 0;
}

int ev_merkle_verify(const uint8_t root[32], const ev_params *par, uint32_t p,
                     const uint8_t leaf_digest[32], const uint8_t *path) {
    uint8_t cur[32], tmp[32];
    memcpy(cur, leaf_digest, 32);
    uint32_t idx = p;
    for (uint32_t l = par->depth; l > 0; l--) {
        const uint8_t *sib = path + (l-1)*32;
        if (idx & 1u) ev_hash_node(sib, cur, tmp);
        else          ev_hash_node(cur, sib, tmp);
        memcpy(cur, tmp, 32);
        idx >>= 1;
    }
    return memcmp(cur, root, 32) == 0 ? 1 : 0;
}

void ev_merkle_free(ev_merkle_tree *mt) {
    free(mt->levels);
    mt->levels = NULL;
}
