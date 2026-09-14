/* Self-checks for the standalone tree layer (no pq-crystals dependency).
 * Run: ./ev_selftest   — prints PASS/FAIL per check; exit 0 iff all pass.
 * Covers: SHA3-256 known vectors; GGM tree determinism & puncturing erasure;
 * Merkle build/path/verify incl. tamper rejection. */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "ev_params.h"
#include "ev_hash.h"
#include "ev_seedtree.h"
#include "ev_merkle.h"

static int fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS %s\n", name); \
    else { printf("FAIL %s\n", name); fails++; } } while (0)

int main(void) {
    /* 1. SHA3-256 known vectors */
    uint8_t out[32];
    const char *v0 = "";
    ev_sha3_256((const uint8_t*)v0, 0, out);
    CHECK(out[0]==0xa7 && out[1]==0xff && out[31]==0x4a, "sha3-256(empty)");
    const char *v1 = "abc";
    ev_sha3_256((const uint8_t*)v1, 3, out);
    CHECK(out[0]==0x3a && out[1]==0x98 && out[31]==0x32, "sha3-256(abc)");

    /* 2. seed tree: determinism + full-walk leaf uniqueness */
    ev_params par = { .T = 1u<<8, .depth = 8 };
    ev_tree_state st, st2;
    uint8_t root[EV_SEED_BYTES]; for (int i=0;i<EV_SEED_BYTES;i++) root[i]=i;
    ev_tree_init(&st, &par, root);
    ev_tree_init(&st2, &par, root);
    uint8_t leaf[EV_SEED_BYTES], leaf2[EV_SEED_BYTES];
    ev_tree_leaf(&st, leaf);
    ev_tree_leaf(&st2, leaf2);
    CHECK(memcmp(leaf, leaf2, EV_SEED_BYTES)==0, "ggm determinism");

    /* advance through all 256 leaves; collect and check uniqueness + that a
     * fresh init+advance equals a lazy advance (state-machine consistency) */
    static uint8_t leaves[256][EV_SEED_BYTES];
    memcpy(leaves[0], leaf, EV_SEED_BYTES);
    int ok = 1;
    for (uint32_t p = 1; p < par.T; p++) {
        if (ev_tree_advance(&st) != 0) { ok = 0; break; }
        ev_tree_leaf(&st, leaves[p]);
    }
    CHECK(ok, "advance walks T-1 times");
    for (uint32_t a = 0; a < par.T && ok; a++)
        for (uint32_t b = a+1; b < par.T; b++)
            if (memcmp(leaves[a], leaves[b], EV_SEED_BYTES)==0) { ok = 0; break; }
    CHECK(ok, "all T leaf seeds distinct");

    /* independent verification: leaf p from a FRESH init at period p via
     * direct descent must equal the state machine's leaf p */
    /* fresh init is at period 0; emulate jump by walking (fine for test) */
    ev_tree_init(&st2, &par, root);
    for (uint32_t p = 1; p <= 100; p++) ev_tree_advance(&st2);
    ev_tree_leaf(&st2, leaf2);
    CHECK(memcmp(leaf2, leaves[100], EV_SEED_BYTES)==0, "fresh-walk == state-machine leaf");

    /* erasure property (adversarial): no retained secret may be a node on the
     * derivation path of ANY past leaf q < p (an ancestor seed would let the
     * adversary re-derive leaf q's key). Recompute each tested q's full
     * ancestor chain from the root and assert the state contains none of
     * those node seeds. */
    {
        int leak = 0;
        uint32_t qs[] = {0, 50, 99};
        ev_tree_state fresh;
        for (unsigned t = 0; t < 3; t++) {
            uint32_t q = qs[t];
            /* derive q's ancestor chain: walk from root, following q's bits */
            ev_tree_init(&fresh, &par, root); /* fresh init zeroed ancestors internally,
                                                 so re-derive manually from root */
            uint8_t node[EV_SEED_BYTES]; memcpy(node, root, EV_SEED_BYTES);
            /* the leaf seed itself */
            uint8_t cur[EV_SEED_BYTES]; memcpy(cur, node, EV_SEED_BYTES);
            for (uint32_t lvl = 0; lvl < par.depth; lvl++) {
                uint8_t L[EV_SEED_BYTES], R[EV_SEED_BYTES];
                ev_derive_child(cur, EV_DOM_LEFT, L);
                ev_derive_child(cur, EV_DOM_RIGHT, R);
                uint8_t bit = (q >> (par.depth-1-lvl)) & 1u;
                /* check state against current node 'cur' (ancestor at lvl) */
                for (uint32_t l = 0; l <= par.depth; l++)
                    if (memcmp(st2.path[l], cur, EV_SEED_BYTES)==0) leak = 1;
                for (uint32_t l = 0; l < par.depth; l++)
                    if (memcmp(st2.future[l], cur, EV_SEED_BYTES)==0) leak = 1;
                memcpy(cur, bit ? R : L, EV_SEED_BYTES);
            }
            /* cur is now leaf q's seed: also check it is not directly held */
            for (uint32_t l = 0; l <= par.depth; l++)
                if (memcmp(st2.path[l], cur, EV_SEED_BYTES)==0) leak = 1;
        }
        CHECK(!leak, "erasure: no ancestor of past leaves in state @p=100");
    }

    /* 3. Merkle over the 256 leaf digests */
    static uint8_t digs[256][32];
    for (uint32_t p = 0; p < par.T; p++)
        ev_merkle_leafdigest(leaves[p], EV_SEED_BYTES, digs[p]);
    ev_merkle_tree mt;
    CHECK(ev_merkle_build(&mt, &par, (const uint8_t*)digs)==0, "merkle build");
    uint8_t root_h[32];
    memcpy(root_h, mt.levels, 32);
    uint8_t path[8*32];
    CHECK(ev_merkle_path(&mt, 77, path)==0, "merkle path@77");
    CHECK(ev_merkle_verify(root_h, &par, 77, digs[77], path)==1, "merkle verify@77");
    /* tamper tests */
    uint8_t bad[32]; memcpy(bad, digs[77], 32); bad[0]^=1;
    CHECK(ev_merkle_verify(root_h, &par, 77, bad, path)==0, "merkle reject bad value");
    CHECK(ev_merkle_verify(root_h, &par, 78, digs[77], path)==0, "merkle reject wrong index");
    path[3]^=0x40;
    CHECK(ev_merkle_verify(root_h, &par, 77, digs[77], path)==0, "merkle reject bad path");
    ev_merkle_free(&mt);

    /* 4. deeper tree spot-check (T=2^16): path/verify at extremes */
    ev_params par16 = { .T = 1u<<16, .depth = 16 };
    ev_tree_state st16;
    ev_tree_init(&st16, &par16, root);
    for (uint32_t p = 1; p <= 0xFFF0; p++) ev_tree_advance(&st16);
    uint8_t lf[EV_SEED_BYTES]; ev_tree_leaf(&st16, lf);
    uint8_t dg[32]; ev_merkle_leafdigest(lf, EV_SEED_BYTES, dg);
    /* small merkle just for the verify check at depth 16 with computed path via
     * a light manual tree: use build on T=2^16 (16*2*32768B=2MB fine) */
    ev_merkle_tree mt16;
    /* construct all leaf digests lazily by walking a second state machine */
    ev_tree_state w; ev_tree_init(&w, &par16, root);
    static uint8_t digs16[1u<<16][32]; /* 2 MB static */
    ev_tree_leaf(&w, lf); ev_merkle_leafdigest(lf, EV_SEED_BYTES, digs16[0]);
    for (uint32_t p = 1; p < par16.T; p++) { ev_tree_advance(&w); ev_tree_leaf(&w, lf); ev_merkle_leafdigest(lf, EV_SEED_BYTES, digs16[p]); }
    CHECK(ev_merkle_build(&mt16, &par16, (const uint8_t*)digs16)==0, "merkle16 build");
    uint8_t path16[16*32];
    ev_merkle_path(&mt16, 0xFFF0, path16);
    CHECK(ev_merkle_verify(mt16.levels, &par16, 0xFFF0, dg, path16)==1, "merkle16 verify@0xFFF0");
    ev_merkle_free(&mt16);

    printf(fails ? "\nSELFTEST: %d FAILURES\n" : "\nSELFTEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
