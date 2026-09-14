/* C4 construction self-test.  This is intentionally independent of benchmark
 * timing: it exercises both the tree state machine and the complete leaf
 * sign/verify path for the required lifetime sizes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "evmldsa.h"
#include "ev_hash.h"
#include "params.h"

static int fails;
#define CHECK(c, fmt, ...) do { \
    if (!(c)) { fprintf(stderr, "FAIL " fmt "\n", ##__VA_ARGS__); fails++; } \
    else { printf("PASS " fmt "\n", ##__VA_ARGS__); } \
} while (0)

static int state_has(const ev_tree_state *st, const uint8_t seed[EV_SEED_BYTES]) {
    for (uint32_t i = 0; i <= st->par.depth; i++)
        if (!memcmp(st->path[i], seed, EV_SEED_BYTES)) return 1;
    for (uint32_t i = 0; i < st->par.depth; i++)
        if (st->future_valid[i] && !memcmp(st->future[i], seed, EV_SEED_BYTES)) return 1;
    return 0;
}

/* Re-derive every ancestor of q from the known test root and ensure the live
 * state does not retain any of them. */
static int no_past_ancestor(const ev_tree_state *st, const uint8_t root[EV_SEED_BYTES], uint32_t upto) {
    /* For every past leaf q < upto, the full root-to-q path INCLUDING the
     * leaf seed must be absent from the retained state. For the CURRENT
     * leaf (q == upto) only its strict ancestors must be absent: the
     * current leaf seed is legitimately retained at path[depth]. */
    for (uint32_t q = 0; q <= upto; q++) {
        uint8_t node[EV_SEED_BYTES]; memcpy(node, root, sizeof(node));
        if (state_has(st, node)) return 0;
        for (uint32_t level = 0; level < st->par.depth; level++) {
            uint8_t left[EV_SEED_BYTES], right[EV_SEED_BYTES];
            ev_derive_child(node, EV_DOM_LEFT, left);
            ev_derive_child(node, EV_DOM_RIGHT, right);
            memcpy(node, ((q >> (st->par.depth - 1 - level)) & 1u) ? right : left, sizeof(node));
            if (level + 1 < st->par.depth || q < upto) {
                if (state_has(st, node)) return 0;
            }
        }
    }
    return 1;
}

static void run_one(uint32_t T) {
    ev_pk pk; ev_sk sk;
    uint8_t root[EV_SEED_BYTES];
    for (size_t i = 0; i < sizeof(root); i++) root[i] = (uint8_t)(0x42u + i + T);
    CHECK(ev_keygen(&pk, &sk, T, root) == 0, "keygen T=%u", T);
    if (!sk.leaf_sk) return;

    const uint32_t periods[] = {0, 1, T / 2, T - 1};
    const size_t maxsig = ev_sig_bytes(sk.par.depth);
    uint8_t *sig = malloc(maxsig), *bad = malloc(maxsig);
    const uint8_t msg[] = "C4 round-trip";
    for (size_t i = 0; i < sizeof(periods)/sizeof(periods[0]); i++) {
        uint32_t p = periods[i];
        while (sk.tree.current < p) CHECK(ev_evolve(&sk) == 0, "evolve to p=%u", p);
        size_t sl = 0;
        CHECK(ev_sign(&sk, &pk, msg, sizeof(msg)-1, sig, &sl) == 0,
              "sign T=%u p=%u", T, p);
        CHECK(ev_verify(&pk, msg, sizeof(msg)-1, sig, sl) == 0,
              "verify T=%u p=%u", T, p);

        memcpy(bad, sig, sl); bad[3] ^= 1;
        CHECK(ev_verify(&pk, msg, sizeof(msg)-1, bad, sl) != 0,
              "reject wrong period tag T=%u p=%u", T, p);
        memcpy(bad, sig, sl); bad[4 + CRYPTO_BYTES] ^= 1;
        CHECK(ev_verify(&pk, msg, sizeof(msg)-1, bad, sl) != 0,
              "reject wrong v_p T=%u p=%u", T, p);
        memcpy(bad, sig, sl); bad[sl - 1] ^= 1;
        CHECK(ev_verify(&pk, msg, sizeof(msg)-1, bad, sl) != 0,
              "reject corrupted path T=%u p=%u", T, p);
        memcpy(bad, sig, sl); bad[4] ^= 1;
        CHECK(ev_verify(&pk, msg, sizeof(msg)-1, bad, sl) != 0,
              "reject corrupted sigma_F T=%u p=%u", T, p);

        CHECK(no_past_ancestor(&sk.tree, root, p),
              "erasure T=%u after Evolve(%u)", T, p);
    }
    CHECK(ev_evolve(&sk) != 0, "Evolve past T-1 returns error T=%u", T);
    free(sig); free(bad);
    ev_merkle_free(&sk.mt);
    free(sk.leaf_pk); free(sk.leaf_sk);
}

int main(void) {
    run_one(1u << 8);
    run_one(1u << 10);
    run_one(1u << 16);
    printf(fails ? "C4 SELFTEST: %d FAILURES\n" : "C4 SELFTEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
