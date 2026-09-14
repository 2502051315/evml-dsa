/* evML-DSA integration layer: GGM/Merkle tree (this project) + FSwA leaf
 * layer (pq-crystals Dilithium reference, CC0).  The default construction uses
 * an independent public rho and a domain-separated matrix seed rho_p per leaf;
 * EVMLDSA_LEGACY=1 restores the old shared-matrix variant. */
#include "evmldsa.h"
#include "ev_hash.h"
#include <stdlib.h>
#include <string.h>

/* pq-crystals API (DILITHIUM_MODE selects 44/65/87 at compile time) */
#include "api.h"
#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "sign.h"
#include "fips202.h"
#include "randombytes.h"

size_t ev_sig_bytes(uint32_t depth) {
    return 4 + CRYPTO_BYTES + (K*POLYT1_PACKEDBYTES) + depth*EV_HASH_BYTES;
}

/* Deterministic leaf keypair: A from SHARED rho; (s1,s2) from leaf seed.
 * Mirrors crypto_sign_keypair's expansion exactly, replacing its randombytes. */
static void ev_leaf_keypair(const uint8_t rho_p[SEEDBYTES],
                            const uint8_t leaf_seed[EV_SEED_BYTES],
                            uint8_t leaf_pk[CRYPTO_PUBLICKEYBYTES],
                            uint8_t leaf_sk[CRYPTO_SECRETKEYBYTES]) {
    uint8_t exp[CRHBYTES + SEEDBYTES];
    const uint8_t *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;
    uint8_t tr[TRBYTES], buf[3 + EV_SEED_BYTES];

    buf[0] = EV_DOM_LEAFKEY;
    /* enc(k) || enc(l) are one-byte canonical parameter encodings. */
    buf[1] = (uint8_t)K;
    buf[2] = (uint8_t)L;
    memcpy(buf+3, leaf_seed, EV_SEED_BYTES);
    shake256(exp, sizeof(exp), buf, sizeof(buf));
    rhoprime = exp;             /* first CRHBYTES bytes: s1/s2 seed */
    key = exp + CRHBYTES;       /* final SEEDBYTES bytes: signing key seed */

    polyvec_matrix_expand(mat, rho_p);
    polyvecl_uniform_eta(&s1, rhoprime, 0);
    polyveck_uniform_eta(&s2, rhoprime, L);

    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);
    polyveck_add(&t1, &t1, &s2);
    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);

    pack_pk(leaf_pk, rho_p, &t1);
    shake256(tr, TRBYTES, leaf_pk, CRYPTO_PUBLICKEYBYTES);
    pack_sk(leaf_sk, rho_p, tr, key, &t0, &s1, &s2);
}

void ev_matrix_seed(const uint8_t rho[32], uint32_t period, uint8_t out[32]) {
#if EVMLDSA_LEGACY
    (void)period;
    memcpy(out, rho, 32);
#else
    ev_period_rho(rho, period, out);
#endif
}

void ev_leaf_t_commit(const uint8_t rho[32], uint32_t period,
                      const uint8_t leaf_seed[EV_SEED_BYTES],
                      uint8_t *t_packed_out) {
    uint8_t lpk[CRYPTO_PUBLICKEYBYTES], lsk[CRYPTO_SECRETKEYBYTES];
    uint8_t rho_p[32];
    ev_matrix_seed(rho, period, rho_p);
    ev_leaf_keypair(rho_p, leaf_seed, lpk, lsk);
    memcpy(t_packed_out, lpk + SEEDBYTES, K*POLYT1_PACKEDBYTES); /* t1 only */
    /* scrub stack copies of sk material */
    memset(lsk, 0, sizeof(lsk));
    memset(lpk, 0, sizeof(lpk));
}

int ev_keygen(ev_pk *pk, ev_sk *sk, uint32_t T, uint8_t root_seed_in[EV_SEED_BYTES]) {
    if (T == 0 || (T & (T-1)) || T > (1u<<EV_MAX_DEPTH)) return -1;
    uint32_t depth = 0; while ((1u<<depth) < T) depth++;
    sk->par.T = T; sk->par.depth = depth;
    pk->par = sk->par;

    uint8_t root_seed[EV_SEED_BYTES];
    if (root_seed_in) memcpy(root_seed, root_seed_in, EV_SEED_BYTES);
    else { if (ev_randombytes(root_seed, EV_SEED_BYTES)) return -2; }

    /* New: sample rho independently of the seed-tree root.  Legacy keeps the
     * historical root-derived value for regression comparisons. */
#if EVMLDSA_LEGACY
    ev_sha3_256(root_seed, EV_SEED_BYTES, pk->rho);
#else
    if (ev_randombytes(pk->rho, sizeof(pk->rho))) { memset(root_seed, 0, sizeof(root_seed)); return -2; }
#endif
    memcpy(sk->rho, pk->rho, SEEDBYTES);

    /* GGM tree state at period 0 */
    ev_tree_init(&sk->tree, &sk->par, root_seed);

    /* commitment digests for ALL leaves: t1_packed -> leaf digest */
    uint8_t *digs = malloc((size_t)T * EV_HASH_BYTES);
    if (!digs) return -3;
    ev_tree_state walk = sk->tree;   /* independent walker */
    for (uint32_t p = 0; p < T; p++) {
        uint8_t leaf_seed[EV_SEED_BYTES], t1[K*POLYT1_PACKEDBYTES];
        ev_tree_leaf(&walk, leaf_seed);
        ev_leaf_t_commit(pk->rho, p, leaf_seed, t1);
        ev_merkle_leafdigest(t1, K*POLYT1_PACKEDBYTES, digs + (size_t)p*EV_HASH_BYTES);
        if (p + 1 < T) ev_tree_advance(&walk);
    }
    if (ev_merkle_build(&sk->mt, &sk->par, digs) != 0) { free(digs); return -4; }
    memcpy(pk->root, sk->mt.levels, EV_HASH_BYTES);
    free(digs);

    /* cache current leaf keypair (recomputed on each Evolve) */
    sk->leaf_sk = malloc(CRYPTO_SECRETKEYBYTES);
    sk->leaf_pk = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t leaf_seed[EV_SEED_BYTES];
    ev_tree_leaf(&sk->tree, leaf_seed);
    ev_matrix_seed(pk->rho, 0, sk->leaf_rho);
    ev_leaf_keypair(sk->leaf_rho, leaf_seed, sk->leaf_pk, sk->leaf_sk);
    return 0;
}

int ev_randombytes(uint8_t *out, size_t n) {
    randombytes(out, n); /* pq-crystals ref: void return, aborts on failure */
    return 0;
}

int ev_evolve(ev_sk *sk) {
    if (ev_tree_advance(&sk->tree) != 0) return -1;
    /* recompute cached leaf keypair at the new period (old keys scrubbed) */
    uint8_t leaf_seed[EV_SEED_BYTES];
    ev_tree_leaf(&sk->tree, leaf_seed);
    memset(sk->leaf_sk, 0, CRYPTO_SECRETKEYBYTES);
    ev_matrix_seed(sk->rho, sk->tree.current, sk->leaf_rho);
    ev_leaf_keypair(sk->leaf_rho, leaf_seed, sk->leaf_pk, sk->leaf_sk);
    memset(leaf_seed, 0, sizeof(leaf_seed));
    return 0;
}

int ev_sign(const ev_sk *sk, const ev_pk *pk, const uint8_t *m, size_t mlen,
            uint8_t *sig, size_t *siglen) {
    (void)pk; /* signer does not need pk: rho cached in sk, tree carries paths */
    /* composite message: DOM || p (BE32) || m  — binds period into FSwA input */
    size_t clen = 1 + 4 + mlen;
    uint8_t *cm = malloc(clen);
    if (!cm) return -1;
    cm[0] = EV_DOM_M;
    cm[1] = (sk->tree.current >> 24) & 0xff;
    cm[2] = (sk->tree.current >> 16) & 0xff;
    cm[3] = (sk->tree.current >>  8) & 0xff;
    cm[4] = (sk->tree.current      ) & 0xff;
    memcpy(cm + 5, m, mlen);

    uint8_t *s = sig;
    s[0] = cm[1]; s[1] = cm[2]; s[2] = cm[3]; s[3] = cm[4]; s += 4;
    size_t sl = CRYPTO_BYTES;
    if (crypto_sign_signature(s, &sl, cm, clen, NULL, 0, sk->leaf_sk) != 0) {
        free(cm); return -2;
    }
    s += sl;
    memcpy(s, sk->leaf_pk + SEEDBYTES, K*POLYT1_PACKEDBYTES); s += K*POLYT1_PACKEDBYTES;
    if (ev_merkle_path(&sk->mt, sk->tree.current, s) != 0) { free(cm); return -3; }
    s += sk->par.depth * EV_HASH_BYTES;
    *siglen = (size_t)(s - sig);
    free(cm);
    return 0;
}

int ev_verify(const ev_pk *pk, const uint8_t *m, size_t mlen,
              const uint8_t *sig, size_t siglen) {
    size_t expect = ev_sig_bytes(pk->par.depth);
    if (siglen != expect) return -1;
    const uint8_t *s = sig;
    uint32_t p = ((uint32_t)s[0]<<24)|((uint32_t)s[1]<<16)|((uint32_t)s[2]<<8)|s[3];
    if (p >= pk->par.T) return -2;
    s += 4;
    const uint8_t *fswa = s; s += CRYPTO_BYTES;
    const uint8_t *t1 = s;  s += K*POLYT1_PACKEDBYTES;
    const uint8_t *path = s;

    uint8_t dg[EV_HASH_BYTES];
    ev_merkle_leafdigest(t1, K*POLYT1_PACKEDBYTES, dg);
    if (!ev_merkle_verify(pk->root, &pk->par, p, dg, path)) return -3;

    uint8_t leaf_pk[CRYPTO_PUBLICKEYBYTES], rho_p[SEEDBYTES];
    ev_matrix_seed(pk->rho, p, rho_p);
    memcpy(leaf_pk, rho_p, SEEDBYTES);
    memcpy(leaf_pk + SEEDBYTES, t1, K*POLYT1_PACKEDBYTES);

    size_t clen = 1 + 4 + mlen;
    uint8_t *cm = malloc(clen);
    if (!cm) return -4;
    cm[0] = EV_DOM_M; cm[1]=sig[0]; cm[2]=sig[1]; cm[3]=sig[2]; cm[4]=sig[3];
    memcpy(cm+5, m, mlen);
    int ok = (crypto_sign_verify(fswa, CRYPTO_BYTES, cm, clen, NULL, 0, leaf_pk) == 0);
    free(cm);
    return ok ? 0 : -5;
}
