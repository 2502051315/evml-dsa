#include <stdio.h>
#include "evmldsa.h"
#include "ev_params.h"
#include "ev_seedtree.h"
#include "ev_merkle.h"
#include "api.h"
#include "params.h"
int main(void){
    printf("sizeof(ev_pk)=%zu\n", sizeof(ev_pk));
    printf("sizeof(ev_sk)=%zu\n", sizeof(ev_sk));
    printf("sizeof(ev_tree_state)=%zu\n", sizeof(ev_tree_state));
    printf("sizeof(ev_merkle_tree)=%zu (ptr only; full tree = 2T-1 hashes)\n", sizeof(ev_merkle_tree));
    printf("CRYPTO_PUBLICKEYBYTES=%d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES=%d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES=%d\n", CRYPTO_BYTES);
    printf("EV_SEED_BYTES=%d\n", EV_SEED_BYTES);
    printf("EV_HASH_BYTES=%d\n", EV_HASH_BYTES);
    /* evML-DSA serialized pk: 4(T)+32(rho)+32(root) = 68 B */
    printf("ev_pk_serialized = 4+32+32 = 68\n");
    /* ev sk secrets: tree state (path 21*64 + future 20*64 + flags) + leaf sk + cached leaf pk */
    printf("ev_sk_secrets ≈ (21*64) + (20*64) + %d + %d = %d\n", CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES, 21*64+20*64+CRYPTO_SECRETKEYBYTES+CRYPTO_PUBLICKEYBYTES);
    /* prototype also stores full Merkle tree = (2T-1)*32 B; T=2^20 → 64MB */
    printf("ev_merkle_fulltree_T20 = %lld B\n", (long long)(2*(1LL<<20)-1)*32);
    /* fractal O(log^2 T) = ~400*32 ≈ 12800 B */
    printf("ev_merkle_fractal ≈ %lld B\n", (long long)(20*20)*32);
    return 0;
}
