/* Minimal standalone SHA3-256 (Keccak-f[1600], rate 1088, no padding options
 * beyond SHA3). Self-tested in ev_selftest.c against:
 *   SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
 *   SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
 * Written from the FIPS 202 specification; kept dependency-free so the tree
 * layer builds and tests even before pq-crystals integration. */

#include "ev_params.h"
#include "ev_hash.h"
#include <string.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};
static const int RHO[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int PI[24]  = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

#define ROL(x,n) (((x)<<(n))|((x)>>(64-(n))))

static void keccakf(uint64_t s[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5], t;
        for (int i = 0; i < 5; i++)
            bc[i] = s[i]^s[i+5]^s[i+10]^s[i+15]^s[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ ROL(bc[(i+1)%5],1);
            for (int j = 0; j < 25; j += 5) s[j+i] ^= t;
        }
        t = s[1];
        for (int i = 0; i < 24; i++) {
            int j = PI[i];
            bc[0] = s[j];
            s[j] = ROL(t, RHO[i]);
            t = bc[0];
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = s[j+i];
            for (int i = 0; i < 5; i++) s[j+i] = bc[i] ^ (~bc[(i+1)%5] & bc[(i+2)%5]);
        }
        s[0] ^= RC[round];
    }
}

void ev_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    uint64_t st[25] = {0};
    uint8_t buf[144]; /* rate 136 bytes for SHA3-256; pad buf to 144 for safety */
    const size_t rate = 136;

    while (inlen >= rate) {
        for (size_t i = 0; i < rate; i++)
            st[i/8] ^= (uint64_t)in[i] << (8*(i%8));
        keccakf(st);
        in += rate; inlen -= rate;
    }
    memset(buf, 0, rate);
    memcpy(buf, in, inlen);
    buf[inlen] = 0x06;             /* SHA3 domain padding */
    buf[rate-1] |= 0x80;
    for (size_t i = 0; i < rate; i++)
        st[i/8] ^= (uint64_t)buf[i] << (8*(i%8));
    keccakf(st);
    for (int i = 0; i < 4; i++)
        ((uint64_t*)out)[i] = st[i];
    (void)buf;
}

void ev_derive_child(const uint8_t seed[EV_SEED_BYTES], uint8_t dom, uint8_t out[EV_SEED_BYTES]) {
    uint8_t buf[1 + EV_SEED_BYTES];
    buf[0] = dom;
    memcpy(buf + 1, seed, EV_SEED_BYTES);
    ev_sha3_256(buf, sizeof(buf), out);
}

void ev_hash_node(const uint8_t L[32], const uint8_t R[32], uint8_t out[32]) {
    uint8_t buf[65];
    buf[0] = EV_DOM_NODE;
    memcpy(buf+1, L, 32);
    memcpy(buf+33, R, 32);
    ev_sha3_256(buf, 65, out);
}

void ev_period_rho(const uint8_t rho[32], uint32_t period, uint8_t out[32]) {
    uint8_t buf[37];
    buf[0] = EV_DOM_MATRIX;
    memcpy(buf + 1, rho, 32);
    buf[33] = (uint8_t)(period >> 24);
    buf[34] = (uint8_t)(period >> 16);
    buf[35] = (uint8_t)(period >> 8);
    buf[36] = (uint8_t)period;
    ev_sha3_256(buf, sizeof(buf), out);
}
