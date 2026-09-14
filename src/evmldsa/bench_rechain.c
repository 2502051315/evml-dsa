/* B4 naive baseline: "Dilithium + periodic re-certification" composition.
 * Period p key certified by chain of period keys back to the root key.
 * Measures: per-period setup cost (keypair + cert chain sign), steady sign,
 * verify at distance d (chain verify), sizes (sig + chain). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "api.h"
#include "params.h"
#include "sign.h"
#include "randombytes.h"

static double now_us(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1e6+ts.tv_nsec/1e3;}

#define MAXCHAIN 64
int main(void) {
    /* root key */
    static uint8_t rootpk[CRYPTO_PUBLICKEYBYTES], rootsk[CRYPTO_SECRETKEYBYTES];
    crypto_sign_keypair(rootpk, rootsk);
    /* chain of MAXCHAIN period keys, each cert signed by previous */
    static uint8_t pkc[MAXCHAIN][CRYPTO_PUBLICKEYBYTES];
    static uint8_t skc[MAXCHAIN][CRYPTO_SECRETKEYBYTES];
    static uint8_t cert[MAXCHAIN][CRYPTO_BYTES]; size_t certlen[MAXCHAIN];

    double t0 = now_us();
    for (int i = 0; i < MAXCHAIN; i++) {
        crypto_sign_keypair(pkc[i], skc[i]);
        const uint8_t *parent_pk = i ? pkc[i-1] : rootpk;
        const uint8_t *parent_sk = i ? skc[i-1] : rootsk;
        size_t cl = CRYPTO_BYTES;
        crypto_sign_signature(cert[i], &cl, pkc[i], CRYPTO_PUBLICKEYBYTES, NULL, 0, parent_sk);
        certlen[i] = cl;
    }
    double setup = (now_us()-t0)/MAXCHAIN;
    printf("rechain setup per period (keypair+cert): %.1f us\n", setup);
    printf("rechain accumulated size at d=%d: %zu B (certs) + sig\n", MAXCHAIN,
           MAXCHAIN*(CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES));

    /* steady sign at period 63 */
    const uint8_t msg[] = "rechain benchmark message";
    static uint8_t sig[CRYPTO_BYTES]; size_t siglen;
    const int R = 1000;
    for (int r=0;r<20;r++) crypto_sign_signature(sig,&siglen,msg,sizeof(msg)-1,NULL,0,skc[63]);
    t0 = now_us();
    for (int r=0;r<R;r++) crypto_sign_signature(sig,&siglen,msg,sizeof(msg)-1,NULL,0,skc[63]);
    printf("rechain sign: %.1f us\n", (now_us()-t0)/R);

    /* verify at distance d: verify cert chain (root->..->p) + sig at p */
    int dists[] = {1, 8, 32, 63};
    for (unsigned di = 0; di < sizeof(dists)/sizeof(dists[0]); di++) {
        int p = dists[di]; /* period index == distance from root */
        size_t plen;
        crypto_sign_signature(sig, &plen, msg, sizeof(msg)-1, NULL, 0, skc[p]); /* sig at period p */
        t0 = now_us();
        const int RV = 100;
        for (int r=0;r<RV;r++) {
            int ok = 1;
            for (int i = 0; i <= p && ok; i++) {
                const uint8_t *parent_pk = i ? pkc[i-1] : rootpk;
                int vr = crypto_sign_verify(cert[i], certlen[i], pkc[i], CRYPTO_PUBLICKEYBYTES, NULL, 0, parent_pk);
                if (vr) { ok = 0; if (r==0) fprintf(stderr, "cert %d verify rc=%d (certlen=%zu)\n", i, vr, certlen[i]); }
            }
            if (ok && crypto_sign_verify(sig, plen, msg, sizeof(msg)-1, NULL, 0, pkc[p])) ok = 0;
            if (!ok) { printf("VERIFY FAIL\n"); return 1; }
        }
        printf("rechain verify @d=%d: %.1f us\n", p, (now_us()-t0)/RV);
    }
    /* plain dilithium single verify reference */
    t0 = now_us();
    for (int r=0;r<1000;r++) crypto_sign_verify(sig,siglen,msg,sizeof(msg)-1,NULL,0,pkc[63]);
    printf("plain ML-DSA-44 verify: %.1f us\n", (now_us()-t0)/1000);
    return 0;
}
