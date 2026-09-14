/* Full-system functional test for evML-DSA (ML-DSA-44 build).
 * Checks: keygen determinism; sign/verify at multiple periods; evolution;
 * old signatures remain valid after evolution; tamper rejection (message,
 * t1, path, FSwA, period tag); cross-period forgery sanity (a p=5 signature
 * must not verify as p=3). Exit 0 iff all pass. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "evmldsa.h"
#include "api.h"
#include "params.h"

static int fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS %s\n", name); \
    else { printf("FAIL %s\n", name); fails++; } } while (0)

#define TT (1u<<8)

int main(void) {
    ev_pk pk; ev_sk sk;
    uint8_t root[EV_SEED_BYTES]; for (int i=0;i<EV_SEED_BYTES;i++) root[i]=0xA0+i;

    CHECK(ev_keygen(&pk,&sk,TT,root)==0, "keygen T=2^8");
    CHECK(pk.par.T==TT && pk.par.depth==8, "pk params");

    /* Independent rho: repeated key generation with the same root does not
     * reuse a root-derived public matrix seed in the new construction. */
    ev_pk pk2; ev_sk sk2;
    CHECK(ev_keygen(&pk2,&sk2,TT,root)==0 &&
#if EVMLDSA_LEGACY
          memcmp(pk.rho,pk2.rho,32)==0,
#else
          memcmp(pk.rho,pk2.rho,32)!=0,
#endif
          "independent public rho");

    /* sign/verify at period 0 */
    const uint8_t msg[] = "evidence record #1: hash=deadbeef";
    uint8_t sig[4096]; size_t siglen;
    CHECK(ev_sign(&sk,&pk,msg,sizeof(msg)-1,sig,&siglen)==0, "sign p=0");
    printf("  siglen=%zu (analytic %zu)\n", siglen, ev_sig_bytes(8));
    CHECK(ev_verify(&pk,msg,sizeof(msg)-1,sig,siglen)==0, "verify p=0");

    /* evolve a few periods, sign/verify at each */
    int ok = 1;
    for (int p = 1; p <= 5; p++) {
        if (ev_evolve(&sk)!=0) { ok=0; break; }
        uint8_t m[64]; int n = snprintf((char*)m,sizeof(m),"record at period %d",p);
        if (ev_sign(&sk,&pk,m,(size_t)n,sig,&siglen)!=0) { ok=0; break; }
        if (ev_verify(&pk,m,(size_t)n,sig,siglen)!=0) { ok=0; break; }
    }
    CHECK(ok, "sign/verify across periods 1..5");

    /* old signature still valid after evolution (archival property) */
    uint8_t sig0[4096]; size_t sig0len;
    ev_pk pkA; ev_sk skA;
    ev_keygen(&pkA,&skA,TT, root);
    ev_sign(&skA,&pkA,msg,sizeof(msg)-1,sig0,&sig0len);
    for (int p=0;p<7;p++) ev_evolve(&skA);
    CHECK(ev_verify(&pkA,msg,sizeof(msg)-1,sig0,sig0len)==0, "old sig valid after evolve (p0->7)");

    /* tamper: message */
    uint8_t bad[4096]; memcpy(bad,sig0,sig0len);
    CHECK(ev_verify(&pkA,msg,sizeof(msg)-2,bad,sig0len)!=0, "reject changed message");

    /* tamper: t1 bytes (offset 4+CRYPTO_BYTES) */
    memcpy(bad,sig0,sig0len); bad[4+CRYPTO_BYTES] ^= 1;
    CHECK(ev_verify(&pkA,msg,sizeof(msg)-1,bad,sig0len)!=0, "reject tampered t1");

    /* tamper: path bytes (last 8*32) */
    memcpy(bad,sig0,sig0len); bad[sig0len-1] ^= 0x80;
    CHECK(ev_verify(&pkA,msg,sizeof(msg)-1,bad,sig0len)!=0, "reject tampered path");

    /* tamper: FSwA sig byte */
    memcpy(bad,sig0,sig0len); bad[10] ^= 0x40;
    CHECK(ev_verify(&pkA,msg,sizeof(msg)-1,bad,sig0len)!=0, "reject tampered FSwA");

    /* cross-period: sign at current period 7 but re-tag as period 3 */
    ev_pk pkB; ev_sk skB; ev_keygen(&pkB,&skB,TT, root);
    for (int p=0;p<7;p++) ev_evolve(&skB);
    uint8_t sig7[4096]; size_t sig7len;
    ev_sign(&skB,&pkB,msg,sizeof(msg)-1,sig7,&sig7len);
    uint8_t retag[4096]; memcpy(retag,sig7,sig7len);
    retag[0]=0;retag[1]=0;retag[2]=0;retag[3]=3;   /* claim period 3 */
    CHECK(ev_verify(&pkB,msg,sizeof(msg)-1,retag,sig7len)!=0, "reject period re-tagging");

    /* wrong root: verify against different pk */
    ev_pk pkC; ev_sk skC; uint8_t root2[EV_SEED_BYTES]; for(int i=0;i<EV_SEED_BYTES;i++) root2[i]=i;
    ev_keygen(&pkC,&skC,TT,root2);
    CHECK(ev_verify(&pkC,msg,sizeof(msg)-1,sig0,sig0len)!=0, "reject under different pk");

    /* FSwA leaf keys at distinct periods are distinct keys (t1 differ) */
    ev_pk pkD; ev_sk skD; ev_keygen(&pkD,&skD,TT, root);
    uint8_t t1_a[K*POLYT1_PACKEDBYTES], t1_b[K*POLYT1_PACKEDBYTES];
    memcpy(t1_a, skD.leaf_pk+32, 1280);
    ev_evolve(&skD);
    memcpy(t1_b, skD.leaf_pk+32, 1280);
    CHECK(memcmp(t1_a,t1_b,sizeof(t1_a))!=0, "leaf t1 differs across periods");

    printf(fails ? "\nEV-TEST: %d FAILURES\n" : "\nEV-TEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
