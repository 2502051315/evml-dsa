/* breakdown_bench.c — step-level instrumentation for Fig.3(e,f), Fig.4(a,c)
 * baselines. Modes (argv[1]):
 *   signbd   : T,rep,msg_us,fswa_us,path_us      (n=1000 per T in {2^10,2^16,2^20})
 *   verbd    : T,rep,parse_us,merkle_us,fswa_us  (n=1000; + plain row: T=0)
 *   plainbatch: batch,rep,total_us,thr           (7 reps, {1,10,100,1000,10000})
 *   plainverify: rep,verify_us                   (n=2000)
 * Instrumentation re-implements ev_sign/ev_verify stage-by-stage with the SAME
 * primitive calls in the SAME order (clocks between stages). No algorithm change.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "evmldsa.h"
#include "ev_hash.h"
#include "api.h"
#include "params.h"
#include "packing.h"
#include "sign.h"

static double now_us(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1e6+ts.tv_nsec/1e3;}
#define MSGLEN 64
static uint8_t MSG[MSGLEN];

/* staged sign: mirrors ev_sign() in evmldsa.c exactly, with clocks */
static void staged_sign(const ev_sk *sk, const ev_pk *pk, const uint8_t *m, size_t mlen,
                        uint8_t *sig, size_t *siglen,
                        double *t_msg, double *t_fswa, double *t_path)
{
    double a = now_us();
    size_t clen = 1 + 4 + mlen;
    uint8_t *cm = malloc(clen);
    uint32_t cur = sk->tree.current;
    cm[0] = EV_DOM_M;
    cm[1]=(cur>>24)&0xff; cm[2]=(cur>>16)&0xff; cm[3]=(cur>>8)&0xff; cm[4]=cur&0xff;
    memcpy(cm+5, m, mlen);
    uint8_t *s = sig;
    s[0]=cm[1];s[1]=cm[2];s[2]=cm[3];s[3]=cm[4]; s+=4;
    double b = now_us();
    size_t sl = CRYPTO_BYTES;
    crypto_sign_signature(s, &sl, cm, clen, NULL, 0, sk->leaf_sk);
    double c = now_us();
    s += sl;
    memcpy(s, sk->leaf_pk + SEEDBYTES, K*POLYT1_PACKEDBYTES); s += K*POLYT1_PACKEDBYTES;
    ev_merkle_path(&sk->mt, cur, s);
    s += sk->par.depth * EV_HASH_BYTES;
    *siglen = (size_t)(s - sig);
    free(cm);
    double d = now_us();
    *t_msg = b-a; *t_fswa = c-b; *t_path = d-c;
    (void)pk;
}

/* staged verify: mirrors ev_verify() stage-by-stage */
static int staged_verify(const ev_pk *pk, const uint8_t *m, size_t mlen,
                         const uint8_t *sig, size_t siglen,
                         double *t_parse, double *t_merkle, double *t_fswa)
{
    double a = now_us();
    const uint8_t *s = sig;
    uint32_t p = ((uint32_t)s[0]<<24)|((uint32_t)s[1]<<16)|((uint32_t)s[2]<<8)|s[3];
    if (p >= pk->par.T) return -2;
    s += 4;
    const uint8_t *fswa = s; s += CRYPTO_BYTES;
    const uint8_t *t1 = s;  s += K*POLYT1_PACKEDBYTES;
    const uint8_t *path = s;
    uint8_t dg[EV_HASH_BYTES];
    double b = now_us();
    ev_merkle_leafdigest(t1, K*POLYT1_PACKEDBYTES, dg);
    int merkle_ok = ev_merkle_verify(pk->root, &pk->par, p, dg, path);
    uint8_t leaf_pk[CRYPTO_PUBLICKEYBYTES];
    memcpy(leaf_pk, pk->rho, SEEDBYTES);
    memcpy(leaf_pk+SEEDBYTES, t1, K*POLYT1_PACKEDBYTES);
    size_t clen = 1+4+mlen;
    uint8_t *cm = malloc(clen);
    cm[0]=EV_DOM_M; cm[1]=sig[0];cm[2]=sig[1];cm[3]=sig[2];cm[4]=sig[3];
    memcpy(cm+5, m, mlen);
    double c = now_us();
    int ok = (merkle_ok && crypto_sign_verify(fswa, CRYPTO_BYTES, cm, clen, NULL, 0, leaf_pk)==0);
    free(cm);
    double d = now_us();
    *t_parse = b-a; *t_merkle = c-b; *t_fswa = d-c;
    (void)siglen;
    return ok ? 0 : -5;
}

int main(int argc, char **argv)
{
    for (int i=0;i<MSGLEN;i++) MSG[i]=(uint8_t)('a'+(i%26));
    if (argc<2) return 1;
    uint8_t root[EV_SEED_BYTES]; for (int i=0;i<EV_SEED_BYTES;i++) root[i]=(uint8_t)(0x5A^i);

    if (!strcmp(argv[1],"signbd")) {
        puts("T,rep,msg_us,fswa_us,path_us");
        uint32_t Ts[]={1024,65536,1048576};
        for (unsigned q=0;q<3;q++){
            uint32_t T=Ts[q];
            ev_pk pk; ev_sk sk;
            if (ev_keygen(&pk,&sk,T,root)) return 2;
            uint8_t sig[8192]; size_t sl;
            for (int r=0;r<100;r++) ev_sign(&sk,&pk,MSG,MSGLEN,sig,&sl); /* warm */
            for (int r=0;r<1000;r++){
                double a,b,c;
                staged_sign(&sk,&pk,MSG,MSGLEN,sig,&sl,&a,&b,&c);
                printf("%u,%d,%.2f,%.2f,%.2f\n",T,r,a,b,c);
            }
            fflush(stdout);
        }
        return 0;
    }
    if (!strcmp(argv[1],"verbd")) {
        puts("T,rep,parse_us,merkle_us,fswa_us");
        uint32_t Ts[]={1024,65536,1048576};
        for (unsigned q=0;q<3;q++){
            uint32_t T=Ts[q];
            ev_pk pk; ev_sk sk;
            if (ev_keygen(&pk,&sk,T,root)) return 2;
            uint8_t sig[8192]; size_t sl;
            ev_sign(&sk,&pk,MSG,MSGLEN,sig,&sl);
            for (int r=0;r<100;r++) staged_verify(&pk,MSG,MSGLEN,sig,sl,&(double){0},&(double){0},&(double){0});
            for (int r=0;r<1000;r++){
                double a,b,c;
                if (staged_verify(&pk,MSG,MSGLEN,sig,sl,&a,&b,&c)) return 3;
                printf("%u,%d,%.2f,%.2f,%.2f\n",T,r,a,b,c);
            }
            /* plain ML-DSA floor row: T=0 marker, full time in fswa column */
            {
                uint8_t lpk[CRYPTO_PUBLICKEYBYTES], lsk[CRYPTO_SECRETKEYBYTES];
                crypto_sign_keypair(lpk,lsk);
                uint8_t ps[CRYPTO_BYTES]; size_t pl;
                crypto_sign_signature(ps,&pl,MSG,MSGLEN,NULL,0,lsk);
                for (int r=0;r<200;r++) crypto_sign_verify(ps,CRYPTO_BYTES,MSG,MSGLEN,NULL,0,lpk);
                for (int r=0;r<2000;r++){
                    double a=now_us();
                    if (crypto_sign_verify(ps,CRYPTO_BYTES,MSG,MSGLEN,NULL,0,lpk)) return 4;
                    printf("0,%d,0.00,0.00,%.2f\n",r,now_us()-a);
                }
            }
            fflush(stdout);
        }
        return 0;
    }
    if (!strcmp(argv[1],"plainbatch")) {
        puts("batch,rep,total_us,throughput_sps");
        uint8_t lpk[CRYPTO_PUBLICKEYBYTES], lsk[CRYPTO_SECRETKEYBYTES];
        crypto_sign_keypair(lpk,lsk);
        int bs[]={1,10,100,1000,10000};
        for (unsigned b=0;b<5;b++){
            int B=bs[b];
            for (int w=0;w<100;w++){ uint8_t ws[CRYPTO_BYTES]; size_t wl; crypto_sign_signature(ws,&wl,MSG,MSGLEN,NULL,0,lsk); } /* warm-up */
            for (int r=0;r<7;r++){
                double t0=now_us();
                for (int k=0;k<B;k++){ uint8_t s[CRYPTO_BYTES]; size_t l;
                    crypto_sign_signature(s,&l,MSG,MSGLEN,NULL,0,lsk); }
                double tot=now_us()-t0;
                printf("%d,%d,%.1f,%.1f\n",B,r,tot,B/(tot/1e6));
            }
            fflush(stdout);
        }
        return 0;
    }
    fprintf(stderr,"unknown mode\n"); return 1;
}
