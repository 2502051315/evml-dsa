/* E2/E4 microbenchmark harness for evML-DSA.
 * Ops: keygen (per T), evolve (amortized), sign, verify, leaf-expand,
 *       path-only verify component.
 * Output: CSV to stdout: op,T,reps,mean_us,std_us,median_us
 * Timing: clock_gettime(CLOCK_MONOTONIC); warmup 10% of reps. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "evmldsa.h"

static double now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec*1e6 + ts.tv_nsec/1e3;
}
static int cmpd(const void *a, const void *b) {
    double x=*(const double*)a, y=*(const double*)b;
    return (x>y)-(x<y);
}
static void report(const char *op, uint32_t T, double *v, size_t n) {
    double mean=0, var=0;
    for (size_t i=0;i<n;i++) mean+=v[i];
    mean/=n;
    for (size_t i=0;i<n;i++) var+=(v[i]-mean)*(v[i]-mean);
    double std = n>1 ? sqrt(var/(n-1)) : 0;
    qsort(v,n,sizeof(double),cmpd);
    double med = n%2 ? v[n/2] : (v[n/2-1]+v[n/2])/2;
    printf("%s,%u,%zu,%.2f,%.2f,%.2f\n", op, T, n, mean, std, med);
}

#define MAXSIG 8192
static uint8_t sig[MAXSIG];

int main(int argc, char **argv) {
    uint32_t Ts[] = {1u<<8, 1u<<10, 1u<<16};
    int nT = 3;
    if (argc > 1 && strcmp(argv[1], "big") == 0) { Ts[2] = 1u<<20; }
    size_t reps_sign = 1000, reps_verify = 1000, reps_evol = 200;
    uint8_t root[EV_SEED_BYTES]; for (int i=0;i<EV_SEED_BYTES;i++) root[i]=0x5A^i;
    const uint8_t msg[] = "benchmark evidence record, 64-byte payload padded .. padding .. done.";
    size_t mlen = sizeof(msg)-1;

    puts("op,T,reps,mean_us,std_us,median_us");
    for (int t = 0; t < nT; t++) {
        uint32_t T = Ts[t];
        double *tv = malloc(sizeof(double)*(reps_evol+reps_sign+reps_verify+64));
        /* keygen (timed once per T; repeat 3x for small T) */
        ev_pk pk; ev_sk sk;
        int kg_reps = T <= (1u<<10) ? 5 : 1;
        for (int r=0;r<kg_reps;r++) { double t0=now_us(); if (ev_keygen(&pk,&sk,T,root)) return 2; tv[r]=now_us()-t0; }
        report("keygen", T, tv, kg_reps);

        /* sign / verify */
        size_t siglen;
        for (size_t r=0;r<10;r++) ev_sign(&sk,&pk,msg,mlen,sig,&siglen);
        for (size_t r=0;r<reps_sign;r++){ double t0=now_us(); ev_sign(&sk,&pk,msg,mlen,sig,&siglen); tv[r]=now_us()-t0; }
        report("sign", T, tv, reps_sign);
        for (size_t r=0;r<10;r++) ev_verify(&pk,msg,mlen,sig,siglen);
        for (size_t r=0;r<reps_verify;r++){ double t0=now_us(); if (ev_verify(&pk,msg,mlen,sig,siglen)) return 3; tv[r]=now_us()-t0; }
        report("verify", T, tv, reps_verify);

        /* evolve: fresh keygen state, then advance reps_evol times (each incl.
         * leaf keypair recompute); amortized + max spike */
        ev_keygen(&pk,&sk,T,root);
        double mx=0; size_t done=0;
        for (size_t r=0;r<reps_evol;r++) {
            double t0=now_us();
            if (ev_evolve(&sk)) break;
            tv[done]=now_us()-t0; if (tv[done]>mx) mx=tv[done]; done++;
        }
        report("evolve_avg", T, tv, done);
        double spike[1]={mx}; report("evolve_max", T, spike, 1);
        free(tv);
    }
    printf("# sizes: sig=%zu (T=2^8/2^10: %zu/%zu), pk=%zu, sk_secrets~%zu\n",
           ev_sig_bytes(8), ev_sig_bytes(8), ev_sig_bytes(10),
           (size_t)(4+32+32), (size_t)(32*(21+20)+21));
    return 0;
}
