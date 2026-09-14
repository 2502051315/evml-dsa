/* E5/E6: evidence-workload and robustness benchmarks (real runs, not derived).
 * E5: sustained batch signing (batch sizes 1/100/10k, message = 64B log line);
 *     archival audit = verify a full archive of N signatures (N=2^14 here for
 *     wall-clock honesty at ref speed; scaling stated linearly by construction
 *     since each verify is independent — but we MEASURE the N we report).
 * E6: acceptance stability across periods: sign+verify at 256 distinct
 *     periods, count failures (expect 0); repeated-sign abort behavior via
 *     timing distribution stability (no drift check).
 * Output: CSV to stdout. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "evmldsa.h"

static double now_us(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1e6+ts.tv_nsec/1e3;}

#define T (1u<<8)
#define MSGLEN 64
#define ARCHIVE (1u<<14)

int main(void) {
    ev_pk pk; ev_sk sk;
    uint8_t root[EV_SEED_BYTES]; for (int i=0;i<EV_SEED_BYTES;i++) root[i]=0xC3^i;
    if (ev_keygen(&pk,&sk,T,root)) return 2;

    uint8_t (*msgs)[MSGLEN] = malloc((size_t)ARCHIVE*MSGLEN);
    size_t sigb = ev_sig_bytes(8);
    uint8_t *sigstore = malloc((size_t)ARCHIVE*sigb);
    if (!msgs || !sigstore) return 3;

    puts("experiment,parameter,value");

    /* E5a: batch signing throughput at current period */
    int bs[] = {1, 100, 10000};
    for (unsigned b=0;b<3;b++) {
        int B = bs[b]; int reps = B==1 ? 2000 : (B==100 ? 30 : 3);
        double best = 1e18;
        for (int r=0;r<reps;r++) {
            double t0=now_us();
            for (int i=0;i<B;i++) {
                size_t sl;
                ev_sign(&sk,&pk,(uint8_t*)msgs,(size_t)MSGLEN,sigstore,&sl);
            }
            double dt = now_us()-t0; if (dt<best) best=dt;
        }
        printf("sign_batch_us,%d,%.1f\n", B, best);
        printf("sign_throughput_sps,%d,%.1f\n", B, B/(best/1e6));
    }

    /* E5b: archival verification of ARCHIVE signatures (mixed periods) */
    {
        /* produce ARCHIVE sigs spread over all T periods */
        ev_pk pk2; ev_sk sk2;
        ev_keygen(&pk2,&sk2,T,root);
        size_t made = 0; int per = ARCHIVE/T; /* 64 per period */
        for (uint32_t p=0;p<T && made<ARCHIVE;p++) {
            for (int i=0;i<per && made<ARCHIVE;i++) {
                snprintf((char*)msgs[made],MSGLEN,"period %u record %d",p,i);
                size_t sl;
                if (ev_sign(&sk2,&pk2,msgs[made],MSGLEN,sigstore+(size_t)made*sigb,&sl)) return 4;
                made++;
            }
            if (p+1<T) ev_evolve(&sk2);
        }
        double t0=now_us(); int bad=0;
        for (size_t i=0;i<made;i++)
            if (ev_verify(&pk2,msgs[i],MSGLEN,sigstore+(size_t)i*sigb,sigb)) bad++;
        double dt=now_us()-t0;
        printf("archive_n,,%zu\n", made);
        printf("archive_verify_us,,%.1f\n", dt);
        printf("archive_verify_failures,,%d\n", bad);
        printf("archive_verify_per_us,,%.2f\n", dt/made);
    }

    /* E6: acceptance stability across periods + timing drift check */
    {
        ev_pk pk3; ev_sk sk3;
        ev_keygen(&pk3,&sk3,T,root);
        int fail=0; double first_half=0, second_half=0; int n1=0,n2=0;
        for (uint32_t p=0;p<T;p++) {
            uint8_t m[MSGLEN];
            snprintf((char*)m,MSGLEN,"stability period %u",p);
            uint8_t sig[8192]; size_t sl;
            double t0=now_us();
            if (ev_sign(&sk3,&pk3,m,MSGLEN,sig,&sl)) { fail++; continue; }
            double d=now_us()-t0;
            if (ev_verify(&pk3,m,MSGLEN,sig,sl)) fail++;
            if (p < T/2) { first_half+=d; n1++; } else { second_half+=d; n2++; }
            if (p+1<T) ev_evolve(&sk3);
        }
        printf("stability_failures,,%d\n", fail);
        printf("sign_mean_us_firsthalf,,%.2f\n", first_half/n1);
        printf("sign_mean_us_secondhalf,,%.2f\n", second_half/n2);
        printf("drift_ratio,,%.4f\n", (second_half/n2)/((first_half/n1)?first_half/n1:1));
    }
    free(msgs); free(sigstore);
    return 0;
}
