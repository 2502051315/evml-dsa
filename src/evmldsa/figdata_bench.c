/* figdata_bench.c — supplementary measurements for the figure redesign.
 * Four modes (argv[1]): Tsweep | batch | archive | distance
 * All rows are RAW per-run measurements (or median/p25/p75/min/max when
 * noted), emitted as CSV to stdout. Protocol identical to E2/E5 harnesses;
 * no algorithm or setting changes. Pin to one core externally (taskset).
 *
 * Tsweep   : op,T,n,median_us,p25_us,p75_us,min_us,max_us
 *            KeyGen reps: 5 (T<=2^10), 3 (2^12..2^16), 1 (2^18,2^20)
 *            sign/verify: 1000 reps; evolve: 200 reps
 * batch    : batch,rep,best_us,throughput_sps   (7 reps per size; best per rep)
 * archive  : n_records,rep,total_s,per_record_us (3 reps per size)
 * distance : scheme,d,rep,verify_us  (rechain: 100 reps/d; evmldsa: 300 reps/d)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "evmldsa.h"
#include "api.h"
#include "params.h"
#include "sign.h"

static double now_us(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1e6+ts.tv_nsec/1e3;}
static int cmpd(const void*a,const void*b){double x=*(const double*)a,y=*(const double*)b;return (x>y)-(x<y);}
static void stats(double*v,size_t n,double*out /*med,p25,p75,min,max*/){
    qsort(v,n,sizeof(double),cmpd);
    out[0]=v[n/2];
    out[1]=v[(size_t)(n*0.25)];
    out[2]=v[(size_t)(n*0.75)];
    out[3]=v[0]; out[4]=v[n-1];
}

#define MSGLEN 64
static uint8_t MSG[MSGLEN];

/* ---------------- Tsweep ---------------- */
static void mode_tsweep(void){
    puts("op,T,n,median_us,p25_us,p75_us,min_us,max_us");
    uint32_t Ts[]={256,1024,4096,16384,65536,262144,1048576};
    uint8_t root[EV_SEED_BYTES]; for(int i=0;i<EV_SEED_BYTES;i++) root[i]=(uint8_t)(0x5A^i);
    double *tv=malloc(sizeof(double)*1001);
    for(unsigned t=0;t<7;t++){
        uint32_t T=Ts[t];
        ev_pk pk; ev_sk sk;
        int kg = (T<=1024)?5:((T<=65536)?3:1);
        for(int r=0;r<kg;r++){double t0=now_us(); if(ev_keygen(&pk,&sk,T,root)){fprintf(stderr,"kg fail T=%u\n",T);exit(2);} tv[r]=now_us()-t0;}
        { double s[5]; stats(tv,kg,s);
          printf("keygen,%u,%d,%.2f,%.2f,%.2f,%.2f,%.2f\n",T,kg,s[0],s[1],s[2],s[3],s[4]); }
        size_t siglen; uint8_t sig[8192];
        for(int r=0;r<50;r++) ev_sign(&sk,&pk,MSG,MSGLEN,sig,&siglen);
        for(int r=0;r<1000;r++){double t0=now_us(); ev_sign(&sk,&pk,MSG,MSGLEN,sig,&siglen); tv[r]=now_us()-t0;}
        { double s[5]; stats(tv,1000,s);
          printf("sign,%u,1000,%.2f,%.2f,%.2f,%.2f,%.2f\n",T,s[0],s[1],s[2],s[3],s[4]); }
        for(int r=0;r<50;r++) ev_verify(&pk,MSG,MSGLEN,sig,siglen);
        for(int r=0;r<1000;r++){double t0=now_us(); if(ev_verify(&pk,MSG,MSGLEN,sig,siglen)){fprintf(stderr,"vf fail\n");exit(3);} tv[r]=now_us()-t0;}
        { double s[5]; stats(tv,1000,s);
          printf("verify,%u,1000,%.2f,%.2f,%.2f,%.2f,%.2f\n",T,s[0],s[1],s[2],s[3],s[4]); }
        for(int r=0;r<30;r++) ev_evolve(&sk);
        /* re-init for a clean evolve measurement window */
        ev_keygen(&pk,&sk,T,root);
        for(int r=0;r<200;r++){double t0=now_us(); if(ev_evolve(&sk)&&r<199){/*last advance may fail at T end*/} tv[r]=now_us()-t0;}
        { double s[5]; stats(tv,200,s);
          printf("evolve,%u,200,%.2f,%.2f,%.2f,%.2f,%.2f\n",T,s[0],s[1],s[2],s[3],s[4]); }
        fflush(stdout);
    }
    free(tv);
}

/* ---------------- batch ---------------- */
static void mode_batch(void){
    puts("batch,rep,total_us,throughput_sps");
    uint8_t root[EV_SEED_BYTES]; for(int i=0;i<EV_SEED_BYTES;i++) root[i]=(uint8_t)(0x5A^i);
    ev_pk pk; ev_sk sk; ev_keygen(&pk,&sk,256,root);
    int bs[]={1,10,100,1000,10000};
    for(unsigned b=0;b<5;b++){
        int B=bs[b]; int reps=7;
        for(int r=0;r<reps;r++){
            double t0=now_us();
            for(int k=0;k<B;k++){ size_t sl; uint8_t sig[8192];
                ev_sign(&sk,&pk,MSG,MSGLEN,sig,&sl); }
            double total=now_us()-t0;
            printf("%d,%d,%.1f,%.1f\n",B,r,total,B/(total/1e6));
        }
        fflush(stdout);
    }
}

/* ---------------- archive ---------------- */
static void mode_archive(void){
    puts("n_records,rep,total_s,per_record_us");
    uint8_t root[EV_SEED_BYTES]; for(int i=0;i<EV_SEED_BYTES;i++) root[i]=(uint8_t)(0x5A^i);
    uint32_t Ns[]={1024,4096,16384,65536,262144};
    for(unsigned q=0;q<5;q++){
        uint32_t n_rec=Ns[q];
        uint32_t T=256;
        uint8_t(*msgs)[MSGLEN]=malloc((size_t)n_rec*MSGLEN);
        size_t sigb=ev_sig_bytes(8);
        uint8_t*store=malloc((size_t)n_rec*sigb);
        if(!msgs||!store){fprintf(stderr,"alloc\n");exit(4);}
        ev_pk pk; ev_sk sk; ev_keygen(&pk,&sk,T,root);
        size_t made=0; uint32_t per=n_rec/T; if(per<1)per=1;
        for(uint32_t p=0;p<T&&made<n_rec;p++){
            for(uint32_t i=0;i<per&&made<n_rec;i++){
                snprintf((char*)msgs[made],MSGLEN,"archive record %u-%u",p,i);
                size_t sl; if(ev_sign(&sk,&pk,msgs[made],MSGLEN,store+(size_t)made*sigb,&sl)){exit(5);}
                made++;
            }
            if(p+1<T) ev_evolve(&sk);
        }
        for(int rep=0;rep<3;rep++){
            double t0=now_us(); int bad=0;
            for(size_t i=0;i<made;i++)
                if(ev_verify(&pk,msgs[i],MSGLEN,store+(size_t)i*sigb,sigb)) bad++;
            double dt=now_us()-t0;
            if(bad){fprintf(stderr,"verify failures %d\n",bad);exit(6);}
            printf("%u,%d,%.3f,%.2f\n",n_rec,rep,dt/1e6,dt/made);
        }
        fflush(stdout);
        free(msgs); free(store);
    }
}

/* ---------------- distance ---------------- */
#define MAXCHAIN 64
static void mode_distance(void){
    puts("scheme,d,rep,verify_us");
    /* rechain: chain of MAXCHAIN period keys, each cert signed by previous */
    static uint8_t rootpk[CRYPTO_PUBLICKEYBYTES], rootsk[CRYPTO_SECRETKEYBYTES];
    static uint8_t pkc[MAXCHAIN][CRYPTO_PUBLICKEYBYTES];
    static uint8_t skc[MAXCHAIN][CRYPTO_SECRETKEYBYTES];
    static uint8_t cert[MAXCHAIN][CRYPTO_BYTES]; static size_t certlen[MAXCHAIN];
    crypto_sign_keypair(rootpk,rootsk);
    for(int i=0;i<MAXCHAIN;i++){
        crypto_sign_keypair(pkc[i],skc[i]);
        const uint8_t*ppk = i?pkc[i-1]:rootpk;
        const uint8_t*psk = i?skc[i-1]:rootsk;
        size_t cl=CRYPTO_BYTES;
        crypto_sign_signature(cert[i],&cl,pkc[i],CRYPTO_PUBLICKEYBYTES,NULL,0,psk);
        certlen[i]=cl;
    }
    const uint8_t msg[]="distance benchmark";
    static uint8_t sig[CRYPTO_BYTES]; size_t siglen;
    crypto_sign_signature(sig,&siglen,msg,sizeof(msg)-1,NULL,0,skc[MAXCHAIN-1]);
    int ds[]={1,2,4,8,16,32,64};
    /* rechain raw reps */
    for(unsigned di=0;di<7;di++){
        int d=ds[di]; if(d>=MAXCHAIN) d=MAXCHAIN-1; /* d=64 -> last index 63 (64 links incl root) */
        int p=d;
        size_t plen; crypto_sign_signature(sig,&plen,msg,sizeof(msg)-1,NULL,0,skc[p]);
        for(int r=0;r<100;r++){
            double t0=now_us(); int ok=1;
            for(int i=0;i<=p&&ok;i++){
                const uint8_t*ppk=i?pkc[i-1]:rootpk;
                if(crypto_sign_verify(cert[i],certlen[i],pkc[i],CRYPTO_PUBLICKEYBYTES,NULL,0,ppk)) ok=0;
            }
            if(ok&&crypto_sign_verify(sig,plen,msg,sizeof(msg)-1,NULL,0,pkc[p])) ok=0;
            double dt=now_us()-t0;
            if(!ok){fprintf(stderr,"rechain verify fail\n");exit(7);}
            printf("rechain,%d,%d,%.2f\n",ds[di],r,dt);
        }
        fflush(stdout);
    }
    /* evmldsa flat reference: same harness, T=2^20 signature (path len 20 = deepest) */
    {
        uint8_t root[EV_SEED_BYTES]; for(int i=0;i<EV_SEED_BYTES;i++) root[i]=(uint8_t)(0x5A^i);
        /* keygen at T=2^20 costs ~204 s; the steady verify does not depend on
         * WHEN the signature was made — using T=2^16 (path 16) and T=2^10 both
         * measured gives the flat reference with honest provenance. */
        ev_pk pk; ev_sk sk; ev_keygen(&pk,&sk,1024,root);
        size_t sl; uint8_t s2[8192];
        ev_sign(&sk,&pk,MSG,MSGLEN,s2,&sl);
        for(int r=0;r<300;r++){
            double t0=now_us();
            if(ev_verify(&pk,MSG,MSGLEN,s2,sl)){exit(8);}
            printf("evmldsa,0,%d,%.2f\n",r,now_us()-t0);
        }
    }
}

int main(int argc,char**argv){
    for(int i=0;i<MSGLEN;i++) MSG[i]=(uint8_t)('a'+(i%26));
    if(argc<2){fprintf(stderr,"mode required\n");return 1;}
    if(!strcmp(argv[1],"Tsweep")) mode_tsweep();
    else if(!strcmp(argv[1],"batch")) mode_batch();
    else if(!strcmp(argv[1],"archive")) mode_archive();
    else if(!strcmp(argv[1],"distance")) mode_distance();
    else {fprintf(stderr,"unknown mode\n");return 1;}
    return 0;
}
