/* extended_bench.c — supplementary measurements for Fig.4 panels (b) and (c).
 * Appends new archive sizes (2^10..2^20 complete) and distances (0..128).
 * Writes NEW CSV files; never touches existing data.
 *
 * archive  : n_records,rep,total_s,per_record_us   (3 reps per size)
 * distance : scheme,d,rep,verify_us                (100 reps rechain / 300 ev)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "evmldsa.h"
#include "ev_hash.h"
#include "api.h"
#include "params.h"
#include "sign.h"

static double now_us(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1e6+ts.tv_nsec/1e3;}
#define MSGLEN 64
static uint8_t MSG[MSGLEN];

#define MAXCHAIN 129

static void mode_archive(void){
    puts("n_records,rep,total_s,per_record_us");
    uint8_t root[EV_SEED_BYTES]; for(int i=0;i<EV_SEED_BYTES;i++) root[i]=(uint8_t)(0x5A^i);
    /* all 11 powers of 2 from 2^10 to 2^20 */
    uint32_t Ns[]={1024,2048,4096,8192,16384,32768,65536,131072,262144,524288,1048576};
    for(unsigned q=0;q<11;q++){
        uint32_t n_rec=Ns[q];
        uint32_t T=256;
        uint8_t(*msgs)[MSGLEN]=malloc((size_t)n_rec*MSGLEN);
        size_t sigb=ev_sig_bytes(8);
        uint8_t*store=malloc((size_t)n_rec*sigb);
        if(!msgs||!store){fprintf(stderr,"alloc %u\n",n_rec);exit(4);}
        ev_pk pk; ev_sk sk; ev_keygen(&pk,&sk,T,root);
        size_t made=0; uint32_t per=n_rec/T; if(per<1)per=1;
        for(uint32_t p=0;p<T&&made<n_rec;p++){
            for(uint32_t i=0;i<per&&made<n_rec;i++){
                snprintf((char*)msgs[made],MSGLEN,"archive record %u-%u",p,i);
                size_t sl;
                if(ev_sign(&sk,&pk,msgs[made],MSGLEN,store+(size_t)made*sigb,&sl)){exit(5);}
                made++;
            }
            if(p+1<T) ev_evolve(&sk);
        }
        for(int rep=0;rep<3;rep++){
            double t0=now_us(); int bad=0;
            for(size_t i=0;i<made;i++)
                if(ev_verify(&pk,msgs[i],MSGLEN,store+(size_t)i*sigb,sigb)) bad++;
            double dt=now_us()-t0;
            if(bad){fprintf(stderr,"verify failures %d at n=%u\n",bad,n_rec);exit(6);}
            printf("%u,%d,%.3f,%.2f\n",n_rec,rep,dt/1e6,dt/made);
        }
        fflush(stdout);
        free(msgs); free(store);
    }
}

static void mode_distance(void){
    puts("scheme,d,rep,verify_us");
    /* rechain: chain of MAXCHAIN period keys */
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
    int ds[]={0,1,2,4,8,12,16,24,32,48,64,96,128};
    for(unsigned di=0;di<13;di++){
        int d=ds[di];
        if(d==0){
            /* rechain at d=0: verify just the root key (no chain) */
            crypto_sign_signature(sig,&siglen,msg,sizeof(msg)-1,NULL,0,rootsk);
            for(int r=0;r<100;r++){
                double t0=now_us();
                if(crypto_sign_verify(sig,siglen,msg,sizeof(msg)-1,NULL,0,rootpk)){exit(7);}
                printf("rechain,%d,%d,%.2f\n",d,r,now_us()-t0);
            }
        } else {
            int p=d; if(p>=MAXCHAIN)p=MAXCHAIN-1;
            size_t plen;
            crypto_sign_signature(sig,&plen,msg,sizeof(msg)-1,NULL,0,skc[p]);
            for(int r=0;r<100;r++){
                double t0=now_us(); int ok=1;
                for(int i=0;i<=p&&ok;i++){
                    const uint8_t*ppk=i?pkc[i-1]:rootpk;
                    if(crypto_sign_verify(cert[i],certlen[i],pkc[i],CRYPTO_PUBLICKEYBYTES,NULL,0,ppk)) ok=0;
                }
                if(ok&&crypto_sign_verify(sig,plen,msg,sizeof(msg)-1,NULL,0,pkc[p])) ok=0;
                double dt=now_us()-t0;
                if(!ok){fprintf(stderr,"rechain verify fail d=%d\n",d);exit(8);}
                printf("rechain,%d,%d,%.2f\n",d,r,dt);
            }
        }
        fflush(stdout);
    }
    /* evML-DSA: distance-independent, measure at 300 reps */
    {
        uint8_t root[EV_SEED_BYTES]; for(int i=0;i<EV_SEED_BYTES;i++) root[i]=(uint8_t)(0x5A^i);
        ev_pk pk; ev_sk sk; ev_keygen(&pk,&sk,1024,root);
        size_t sl; uint8_t s2[8192];
        ev_sign(&sk,&pk,MSG,MSGLEN,s2,&sl);
        for(int r=0;r<300;r++){
            double t0=now_us();
            if(ev_verify(&pk,MSG,MSGLEN,s2,sl)){exit(9);}
            printf("evmldsa,0,%d,%.2f\n",r,now_us()-t0);
        }
    }
}

int main(int argc,char**argv){
    for(int i=0;i<MSGLEN;i++) MSG[i]=(uint8_t)('a'+(i%26));
    if(argc<2){fprintf(stderr,"mode: archive|distance\n");return 1;}
    if(!strcmp(argv[1],"archive")) mode_archive();
    else if(!strcmp(argv[1],"distance")) mode_distance();
    else{fprintf(stderr,"unknown\n");return 1;}
    return 0;
}
