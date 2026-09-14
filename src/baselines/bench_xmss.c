/*
 * bench_xmss.c -- benchmark XMSS keygen/sign/verify using xmss-reference
 *
 * Commands used (run from "/home/suzeyan/ALLclaude/TIFS TDSC/experiments"):
 *   Build:
 *     gcc -O3 -Wall -o scripts/bench_xmss scripts/bench_xmss.c \
 *         thirdparty/xmss-reference/{params.c,hash.c,fips202.c,hash_address.c,\
 *         randombytes.c,wots.c,xmss.c,xmss_core.c,xmss_commons.c,utils.c} \
 *         -Ithirdparty/xmss-reference -lcrypto -lm
 *   Run (pinned):
 *     taskset -c 10 scripts/bench_xmss
 *
 * Parameter set: XMSS-SHA2_10_256 (selected by string -> OID via
 * xmss_str_to_oid, exactly as in the repo's own test/speed.c; OID 0x01000001).
 * This is the library default variant used by test/speed.c. Sizes come from
 * the parsed xmss_params struct (params.h); note there is no
 * XMSS_SIG_BYTES-style macro in this repo -- sizes are runtime values in
 * xmss_params (sig_bytes/pk_bytes/sk_bytes).
 *
 * The sign API (xmss_sign) mutates the secret key state (index walk); that
 * stateful behavior is kept and is what we benchmark.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "xmss.h"
#include "params.h"

#define VARIANT "XMSS-SHA2_10_256"
#define N_SIGN  100      /* sequential signatures (max for h=10 is 1024) */
#define MLEN    32       /* message length */

/* ---- timing ---- */
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---- stats ---- */
static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static double mean_of(const double *a, int n) {
    double s = 0; for (int i = 0; i < n; i++) s += a[i];
    return s / n;
}
static double median_of(const double *a, int n) {
    double *c = malloc(n * sizeof *c);
    memcpy(c, a, n * sizeof *c);
    qsort(c, n, sizeof *c, cmp_double);
    double m = (n % 2) ? c[n/2] : 0.5 * (c[n/2 - 1] + c[n/2]);
    free(c);
    return m;
}
static double stdev_of(const double *a, int n) {
    if (n < 2) return 0;
    double m = mean_of(a, n), s = 0;
    for (int i = 0; i < n; i++) s += (a[i] - m) * (a[i] - m);
    return sqrt(s / (n - 1));
}
static void report(const char *label, const double *ms, int n) {
    double *c = malloc(n * sizeof *c);
    memcpy(c, ms, n * sizeof *c);
    qsort(c, n, sizeof *c, cmp_double);
    printf("%-28s n=%d  first=%8.3f  mean=%8.3f  median=%8.3f  "
           "stdev=%8.3f  min=%8.3f  max=%8.3f  (ms)\n",
           label, n, ms[0], mean_of(ms, n), median_of(ms, n),
           stdev_of(ms, n), c[0], c[n-1]);
    free(c);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* param selection exactly as in test/speed.c */
    xmss_params params;
    uint32_t oid;
    if (xmss_str_to_oid(&oid, VARIANT)) {
        printf("ERROR: variant %s not recognized\n", VARIANT);
        return 1;
    }
    if (xmss_parse_oid(&params, oid)) {
        printf("ERROR: OID 0x%08x not recognized\n", oid);
        return 1;
    }
    printf("param_set: %s (oid=0x%08x, hash=SHA2, n=%u, h=%u, w=%u, "
           "max_sigs=%u)\n",
           VARIANT, oid, params.n, params.full_height,
           1u << params.wots_log_w, 1u << params.full_height);

    unsigned char *pk = malloc(XMSS_OID_LEN + params.pk_bytes);
    unsigned char *sk = malloc(XMSS_OID_LEN + params.sk_bytes);
    unsigned char *m    = malloc(MLEN);
    unsigned char *mout = malloc(params.sig_bytes + MLEN);
    unsigned char *sm   = malloc(params.sig_bytes + MLEN);
    size_t one = params.sig_bytes + MLEN;
    unsigned char *all_sm = malloc((size_t)N_SIGN * one);
    unsigned long long *smlens = malloc(N_SIGN * sizeof *smlens);
    double *t_sign = malloc(N_SIGN * sizeof *t_sign);
    double *t_ver  = malloc(N_SIGN * sizeof *t_ver);
    if (!pk || !sk || !m || !mout || !sm || !all_sm || !smlens ||
        !t_sign || !t_ver) {
        printf("ERROR: malloc\n"); return 1;
    }

    /* ---------- keygen (once; seeds come from randombytes()) ---------- */
    double t0 = now_sec();
    int ret = xmss_keypair(pk, sk, oid);
    double t_keygen = now_sec() - t0;
    if (ret) { printf("ERROR: keypair failed\n"); return 1; }
    printf("keygen (once)          : %.3f ms  (%.3f s)\n",
           t_keygen * 1e3, t_keygen);

    /* ---------- sign N_SIGN sequential messages ----------
     * xmss_sign mutates sk (advances the leaf index): real stateful behavior.
     */
    unsigned long long smlen;
    for (int i = 0; i < N_SIGN; i++) {
        snprintf((char *)m, MLEN, "XMSS benchmark msg #%d", i);
        t0 = now_sec();
        ret = xmss_sign(sk, sm, &smlen, m, MLEN);
        t_sign[i] = (now_sec() - t0) * 1e3;
        if (ret) { printf("ERROR: sign %d failed\n", i); return 1; }
        memcpy(all_sm + (size_t)i * one, sm, smlen);
        smlens[i] = smlen;
    }
    report("sign (sequential)", t_sign, N_SIGN);
    printf("sign amortized over %d : %.3f ms/sig (sk state walk incl.)\n",
           N_SIGN, mean_of(t_sign, N_SIGN));

    /* ---------- verify all N_SIGN signatures ---------- */
    int n_valid = 0;
    unsigned long long mlen;
    for (int i = 0; i < N_SIGN; i++) {
        t0 = now_sec();
        ret = xmss_sign_open(mout, &mlen,
                             all_sm + (size_t)i * one, smlens[i], pk);
        t_ver[i] = (now_sec() - t0) * 1e3;
        if (ret == 0 && mlen == MLEN) n_valid++;
    }
    report("verify", t_ver, N_SIGN);
    printf("verify valid/total     : %d/%d\n", n_valid, N_SIGN);

    /* ---------- sizes (runtime params; no XMSS_SIG_BYTES macros here) ---- */
    printf("\nsizes:\n");
    printf("  signature : %u bytes (params.sig_bytes)\n", params.sig_bytes);
    printf("  signed msg: %llu bytes (sig||msg, smlen)\n", smlens[0]);
    printf("  public key: %u bytes (params.pk_bytes; %d incl. OID prefix)\n",
           params.pk_bytes, XMSS_OID_LEN + params.pk_bytes);
    printf("  secret key: %llu bytes (params.sk_bytes; %d incl. OID prefix)\n",
           params.sk_bytes, XMSS_OID_LEN + (int)params.sk_bytes);

    free(pk); free(sk); free(m); free(mout); free(sm);
    free(all_sm); free(smlens); free(t_sign); free(t_ver);
    return (n_valid == N_SIGN) ? 0 : 1;
}
