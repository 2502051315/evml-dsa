/*
 * bench_lms.c -- benchmark LMS/HSS keygen/sign/verify using cisco/hash-sigs
 *
 * Commands used (run from "/home/suzeyan/ALLclaude/TIFS TDSC/experiments"):
 *   Build (all hash-sigs .c except test_*.c, demo.c and hss_thread_pthread.c
 *   -- the pthread/single thread backends clash; we build single-threaded
 *   since the run is pinned to one core):
 *     gcc -O3 -Wall -Wno-deprecated-declarations -o scripts/bench_lms scripts/bench_lms.c \
 *         $(ls thirdparty/hash-sigs/ | grep '\.c$' | grep -v -E '^(test_[a-z_]*|demo|hss_thread_pthread)\.c$' | sed 's|^|thirdparty/hash-sigs/|') \
 *         -Ithirdparty/hash-sigs -lcrypto -lpthread -lm
 *   Run (pinned):
 *     taskset -c 9 scripts/bench_lms
 *
 * Parameter set: 1 level, LMS_SHA256_N32_H20 + LMOTS_SHA256_N32_W8
 * DEVIATION NOTE: the plan asked for LMS_SHA256_M24_H20; that macro does NOT
 * exist in hash-sigs @44e6c7de (common_defs.h only defines N32 variants:
 * H5/H10/H15/H20/H25). The closest set, LMS_SHA256_N32_H20 (same H=20,
 * N=32), is used and this is stated in the output file.
 *
 * Usage pattern mirrored from hash-sigs demo.c: hss_generate_private_key
 * with a do_rand callback and an update_private_key callback; the private
 * key is kept in RAM only (no disk). hss_validate_signature is the one-shot
 * verify API (hss_verify.h).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <math.h>
#include <time.h>
#include "hss.h"

#define N_SIGN  100      /* sequential signatures (leaf walk) */
#ifdef BENCH_SMOKE       /* H5 tree only holds 2^5 = 32 signatures */
#undef N_SIGN
#define N_SIGN 30
#endif
#define N_MSG   32       /* message length */

/* ---- timing ---- */
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---- randombytes callback (format per demo.c: bool f(void*, size_t)) ---- */
static bool do_rand(void *output, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t n = fread(output, 1, len, f);
    fclose(f);
    return n == len;
}

/* ---- private key kept in memory via the hss write callback (no disk) ---- */
static unsigned char privkey[HSS_MAX_PRIVATE_KEY_LEN];
static size_t privkey_len = 0;

static bool write_private_key_cb(unsigned char *private_key,
                                 size_t len_private_key, void *ctx) {
    (void)ctx;
    if (len_private_key > sizeof privkey) return false;
    memcpy(privkey, private_key, len_private_key);
    if (len_private_key > privkey_len) privkey_len = len_private_key;
    /* note: hss later updates only the first 8 bytes (index), which the
     * prefix copy above handles; buffer always holds the full key */
    return true;
}
static bool read_private_key_cb(unsigned char *private_key,
                                size_t len_private_key, void *ctx) {
    (void)ctx;
    /* library reads varying lengths: PRIVATE_KEY_SEED (param-set parse)
     * or PRIVATE_KEY_LEN (full key) -- both are prefixes of the stored key */
    if (len_private_key > privkey_len) return false;
    memcpy(private_key, privkey, len_private_key);
    return true;
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
static double median_of(const double *a, int n) {   /* sorts a copy */
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

    param_set_t lm_type[1]  = { LMS_SHA256_N32_H20 };
    param_set_t ots_type[1] = { LMOTS_SHA256_N32_W8 };
    unsigned levels = 1;
#ifdef BENCH_SMOKE   /* quick correctness run, not for measurements */
    lm_type[0] = LMS_SHA256_N32_H5;
#endif
    printf("param_set: %d level(s), lm[0]=0x%08lx (LMS_SHA256_N32_%s), "
           "ots[0]=0x%08lx (LMOTS_SHA256_N32_W8)\n",
           levels, (unsigned long)lm_type[0],
#ifdef BENCH_SMOKE
           "H5"
#else
           "H20"
#endif
           , (unsigned long)ots_type[0]);

    size_t aux_budget = (size_t)8 << 20;   /* 8 MiB budget for aux (cache) data */
    size_t aux_len = hss_get_aux_data_len(aux_budget, levels, lm_type, ots_type);
    unsigned char *aux = malloc(aux_len ? aux_len : 1);
    if (!aux) { printf("ERROR: aux malloc\n"); return 1; }
    printf("aux_data: budget=%zu bytes, actually used=%zu bytes (kept in RAM)\n",
           aux_budget, aux_len);

    unsigned len_pub = hss_get_public_key_len(levels, lm_type, ots_type);
    if (!len_pub) { printf("ERROR: bad param set\n"); return 1; }
    unsigned char public_key[HSS_MAX_PUBLIC_KEY_LEN];

    /* ---------- keygen (once) ---------- */
    struct hss_extra_info info;
    hss_init_extra_info(&info);
    double t0 = now_sec();
    bool ok = hss_generate_private_key(
        do_rand, levels, lm_type, ots_type,
        write_private_key_cb, NULL,           /* private key -> RAM callback */
        public_key, len_pub,
        aux_len ? aux : NULL, aux_len, &info);
    double t_keygen = now_sec() - t0;
    if (!ok) {
        printf("ERROR: keygen failed, code=%d\n",
               (int)hss_extra_info_test_error_code(&info));
        return 1;
    }
    printf("keygen (once)          : %.3f ms  (%.3f s)\n",
           t_keygen * 1e3, t_keygen);

    /* ---------- load working key (once) ---------- */
    hss_init_extra_info(&info);
    t0 = now_sec();
    struct hss_working_key *w = hss_load_private_key(
        read_private_key_cb, NULL, 0 /* minimal memory */,
        aux_len ? aux : NULL, aux_len, &info);
    double t_load = now_sec() - t0;
    if (!w) {
        printf("ERROR: load failed, code=%d\n",
               (int)hss_extra_info_test_error_code(&info));
        return 1;
    }
    printf("load working key (once): %.3f ms  (%.3f s)\n", t_load * 1e3, t_load);

    size_t sig_len = hss_get_signature_len_from_working_key(w);
    if (!sig_len) { printf("ERROR: sig len\n"); return 1; }

    unsigned char *sig    = malloc(sig_len);
    unsigned char *msg    = malloc(N_MSG);
    unsigned char *all_sig = malloc((size_t)N_SIGN * sig_len);
    double *t_sign = malloc(N_SIGN * sizeof *t_sign);
    double *t_ver  = malloc(N_SIGN * sizeof *t_ver);
    if (!sig || !msg || !all_sig || !t_sign || !t_ver) {
        printf("ERROR: malloc\n"); return 1;
    }

    /* ---------- sign N_SIGN sequential messages (state walk) ---------- */
    for (int i = 0; i < N_SIGN; i++) {
        snprintf((char *)msg, N_MSG, "LMS benchmark message #%d", i);
        hss_init_extra_info(&info);
        t0 = now_sec();
        ok = hss_generate_signature(w, write_private_key_cb, NULL,
                                    msg, strlen((char *)msg),
                                    sig, sig_len, &info);
        t_sign[i] = (now_sec() - t0) * 1e3;
        if (!ok) {
            printf("ERROR: sign %d failed, code=%d\n", i,
                   (int)hss_extra_info_test_error_code(&info));
            return 1;
        }
        memcpy(all_sig + (size_t)i * sig_len, sig, sig_len);
    }
    report("sign (sequential)", t_sign, N_SIGN);
    printf("sign amortized over %d : %.3f ms/sig (incl. leaf derivation)\n",
           N_SIGN, mean_of(t_sign, N_SIGN));

    /* ---------- verify all N_SIGN signatures ---------- */
    int n_valid = 0;
    for (int i = 0; i < N_SIGN; i++) {
        snprintf((char *)msg, N_MSG, "LMS benchmark message #%d", i);
        hss_init_extra_info(&info);
        t0 = now_sec();
        bool v = hss_validate_signature(public_key,
                                        msg, strlen((char *)msg),
                                        all_sig + (size_t)i * sig_len,
                                        sig_len, &info);
        t_ver[i] = (now_sec() - t0) * 1e3;
        if (v) n_valid++;
    }
    report("verify", t_ver, N_SIGN);
    printf("verify valid/total     : %d/%d\n", n_valid, N_SIGN);

    /* ---------- sizes ---------- */
    printf("\nsizes:\n");
    printf("  signature : %zu bytes (returned length)\n", sig_len);
    printf("  public key: %u bytes (hss_get_public_key_len)\n", len_pub);
    printf("  private key: %zu bytes (hss write callback, RAM only)\n",
           privkey_len);
    printf("  aux data  : %zu bytes\n", aux_len);

    hss_free_working_key(w);
    free(aux); free(sig); free(msg); free(all_sig);
    free(t_sign); free(t_ver);
    return (n_valid == N_SIGN) ? 0 : 1;
}
