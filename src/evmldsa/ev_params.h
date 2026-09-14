#ifndef EV_PARAMS_H
#define EV_PARAMS_H

/* evML-DSA prototype — self-contained tree/commitment layer parameters.
 * The FSwA leaf layer reuses pq-crystals Dilithium (reference) code. */

#include <stdint.h>
#include <string.h>

#define EV_SEED_BYTES 32          /* 256-bit GGM node/leaf seed.  Child inputs
                                   * are exactly 0x01/0x02 || sd (33 bytes). */
#define EV_HASH_BYTES 32          /* SHA3-256 output for Merkle */
#define EV_MAX_DEPTH 20           /* T = 2^20 max => depth 20 */
#define EV_MAX_LEAVES (1u << EV_MAX_DEPTH)

/* Domain separators (single byte prefixes, explicit binding) */
#define EV_DOM_LEFT   0x01        /* GGM left-child derivation  */
#define EV_DOM_RIGHT  0x02        /* GGM right-child derivation */
#define EV_DOM_LEAFKEY 0x03       /* leaf seed -> secret-material expansion */
#define EV_DOM_NODE   0x04        /* Merkle inner node H(L||R) marker */
#define EV_DOM_M      0x05        /* 0x05 || p_be32 || m */
#define EV_DOM_LEAF   0x06        /* Merkle leaf H(0x06 || v_p) */
#define EV_DOM_MATRIX 0x07        /* rho_p = H(0x07 || rho || p_be32) */

/* EVMLDSA_CONSTRUCTION selects the matrix-seed mode.
 *
 *   1 (release default) = SHARED matrix seed: one public rho for all
 *       periods. This is the construction analyzed and benchmarked in
 *       the paper ("evML-DSA"), and the mode in which every result CSV
 *       in results/ was produced. Historically flagged EVMLDSA_LEGACY.
 *   0 = PER-PERIOD seed rho_p = H(0x07 || rho || p_be32): decouples
 *       leaf instances at one extra hash per verification. NOT covered
 *       by the paper's measurements; experimental. */
#ifndef EVMLDSA_LEGACY
#define EVMLDSA_LEGACY 1
#endif

typedef struct {
    uint32_t T;                   /* number of periods (power of two) */
    uint32_t depth;               /* log2(T) */
} ev_params;

#endif
