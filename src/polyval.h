/*
 * POLYVAL (RFC 8452) as used by HCTR2.
 *
 * Two backends:
 *   - PMULL:    ARMv8 carry-less multiply, 8-block aggregated reduction,
 *   - portable: constant-time 64-bit integer multiplications (no PMULL),
 *               used to model platforms without carry-less multiplication.
 */
#pragma once
#include "common.h"

#define POLYVAL_NPOWERS 8

typedef struct {
	uint64x2_t pow[POLYVAL_NPOWERS + 1];  /* pow[i] = h^i (Montgomery form) */
	uint64x2_t pows[POLYVAL_NPOWERS + 1]; /* halves swapped */
	u64 h_lo, h_hi;                        /* h for the portable backend */
	int portable;
} polyval_key;

typedef struct {
	uint64x2_t s;
} polyval_state;

void polyval_setkey(polyval_key *key, const u8 h[16], int portable);
FORCEINLINE void polyval_init(polyval_state *st) { st->s = vdupq_n_u64(0); }
void polyval_update(polyval_state *st, const polyval_key *key, const u8 *data,
		    size_t nblocks);
FORCEINLINE void polyval_emit(const polyval_state *st, u8 out[16])
{
	vst1q_u8(out, vreinterpretq_u8_u64(st->s));
}
