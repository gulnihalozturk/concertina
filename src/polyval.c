#include "polyval.h"

/* ---------------- PMULL backend ---------------- */

#define POLYVAL_REDUCTION_CONST 0xc200000000000000ULL

FORCEINLINE uint64x2_t pmull_lo(uint64x2_t a, uint64x2_t b)
{
	return vreinterpretq_u64_p128(
		vmull_p64((poly64_t)vgetq_lane_u64(a, 0),
			  (poly64_t)vgetq_lane_u64(b, 0)));
}

FORCEINLINE uint64x2_t pmull_hi(uint64x2_t a, uint64x2_t b)
{
	return vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(a),
						     vreinterpretq_p64_u64(b)));
}

/* Montgomery reduction: returns (hi*x^128 + lo) * x^-128 mod p(x). */
FORCEINLINE uint64x2_t pv_reduce(uint64x2_t lo, uint64x2_t mid, uint64x2_t hi)
{
	const uint64x2_t zero = vdupq_n_u64(0);
	const uint64x2_t c = vdupq_n_u64(POLYVAL_REDUCTION_CONST);
	uint64x2_t t;

	lo = veorq_u64(lo, vextq_u64(zero, mid, 1));
	hi = veorq_u64(hi, vextq_u64(mid, zero, 1));
	t = pmull_lo(lo, c);
	lo = veorq_u64(t, vextq_u64(lo, lo, 1));
	t = pmull_lo(lo, c);
	lo = veorq_u64(t, vextq_u64(lo, lo, 1));
	return veorq_u64(lo, hi);
}

FORCEINLINE uint64x2_t pv_mul(uint64x2_t a, uint64x2_t b, uint64x2_t bs)
{
	uint64x2_t lo = pmull_lo(a, b);
	uint64x2_t hi = pmull_hi(a, b);
	uint64x2_t mid = veorq_u64(pmull_lo(a, bs), pmull_hi(a, bs));

	return pv_reduce(lo, mid, hi);
}

static void polyval_update_pmull(polyval_state *st, const polyval_key *key,
				 const u8 *data, size_t nblocks)
{
	uint64x2_t s = st->s;
	int i;

	while (nblocks >= POLYVAL_NPOWERS) {
		uint64x2_t lo = vdupq_n_u64(0), mid = lo, hi = lo;

		for (i = 0; i < POLYVAL_NPOWERS; i++) {
			uint64x2_t x = vreinterpretq_u64_u8(vld1q_u8(data + 16 * i));
			const uint64x2_t p = key->pow[POLYVAL_NPOWERS - i];
			const uint64x2_t ps = key->pows[POLYVAL_NPOWERS - i];

			if (i == 0)
				x = veorq_u64(x, s);
			lo = veorq_u64(lo, pmull_lo(x, p));
			hi = veorq_u64(hi, pmull_hi(x, p));
			mid = veorq_u64(mid, veorq_u64(pmull_lo(x, ps),
						       pmull_hi(x, ps)));
		}
		s = pv_reduce(lo, mid, hi);
		data += 16 * POLYVAL_NPOWERS;
		nblocks -= POLYVAL_NPOWERS;
	}
	while (nblocks--) {
		uint64x2_t x = vreinterpretq_u64_u8(vld1q_u8(data));

		s = pv_mul(veorq_u64(s, x), key->pow[1], key->pows[1]);
		data += 16;
	}
	st->s = s;
}

/* ---------------- portable backend (no PMULL) ---------------- */

/* Low 64 bits of the carry-less product, using integer multiplications on
 * bit-interleaved operands (the technique of BearSSL's ghash_ctmul64). */
static inline u64 bmul64(u64 x, u64 y)
{
	const u64 m0 = 0x1111111111111111ULL, m1 = 0x2222222222222222ULL;
	const u64 m2 = 0x4444444444444444ULL, m3 = 0x8888888888888888ULL;
	u64 x0 = x & m0, x1 = x & m1, x2 = x & m2, x3 = x & m3;
	u64 y0 = y & m0, y1 = y & m1, y2 = y & m2, y3 = y & m3;
	u64 z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
	u64 z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
	u64 z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
	u64 z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

	return (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3);
}

static inline u64 rev64(u64 x)
{
	x = ((x >> 1) & 0x5555555555555555ULL) | ((x & 0x5555555555555555ULL) << 1);
	x = ((x >> 2) & 0x3333333333333333ULL) | ((x & 0x3333333333333333ULL) << 2);
	x = ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL) | ((x & 0x0F0F0F0F0F0F0F0FULL) << 4);
	return __builtin_bswap64(x);
}

static inline void clmul64(u64 x, u64 y, u64 *lo, u64 *hi)
{
	*lo = bmul64(x, y);
	*hi = rev64(bmul64(rev64(x), rev64(y))) >> 1;
}

static void pv_mul_portable(u64 a_lo, u64 a_hi, u64 b_lo, u64 b_hi, u64 *r_lo,
			    u64 *r_hi)
{
	u64 l0, l1, h0, h1, m0, m1, t0, t1;

	clmul64(a_lo, b_lo, &l0, &l1);
	clmul64(a_hi, b_hi, &h0, &h1);
	clmul64(a_lo ^ a_hi, b_lo ^ b_hi, &m0, &m1);
	m0 ^= l0 ^ h0;
	m1 ^= l1 ^ h1;
	l1 ^= m0;
	h0 ^= m1;
	/* Montgomery reduction, as in the PMULL backend. */
	clmul64(l0, POLYVAL_REDUCTION_CONST, &t0, &t1);
	t0 ^= l1;
	t1 ^= l0;
	clmul64(t0, POLYVAL_REDUCTION_CONST, &l0, &l1);
	l0 ^= t1;
	l1 ^= t0;
	*r_lo = l0 ^ h0;
	*r_hi = l1 ^ h1;
}

static void polyval_update_portable(polyval_state *st, const polyval_key *key,
				    const u8 *data, size_t nblocks)
{
	u64 s_lo = vgetq_lane_u64(st->s, 0), s_hi = vgetq_lane_u64(st->s, 1);

	while (nblocks--) {
		s_lo ^= load_le64(data);
		s_hi ^= load_le64(data + 8);
		pv_mul_portable(s_lo, s_hi, key->h_lo, key->h_hi, &s_lo, &s_hi);
		data += 16;
	}
	st->s = vcombine_u64(vcreate_u64(s_lo), vcreate_u64(s_hi));
}

/* ---------------- common ---------------- */

void polyval_setkey(polyval_key *key, const u8 h[16], int portable)
{
	int i;

	key->portable = portable;
	key->h_lo = load_le64(h);
	key->h_hi = load_le64(h + 8);
	key->pow[1] = vreinterpretq_u64_u8(vld1q_u8(h));
	key->pows[1] = vextq_u64(key->pow[1], key->pow[1], 1);
	for (i = 2; i <= POLYVAL_NPOWERS; i++) {
		key->pow[i] = pv_mul(key->pow[i - 1], key->pow[1], key->pows[1]);
		key->pows[i] = vextq_u64(key->pow[i], key->pow[i], 1);
	}
}

void polyval_update(polyval_state *st, const polyval_key *key, const u8 *data,
		    size_t nblocks)
{
	if (key->portable)
		polyval_update_portable(st, key, data, nblocks);
	else
		polyval_update_pmull(st, key, data, nblocks);
}
