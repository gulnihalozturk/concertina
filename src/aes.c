#include "aes.h"

/* SubWord via AESE with an all-zero round key: every column holds the same
 * word, so ShiftRows has no effect and lane 0 contains SubWord(w). */
static u32 sub_word(u32 w)
{
	uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(w));

	v = vaeseq_u8(v, vdupq_n_u8(0));
	return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

void aes_setkey(aes_key *k, const u8 *key, size_t key_len)
{
	static const u8 rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
				    0x20, 0x40, 0x80, 0x1b, 0x36};
	u32 w[60];
	const int nk = (int)key_len / 4;
	int i, total;

	CHECK(key_len == 16 || key_len == 24 || key_len == 32);
	k->nr = nk + 6;
	total = 4 * (k->nr + 1);
	for (i = 0; i < nk; i++)
		memcpy(&w[i], key + 4 * i, 4); /* little-endian words */
	for (i = nk; i < total; i++) {
		u32 t = w[i - 1];

		if (i % nk == 0)
			t = sub_word((t >> 8) | (t << 24)) ^ rcon[i / nk - 1];
		else if (nk > 6 && i % nk == 4)
			t = sub_word(t);
		w[i] = w[i - nk] ^ t;
	}
	for (i = 0; i <= k->nr; i++)
		k->rk[i] = vld1q_u8((const u8 *)&w[4 * i]);
	k->dk[0] = k->rk[k->nr];
	for (i = 1; i < k->nr; i++)
		k->dk[i] = vaesimcq_u8(k->rk[k->nr - i]);
	k->dk[k->nr] = k->rk[0];
	memset(w, 0, sizeof(w));
}

FORCEINLINE uint8x16_t ctr_block(u64 s_lo, u64 s_hi, u64 i, int xctr)
{
	u64 lo = xctr ? (s_lo ^ i) : s_lo;
	u64 hi = xctr ? s_hi : (s_hi ^ __builtin_bswap64(i));

	return vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo), vcreate_u64(hi)));
}

FORCEINLINE void ctr_generic(const aes_key *k, const u8 S[16], const u8 *in,
			     u8 *out, size_t len, int xctr)
{
	const u64 s_lo = load_le64(S), s_hi = load_le64(S + 8);
	const int nr = k->nr;
	u64 ctr = xctr ? 1 : 0;
	uint8x16_t rk[15];
	int r, j;

	for (r = 0; r <= nr; r++)
		rk[r] = k->rk[r];

	while (len >= 128) {
		uint8x16_t b[8];

		for (j = 0; j < 8; j++)
			b[j] = ctr_block(s_lo, s_hi, ctr + j, xctr);
		for (r = 0; r < nr - 1; r++)
			for (j = 0; j < 8; j++)
				b[j] = vaesmcq_u8(vaeseq_u8(b[j], rk[r]));
		for (j = 0; j < 8; j++) {
			b[j] = veorq_u8(vaeseq_u8(b[j], rk[nr - 1]), rk[nr]);
			vst1q_u8(out + 16 * j,
				 veorq_u8(b[j], vld1q_u8(in + 16 * j)));
		}
		in += 128;
		out += 128;
		len -= 128;
		ctr += 8;
	}
	while (len >= 16) {
		uint8x16_t b = ctr_block(s_lo, s_hi, ctr, xctr);

		for (r = 0; r < nr - 1; r++)
			b = vaesmcq_u8(vaeseq_u8(b, rk[r]));
		b = veorq_u8(vaeseq_u8(b, rk[nr - 1]), rk[nr]);
		vst1q_u8(out, veorq_u8(b, vld1q_u8(in)));
		in += 16;
		out += 16;
		len -= 16;
		ctr++;
	}
	if (len) {
		u8 ks[16];
		uint8x16_t b = ctr_block(s_lo, s_hi, ctr, xctr);

		for (r = 0; r < nr - 1; r++)
			b = vaesmcq_u8(vaeseq_u8(b, rk[r]));
		b = veorq_u8(vaeseq_u8(b, rk[nr - 1]), rk[nr]);
		vst1q_u8(ks, b);
		xor_bytes(out, in, ks, len);
	}
}

void aes_ctr_be_xor(const aes_key *k, const u8 S[16], const u8 *in, u8 *out,
		    size_t len)
{
	ctr_generic(k, S, in, out, len, 0);
}

void aes_xctr_xor(const aes_key *k, const u8 S[16], const u8 *in, u8 *out,
		  size_t len)
{
	ctr_generic(k, S, in, out, len, 1);
}
