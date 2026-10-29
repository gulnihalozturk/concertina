#include "xts.h"

void xts_setkey(xts_ctx *c, const u8 *key, size_t key_len)
{
	aes_setkey(&c->k1, key, key_len / 2);
	aes_setkey(&c->k2, key + key_len / 2, key_len / 2);
}

FORCEINLINE uint8x16_t mul_alpha(uint8x16_t t)
{
	uint64x2_t v = vreinterpretq_u64_u8(t);
	u64 lo = vgetq_lane_u64(v, 0), hi = vgetq_lane_u64(v, 1);
	u64 carry = hi >> 63;

	hi = (hi << 1) | (lo >> 63);
	lo = (lo << 1) ^ (0x87 & (0 - carry));
	return vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo), vcreate_u64(hi)));
}

FORCEINLINE void xts_generic(const xts_ctx *c, u8 *dst, const u8 *src,
			     size_t len, const u8 iv[16], int enc)
{
	const aes_key *k = &c->k1;
	const int nr = k->nr;
	uint8x16_t t = aes_enc1(&c->k2, vld1q_u8(iv));
	int r, j;

	CHECK(len >= 16 && len % 16 == 0);
	while (len >= 128) {
		uint8x16_t tw[8], b[8];

		for (j = 0; j < 8; j++) {
			tw[j] = t;
			t = mul_alpha(t);
			b[j] = veorq_u8(vld1q_u8(src + 16 * j), tw[j]);
		}
		if (enc) {
			for (r = 0; r < nr - 1; r++)
				for (j = 0; j < 8; j++)
					b[j] = vaesmcq_u8(vaeseq_u8(b[j], k->rk[r]));
			for (j = 0; j < 8; j++)
				b[j] = veorq_u8(vaeseq_u8(b[j], k->rk[nr - 1]), k->rk[nr]);
		} else {
			for (r = 0; r < nr - 1; r++)
				for (j = 0; j < 8; j++)
					b[j] = vaesimcq_u8(vaesdq_u8(b[j], k->dk[r]));
			for (j = 0; j < 8; j++)
				b[j] = veorq_u8(vaesdq_u8(b[j], k->dk[nr - 1]), k->dk[nr]);
		}
		for (j = 0; j < 8; j++)
			vst1q_u8(dst + 16 * j, veorq_u8(b[j], tw[j]));
		src += 128;
		dst += 128;
		len -= 128;
	}
	while (len) {
		uint8x16_t b = veorq_u8(vld1q_u8(src), t);

		b = enc ? aes_enc1(k, b) : aes_dec1(k, b);
		vst1q_u8(dst, veorq_u8(b, t));
		t = mul_alpha(t);
		src += 16;
		dst += 16;
		len -= 16;
	}
}

void xts_crypt(const xts_ctx *c, u8 *dst, const u8 *src, size_t len,
	       const u8 iv[16], int encrypt)
{
	if (encrypt)
		xts_generic(c, dst, src, len, iv, 1);
	else
		xts_generic(c, dst, src, len, iv, 0);
}
