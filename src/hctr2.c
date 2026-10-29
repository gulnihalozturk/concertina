#include "hctr2.h"

static void first_block_state(const hctr2_ctx *c, polyval_state *st,
			      size_t tweak_len, int divisible)
{
	u8 blk[16] = {0};

	store_le64(blk, (u64)tweak_len * 8 * 2 + (divisible ? 2 : 3));
	polyval_init(st);
	polyval_update(st, &c->pv, blk, 1);
}

void hctr2_setkey(hctr2_ctx *c, const u8 *key, size_t key_len,
		  int portable_polyval)
{
	u8 h[16] = {0};

	aes_setkey(&c->aes, key, key_len);
	vst1q_u8(h, aes_enc1(&c->aes, vdupq_n_u8(0)));
	memset(c->L, 0, 16);
	c->L[0] = 0x01;
	vst1q_u8(c->L, aes_enc1(&c->aes, vld1q_u8(c->L)));
	polyval_setkey(&c->pv, h, portable_polyval);
	first_block_state(c, &c->init[0], HCTR2_DEFAULT_TWEAK_LEN, 0);
	first_block_state(c, &c->init[1], HCTR2_DEFAULT_TWEAK_LEN, 1);
}

static void hash_padded(const hctr2_ctx *c, polyval_state *st, const u8 *data,
			size_t len, int one_pad)
{
	const size_t nblocks = len / 16, rem = len % 16;

	polyval_update(st, &c->pv, data, nblocks);
	if (rem) {
		u8 blk[16] = {0};

		memcpy(blk, data + 16 * nblocks, rem);
		if (one_pad)
			blk[rem] = 0x01;
		polyval_update(st, &c->pv, blk, 1);
	}
}

void hctr2_crypt(const hctr2_ctx *c, u8 *dst, const u8 *src, size_t len,
		 const u8 *tweak, size_t tweak_len, int encrypt)
{
	polyval_state st1, st2;
	u8 digest[16], MM[16], UU[16], S[16];
	const size_t n_len = len - 16;
	const int divisible = (n_len % 16) == 0;

	CHECK(len >= 16);
	if (tweak_len == HCTR2_DEFAULT_TWEAK_LEN)
		st1 = c->init[divisible];
	else
		first_block_state(c, &st1, tweak_len, divisible);
	hash_padded(c, &st1, tweak, tweak_len, 0);
	st2 = st1;

	hash_padded(c, &st1, src + 16, n_len, 1);
	polyval_emit(&st1, digest);
	xor_bytes(MM, src, digest, 16);

	if (encrypt)
		vst1q_u8(UU, aes_enc1(&c->aes, vld1q_u8(MM)));
	else
		vst1q_u8(UU, aes_dec1(&c->aes, vld1q_u8(MM)));

	vst1q_u8(S, veorq_u8(veorq_u8(vld1q_u8(MM), vld1q_u8(UU)),
			     vld1q_u8(c->L)));
	aes_xctr_xor(&c->aes, S, src + 16, dst + 16, n_len);

	hash_padded(c, &st2, dst + 16, n_len, 1);
	polyval_emit(&st2, digest);
	xor_bytes(dst, UU, digest, 16);
}
