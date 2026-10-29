#include "scheme.h"

enum { ROLE_TWEAK = 0x00, ROLE_CTEXT = 0x01, ROLE_PTEXT = 0x02 };

static void mac_raw(int hash, const void *key, const u8 *a, size_t a_len,
		    const u8 *b, size_t b_len, u8 out[32])
{
	if (hash == SCHEME_HMAC_SHA3_256)
		hmac_sha3_256((const hmac_sha3_256_key *)key, a, a_len, b, b_len, out);
	else
		hmac_sha256((const hmac_sha256_key *)key, a, a_len, b, b_len, out);
}

void scheme_setkey(scheme_ctx *c, const u8 *master_key, size_t key_len,
		   int hash, int portable_hash)
{
	static const char *const labels[6] = {"1", "2", "3", "4", "ctr", "hash"};
	union {
		hmac_sha3_256_key s3;
		hmac_sha256_key s2;
	} mk;
	u8 msg[64], out[32], keys[6][32];
	int u;

	CHECK(key_len == 16 || key_len == 24 || key_len == 32);
	c->hash = hash;
	if (hash == SCHEME_HMAC_SHA3_256)
		hmac_sha3_256_setkey(&mk.s3, master_key, key_len, portable_hash);
	else
		hmac_sha256_setkey(&mk.s2, master_key, key_len, portable_hash);

	for (u = 0; u < 6; u++) {
		size_t n = 0, lab = strlen(SCHEME_NAME) + 1 + strlen(labels[u]);

		CHECK(lab + 9 <= sizeof(msg));
		store_be32(msg, 1);
		n = 4;
		memcpy(msg + n, SCHEME_NAME, strlen(SCHEME_NAME));
		n += strlen(SCHEME_NAME);
		msg[n++] = '/';
		memcpy(msg + n, labels[u], strlen(labels[u]));
		n += strlen(labels[u]);
		msg[n++] = 0x00;
		store_be32(msg + n, (u32)(8 * key_len));
		n += 4;
		mac_raw(hash, &mk, msg, n, NULL, 0, out);
		memcpy(keys[u], out, key_len);
	}
	for (u = 0; u < 4; u++)
		aes_setkey(&c->k[u], keys[u], key_len);
	aes_setkey(&c->kctr, keys[4], key_len);
	if (hash == SCHEME_HMAC_SHA3_256)
		hmac_sha3_256_setkey(&c->hk.s3, keys[5], key_len, portable_hash);
	else
		hmac_sha256_setkey(&c->hk.s2, keys[5], key_len, portable_hash);
	memset(keys, 0, sizeof(keys));
	memset(&mk, 0, sizeof(mk));
	memset(out, 0, sizeof(out));
}

/* Returns H(tail || role || T) as two 128-bit halves. */
FORCEINLINE void mask(const scheme_ctx *c, const u8 *tail, size_t tail_len,
		      u8 role, const u8 *tweak, uint8x16_t *m1, uint8x16_t *m2)
{
	u8 suffix[1 + SCHEME_TWEAK_LEN], x[32];

	suffix[0] = role;
	memcpy(suffix + 1, tweak, SCHEME_TWEAK_LEN);
	mac_raw(c->hash, &c->hk, tail, tail_len, suffix, sizeof(suffix), x);
	*m1 = vld1q_u8(x);
	*m2 = vld1q_u8(x + 16);
}

void scheme_encrypt(const scheme_ctx *c, u8 *dst, const u8 *src, size_t len,
		    const u8 tweak[SCHEME_TWEAK_LEN])
{
	uint8x16_t a1, a2, u1, u2, r, l, v1, v2;
	u8 S[16];
	const size_t tl = len - 32;

	CHECK(len >= SCHEME_MIN_LEN);
	mask(c, src + 32, tl, ROLE_PTEXT, tweak, &a1, &a2);
	u1 = veorq_u8(vld1q_u8(src), a1);
	u2 = veorq_u8(vld1q_u8(src + 16), a2);

	r = veorq_u8(u2, aes_enc1(&c->k[0], u1));
	l = veorq_u8(u1, aes_enc1(&c->k[1], r));
	v2 = veorq_u8(r, aes_enc1(&c->k[2], l));
	v1 = veorq_u8(l, aes_enc1(&c->k[3], v2));

	vst1q_u8(S, veorq_u8(veorq_u8(u1, u2), veorq_u8(v1, v2)));
	aes_ctr_be_xor(&c->kctr, S, src + 32, dst + 32, tl);

	mask(c, dst + 32, tl, ROLE_CTEXT, tweak, &a1, &a2);
	vst1q_u8(dst, veorq_u8(v1, a1));
	vst1q_u8(dst + 16, veorq_u8(v2, a2));
}

void scheme_decrypt(const scheme_ctx *c, u8 *dst, const u8 *src, size_t len,
		    const u8 tweak[SCHEME_TWEAK_LEN])
{
	uint8x16_t a1, a2, u1, u2, r, l, v1, v2;
	u8 S[16];
	const size_t tl = len - 32;

	CHECK(len >= SCHEME_MIN_LEN);
	mask(c, src + 32, tl, ROLE_CTEXT, tweak, &a1, &a2);
	v1 = veorq_u8(vld1q_u8(src), a1);
	v2 = veorq_u8(vld1q_u8(src + 16), a2);

	l = veorq_u8(v1, aes_enc1(&c->k[3], v2));
	r = veorq_u8(v2, aes_enc1(&c->k[2], l));
	u1 = veorq_u8(l, aes_enc1(&c->k[1], r));
	u2 = veorq_u8(r, aes_enc1(&c->k[0], u1));

	vst1q_u8(S, veorq_u8(veorq_u8(u1, u2), veorq_u8(v1, v2)));
	aes_ctr_be_xor(&c->kctr, S, src + 32, dst + 32, tl);

	mask(c, dst + 32, tl, ROLE_PTEXT, tweak, &a1, &a2);
	vst1q_u8(dst, veorq_u8(u1, a1));
	vst1q_u8(dst + 16, veorq_u8(u2, a2));
}
