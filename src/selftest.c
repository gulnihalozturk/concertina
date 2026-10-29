/*
 * Self-tests: every implementation is checked against external test vectors
 * before any benchmark is run.
 *   AES      - FIPS 197, Appendix C
 *   SHA-3    - Python hashlib (KAT), SHA3-256("abc"), CE vs. portable Keccak-f
 *   HMAC     - Python hmac (KAT), all message split points
 *   POLYVAL, XCTR, HCTR2 - official vectors of the HCTR2 repository
 *   XTS      - Python `cryptography` (KAT)
 *   proposed mode - independent Python reference (python/scheme_ref.py)
 */
#include "selftest.h"
#include "hctr2.h"
#include "kat_generated.h"
#include "scheme.h"
#include "testvecs/hctr2_testvecs.h"
#include "testvecs/polyval_testvecs.h"
#include "testvecs/xctr_testvecs.h"
#include "xts.h"

static int failures;

#define EXPECT(cond, ...)                                                      \
	do {                                                                   \
		if (!(cond)) {                                                 \
			failures++;                                            \
			fprintf(stderr, "  FAIL: " __VA_ARGS__);               \
			fprintf(stderr, "\n");                                 \
		}                                                              \
	} while (0)

static int hexeq(const u8 *a, const char *hex, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		unsigned v;

		sscanf(hex + 2 * i, "%2x", &v);
		if (a[i] != (u8)v)
			return 0;
	}
	return 1;
}

static void test_aes(void)
{
	static const struct {
		size_t klen;
		const char *ct;
	} v[] = {{16, "69c4e0d86a7b0430d8cdb78070b4c55a"},
		 {24, "dda97ca4864cdfe06eaf70a0ec0d7191"},
		 {32, "8ea2b7ca516745bfeafc49904b496089"}};
	u8 key[32], pt[16], ct[16], back[16];
	size_t i, j;
	aes_key k;

	for (j = 0; j < 32; j++)
		key[j] = (u8)j;
	for (j = 0; j < 16; j++)
		pt[j] = (u8)(0x11 * j);
	for (i = 0; i < 3; i++) {
		aes_setkey(&k, key, v[i].klen);
		vst1q_u8(ct, aes_enc1(&k, vld1q_u8(pt)));
		vst1q_u8(back, aes_dec1(&k, vld1q_u8(ct)));
		EXPECT(hexeq(ct, v[i].ct, 16), "AES-%zu encryption", 8 * v[i].klen);
		EXPECT(!memcmp(back, pt, 16), "AES-%zu decryption", 8 * v[i].klen);
	}
}

static void test_keccak(void)
{
	u64 a[25], b[25];
	u8 d[32];
	int i, t;

	sha3_256((const u8 *)"abc", 3, d, 1);
	EXPECT(hexeq(d, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", 32),
	       "SHA3-256(abc), portable");
	sha3_256((const u8 *)"abc", 3, d, 0);
	EXPECT(hexeq(d, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", 32),
	       "SHA3-256(abc), CE");
	for (t = 0; t < 64; t++) {
		for (i = 0; i < 25; i++)
			a[i] = b[i] = ((u64)rand() << 42) ^ ((u64)rand() << 21) ^ (u64)rand();
		keccak_permute(a, 1);
		keccak_permute(b, 0);
		EXPECT(!memcmp(a, b, sizeof(a)), "Keccak-f CE vs portable");
	}
	sha256((const u8 *)"abc", 3, d, 1);
	EXPECT(hexeq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32),
	       "SHA-256(abc), portable");
	sha256((const u8 *)"abc", 3, d, 0);
	EXPECT(hexeq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32),
	       "SHA-256(abc), CE");
}

static void test_mac(void)
{
	size_t i, split;
	int portable;

	for (i = 0; i < KAT_MAC_COUNT; i++) {
		const struct kat_mac *v = &kat_mac[i];

		for (portable = 0; portable <= 1; portable++) {
			u8 d[32], m[32];

			if (v->hash == 0)
				sha3_256(v->msg, v->len, d, portable);
			else
				sha256(v->msg, v->len, d, portable);
			EXPECT(!memcmp(d, v->digest, 32), "hash %d len %zu", v->hash, v->len);
			for (split = v->len > 64 ? v->len - 64 : 0; split <= v->len; split++) {
				if (v->hash == 0) {
					hmac_sha3_256_key k;

					hmac_sha3_256_setkey(&k, v->key, v->key_len, portable);
					hmac_sha3_256(&k, v->msg, split, v->msg + split,
						      v->len - split, m);
				} else {
					hmac_sha256_key k;

					hmac_sha256_setkey(&k, v->key, v->key_len, portable);
					hmac_sha256(&k, v->msg, split, v->msg + split,
						    v->len - split, m);
				}
				EXPECT(!memcmp(m, v->mac, 32),
				       "HMAC hash %d key %zu len %zu split %zu portable %d",
				       v->hash, v->key_len, v->len, split, portable);
			}
		}
	}
}

static void test_polyval(void)
{
	size_t i;
	int portable;

	for (i = 0; i < polyval_tv_count; i++) {
		const struct polyval_testvec *v = &polyval_tv[i];

		for (portable = 0; portable <= 1; portable++) {
			polyval_key k;
			polyval_state st;
			u8 out[16];

			polyval_setkey(&k, v->key.data, portable);
			polyval_init(&st);
			polyval_update(&st, &k, v->message.data, v->message.len / 16);
			polyval_emit(&st, out);
			EXPECT(!memcmp(out, v->hash.data, 16), "POLYVAL vector %zu (portable %d)",
			       i, portable);
		}
	}
}

static void test_xctr_set(const struct xctr_testvec *tv, size_t n, size_t klen)
{
	size_t i;

	for (i = 0; i < n; i++) {
		const struct xctr_testvec *v = &tv[i];
		u8 out[1024];
		aes_key k;

		CHECK(v->plaintext.len <= sizeof(out) && v->key.len == klen);
		aes_setkey(&k, v->key.data, klen);
		aes_xctr_xor(&k, v->nonce.data, v->plaintext.data, out, v->plaintext.len);
		EXPECT(!memcmp(out, v->ciphertext.data, v->plaintext.len),
		       "XCTR-AES-%zu vector %zu", 8 * klen, i);
	}
}

static void test_hctr2_set(const struct hctr2_testvec *tv, size_t n, size_t klen)
{
	size_t i;
	int portable;

	for (i = 0; i < n; i++) {
		const struct hctr2_testvec *v = &tv[i];
		const size_t len = v->plaintext.len;
		u8 ct[1024], pt[1024];

		CHECK(len <= sizeof(ct));
		for (portable = 0; portable <= 1; portable++) {
			hctr2_ctx c;

			hctr2_setkey(&c, v->key.data, klen, portable);
			hctr2_crypt(&c, ct, v->plaintext.data, len, v->tweak.data,
				    v->tweak.len, 1);
			EXPECT(!memcmp(ct, v->ciphertext.data, len),
			       "HCTR2-AES-%zu enc vector %zu (portable POLYVAL %d)", 8 * klen, i,
			       portable);
			hctr2_crypt(&c, pt, ct, len, v->tweak.data, v->tweak.len, 0);
			EXPECT(!memcmp(pt, v->plaintext.data, len),
			       "HCTR2-AES-%zu dec vector %zu (portable POLYVAL %d)", 8 * klen, i,
			       portable);
		}
	}
}

static void test_xts(void)
{
	size_t i;

	for (i = 0; i < KAT_XTS_COUNT; i++) {
		const struct kat_xts *v = &kat_xts[i];
		u8 ct[4096], pt[4096];
		xts_ctx c;

		xts_setkey(&c, v->key, v->key_len);
		xts_crypt(&c, ct, v->pt, v->len, v->iv, 1);
		EXPECT(!memcmp(ct, v->ct, v->len), "XTS enc vector %zu", i);
		xts_crypt(&c, pt, ct, v->len, v->iv, 0);
		EXPECT(!memcmp(pt, v->pt, v->len), "XTS dec vector %zu", i);
	}
}

static void test_scheme(void)
{
	size_t i;
	int portable;

	for (i = 0; i < KAT_SCHEME_COUNT; i++) {
		const struct kat_scheme *v = &kat_scheme[i];
		u8 buf[1024], out[1024];

		for (portable = 0; portable <= 1; portable++) {
			scheme_ctx c;

			scheme_setkey(&c, v->key, v->key_len, v->hash, portable);
			scheme_encrypt(&c, out, v->pt, v->len, v->tweak);
			EXPECT(!memcmp(out, v->ct, v->len),
			       SCHEME_DISPLAY_NAME " enc: hash %d, key %zu, len %zu, portable %d",
			       v->hash, v->key_len, v->len, portable);
			scheme_decrypt(&c, buf, v->ct, v->len, v->tweak);
			EXPECT(!memcmp(buf, v->pt, v->len),
			       SCHEME_DISPLAY_NAME " dec: hash %d, key %zu, len %zu, portable %d",
			       v->hash, v->key_len, v->len, portable);
			/* in place */
			memcpy(buf, v->pt, v->len);
			scheme_encrypt(&c, buf, buf, v->len, v->tweak);
			EXPECT(!memcmp(buf, v->ct, v->len), SCHEME_DISPLAY_NAME " in-place enc");
			scheme_decrypt(&c, buf, buf, v->len, v->tweak);
			EXPECT(!memcmp(buf, v->pt, v->len), SCHEME_DISPLAY_NAME " in-place dec");
		}
	}
}

int run_selftests(int verbose)
{
	failures = 0;
	test_aes();
	test_keccak();
	test_mac();
	test_polyval();
	test_xctr_set(xctr_aes128_tv, xctr_aes128_tv_count, 16);
	test_xctr_set(xctr_aes192_tv, xctr_aes192_tv_count, 24);
	test_xctr_set(xctr_aes256_tv, xctr_aes256_tv_count, 32);
	test_hctr2_set(hctr2_aes128_tv, hctr2_aes128_tv_count, 16);
	test_hctr2_set(hctr2_aes192_tv, hctr2_aes192_tv_count, 24);
	test_hctr2_set(hctr2_aes256_tv, hctr2_aes256_tv_count, 32);
	test_xts();
	test_scheme();
	if (verbose)
		printf("Self-tests: %s (AES, SHA-3/Keccak, SHA-256, HMAC, POLYVAL: %zu, "
		       "XCTR: %zu, HCTR2: %zu, XTS: %d, " SCHEME_DISPLAY_NAME ": %d vectors)\n",
		       failures ? "FAILED" : "all passed", polyval_tv_count,
		       xctr_aes128_tv_count + xctr_aes192_tv_count + xctr_aes256_tv_count,
		       hctr2_aes128_tv_count + hctr2_aes192_tv_count + hctr2_aes256_tv_count,
		       KAT_XTS_COUNT, KAT_SCHEME_COUNT);
	return failures;
}
