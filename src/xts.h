/* AES-XTS (IEEE 1619, NIST SP 800-38E) as a narrow-block reference point.
 * Only lengths that are multiples of 16 bytes are supported (no ciphertext
 * stealing), which covers all benchmarked message sizes. */
#pragma once
#include "aes.h"

typedef struct {
	aes_key k1, k2;
} xts_ctx;

void xts_setkey(xts_ctx *c, const u8 *key, size_t key_len); /* key_len = 2k */
void xts_crypt(const xts_ctx *c, u8 *dst, const u8 *src, size_t len,
	       const u8 iv[16], int encrypt);
