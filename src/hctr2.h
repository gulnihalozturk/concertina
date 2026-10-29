/*
 * HCTR2 (Crowley, Huckleberry, Biggers, ePrint 2021/1441), re-implemented on
 * the shared AES code of this benchmark and validated against the official
 * test vectors of the HCTR2 repository (src/testvecs/hctr2_testvecs.c).
 */
#pragma once
#include "aes.h"
#include "polyval.h"

#define HCTR2_DEFAULT_TWEAK_LEN 16

typedef struct {
	aes_key aes;
	polyval_key pv;
	u8 L[16];
	polyval_state init[2]; /* precomputed first hash block, tweak length 16 */
} hctr2_ctx;

void hctr2_setkey(hctr2_ctx *c, const u8 *key, size_t key_len,
		  int portable_polyval);
void hctr2_crypt(const hctr2_ctx *c, u8 *dst, const u8 *src, size_t len,
		 const u8 *tweak, size_t tweak_len, int encrypt);
