/*
 * Keccak-f[1600], SHA3-256 and HMAC-SHA3-256 (FIPS 202, FIPS 198-1).
 *
 * Backends:
 *   - CE:       ARMv8.2-SHA3 instructions (EOR3, RAX1, XAR, BCAX); selected
 *               when the compiler defines __ARM_FEATURE_SHA3,
 *   - portable: 64-bit scalar code, used to model platforms without SHA-3
 *               instructions.
 * HMAC keys are pre-processed once: the states after absorbing K^ipad and
 * K^opad are stored, so that each MAC evaluation only absorbs the message.
 */
#pragma once
#include "common.h"

#define SHA3_256_RATE 136

extern const int keccak_have_ce;

void keccak_permute(u64 st[25], int portable);
void sha3_256(const u8 *msg, size_t len, u8 out[32], int portable);

typedef struct {
	u64 inner[25];
	u64 outer[25];
	int portable;
} hmac_sha3_256_key;

void hmac_sha3_256_setkey(hmac_sha3_256_key *k, const u8 *key, size_t key_len,
			  int portable);
/* MAC over the concatenation a || b, where b is a short suffix (<= 64 bytes). */
void hmac_sha3_256(const hmac_sha3_256_key *k, const u8 *a, size_t a_len,
		   const u8 *b, size_t b_len, u8 out[32]);
