/*
 * SHA-256 and HMAC-SHA-256 (FIPS 180-4, FIPS 198-1).
 *
 * Backends: ARMv8 SHA-2 instructions (SHA256H/H2/SU0/SU1) when the compiler
 * defines __ARM_FEATURE_SHA2, and portable scalar code.
 * As for HMAC-SHA3-256, the ipad/opad states are precomputed per key.
 */
#pragma once
#include "common.h"

#define SHA256_BLOCK 64

extern const int sha256_have_ce;

void sha256(const u8 *msg, size_t len, u8 out[32], int portable);

typedef struct {
	u32 inner[8];
	u32 outer[8];
	int portable;
} hmac_sha256_key;

void hmac_sha256_setkey(hmac_sha256_key *k, const u8 *key, size_t key_len,
			int portable);
void hmac_sha256(const hmac_sha256_key *k, const u8 *a, size_t a_len,
		 const u8 *b, size_t b_len, u8 out[32]);
