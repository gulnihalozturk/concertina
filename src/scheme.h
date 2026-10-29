/*
 * Concertina: a tweakable wide-block mode (inverse-free, multiplication-free).
 *
 * Core, for n = 128 and P = P1 || P2 || Pbar with |P| >= 32 bytes:
 *   X_P = H(Pbar || 0x02 || T),       A1 || A2 = X_P
 *   U1 = P1 ^ A1, U2 = P2 ^ A2
 *   R  = U2 ^ E_K1(U1),  L  = U1 ^ E_K2(R)
 *   V2 = R  ^ E_K3(L),   V1 = L  ^ E_K4(V2)
 *   S  = U1 ^ U2 ^ V1 ^ V2
 *   Cbar = Pbar ^ CTR_Kctr(S),  block i = E_Kctr(S ^ <i>_128), i = 0, 1, ...
 *   X_C = H(Cbar || 0x01 || T),       A3 || A4 = X_C
 *   C1 = V1 ^ A3, C2 = V2 ^ A4
 *
 * H is HMAC-SHA3-256 (paper) or HMAC-SHA-256 (alternative instantiation).
 *
 * Byte-oriented encoding: the two-bit role codes of the paper (10, 01, 00)
 * are encoded as one octet (0x02, 0x01, 0x00) directly followed by the
 * 16-byte tweak. The domain-separation argument is unchanged, since the role
 * code is still followed by exactly n bits.
 *
 * Working keys (NIST SP 800-108r1, counter mode, one iteration):
 *   K_u = MSB_k( H_KM( <1>_32 || "concertina/u" || 0x00 || <k>_32 ) ),
 *   u in {1, 2, 3, 4, ctr, hash}.
 */
#pragma once
#include "aes.h"
#include "keccak.h"
#include "sha256.h"

/* Prefix of the KDF labels ("concertina/1", ...), as in the paper. */
#ifndef SCHEME_NAME
#define SCHEME_NAME "concertina"
#endif
#define SCHEME_DISPLAY_NAME "Concertina"

#define SCHEME_MIN_LEN 32
#define SCHEME_TWEAK_LEN 16

enum scheme_hash { SCHEME_HMAC_SHA3_256 = 0, SCHEME_HMAC_SHA256 = 1 };

typedef struct {
	aes_key k[4];
	aes_key kctr;
	int hash;
	union {
		hmac_sha3_256_key s3;
		hmac_sha256_key s2;
	} hk;
} scheme_ctx;

/* portable_hash = 1 selects the scalar Keccak/SHA-256 backend. */
void scheme_setkey(scheme_ctx *c, const u8 *master_key, size_t key_len,
		   int hash, int portable_hash);
void scheme_encrypt(const scheme_ctx *c, u8 *dst, const u8 *src, size_t len,
		    const u8 tweak[SCHEME_TWEAK_LEN]);
void scheme_decrypt(const scheme_ctx *c, u8 *dst, const u8 *src, size_t len,
		    const u8 tweak[SCHEME_TWEAK_LEN]);
