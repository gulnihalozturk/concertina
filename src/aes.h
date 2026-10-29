/*
 * AES with the ARMv8 Cryptographic Extension (AESE/AESMC, AESD/AESIMC).
 * The same code is used by every mode in the benchmark, so that differences
 * between the modes are not caused by different AES implementations.
 */
#pragma once
#include "common.h"

typedef struct {
	uint8x16_t rk[15]; /* encryption round keys */
	uint8x16_t dk[15]; /* equivalent-inverse-cipher round keys */
	int nr;            /* 10, 12 or 14 */
} aes_key;

void aes_setkey(aes_key *k, const u8 *key, size_t key_len);

FORCEINLINE uint8x16_t aes_enc1(const aes_key *k, uint8x16_t b)
{
	const int nr = k->nr;
	int r;

	for (r = 0; r < nr - 1; r++)
		b = vaesmcq_u8(vaeseq_u8(b, k->rk[r]));
	b = vaeseq_u8(b, k->rk[nr - 1]);
	return veorq_u8(b, k->rk[nr]);
}

FORCEINLINE uint8x16_t aes_dec1(const aes_key *k, uint8x16_t b)
{
	const int nr = k->nr;
	int r;

	for (r = 0; r < nr - 1; r++)
		b = vaesimcq_u8(vaesdq_u8(b, k->dk[r]));
	b = vaesdq_u8(b, k->dk[nr - 1]);
	return veorq_u8(b, k->dk[nr]);
}

/*
 * Counter-mode keystream XOR, 8 blocks in parallel.
 *
 * aes_ctr_be_xor: block i (i = 0, 1, ...) is E_K(S xor <i>_128), with <i>_128
 *                 the 128-bit big-endian encoding of i. Used by the proposed
 *                 mode.
 * aes_xctr_xor:   block i (i = 1, 2, ...) is E_K(S xor le64(i) || 0^64). This
 *                 is XCTR as used by HCTR2.
 */
void aes_ctr_be_xor(const aes_key *k, const u8 S[16], const u8 *in, u8 *out,
		    size_t len);
void aes_xctr_xor(const aes_key *k, const u8 S[16], const u8 *in, u8 *out,
		  size_t len);
