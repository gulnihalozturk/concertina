/*
 * Common definitions for the wide-block mode benchmark.
 *
 * Target: AArch64 with the ARMv8 Cryptographic Extension (AES, PMULL, SHA-2)
 * and, optionally, the ARMv8.2 SHA-3 extension. Developed for Apple M-series
 * processors (macOS); also builds on AArch64 Linux.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(__aarch64__)
#error "This benchmark targets AArch64 (e.g. Apple M-series)."
#endif
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "A little-endian target is assumed."
#endif
#if !defined(__ARM_FEATURE_AES) && !defined(__ARM_FEATURE_CRYPTO)
#error "Compile with the ARMv8 Cryptographic Extension enabled (see Makefile)."
#endif

#include <arm_neon.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define FORCEINLINE static inline __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))

#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "Check failed: %s (%s:%d)\n", #cond,   \
				__FILE__, __LINE__);                           \
			abort();                                               \
		}                                                              \
	} while (0)

FORCEINLINE u64 load_le64(const u8 *p)
{
	u64 v;
	memcpy(&v, p, 8);
	return v;
}

FORCEINLINE void store_le64(u8 *p, u64 v) { memcpy(p, &v, 8); }

FORCEINLINE u32 load_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) |
	       (u32)p[3];
}

FORCEINLINE void store_be32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

FORCEINLINE void store_be64(u8 *p, u64 v)
{
	store_be32(p, (u32)(v >> 32));
	store_be32(p + 4, (u32)v);
}

static inline void xor_bytes(u8 *dst, const u8 *a, const u8 *b, size_t n)
{
	while (n >= 16) {
		vst1q_u8(dst, veorq_u8(vld1q_u8(a), vld1q_u8(b)));
		dst += 16;
		a += 16;
		b += 16;
		n -= 16;
	}
	while (n--)
		*dst++ = *a++ ^ *b++;
}

static inline u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;
}
