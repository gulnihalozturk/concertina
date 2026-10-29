#include "keccak.h"

static const u64 RC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#include "keccak_round.inc"

#define DECLARE_LANES(T_)                                                      \
	T_ A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14,    \
		A15, A16, A17, A18, A19, A20, A21, A22, A23, A24;              \
	T_ C0, C1, C2, C3, C4, D0, D1, D2, D3, D4, T, BC

#define LANE_LIST(M)                                                           \
	M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9) M(10) M(11) M(12)    \
	M(13) M(14) M(15) M(16) M(17) M(18) M(19) M(20) M(21) M(22) M(23) M(24)
#define RATE_LIST(M)                                                           \
	M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9) M(10) M(11) M(12)    \
	M(13) M(14) M(15) M(16)

/* ---------------- portable backend ---------------- */

#define S_LOAD(i) A##i = st[i];
#define S_STORE(i) st[i] = A##i;
#define S_XOR_IN(i) A##i ^= load_le64(in + 8 * i);

static void absorb_scalar(u64 st[25], const u8 *in, size_t nblocks, int permute_only)
{
	DECLARE_LANES(u64);
	int r;

	LANE_LIST(S_LOAD)
	do {
		if (!permute_only) {
			RATE_LIST(S_XOR_IN)
			in += SHA3_256_RATE;
		}
		for (r = 0; r < 24; r++)
			KECCAK_ROUND_SCALAR(RC[r]);
	} while (--nblocks);
	LANE_LIST(S_STORE)
}

/* ---------------- ARMv8.2-SHA3 backend ---------------- */

#if defined(__ARM_FEATURE_SHA3)
const int keccak_have_ce = 1;

#define V_LOAD(i) A##i = vdupq_n_u64(st[i]);
#define V_STORE(i) st[i] = vgetq_lane_u64(A##i, 0);
#define V_XOR_IN(i) A##i = veorq_u64(A##i, vdupq_n_u64(load_le64(in + 8 * i)));

static void absorb_ce(u64 st[25], const u8 *in, size_t nblocks, int permute_only)
{
	DECLARE_LANES(uint64x2_t);
	int r;

	LANE_LIST(V_LOAD)
	do {
		if (!permute_only) {
			RATE_LIST(V_XOR_IN)
			in += SHA3_256_RATE;
		}
		for (r = 0; r < 24; r++)
			KECCAK_ROUND_CE(RC[r]);
	} while (--nblocks);
	LANE_LIST(V_STORE)
}
#else
const int keccak_have_ce = 0;
#define absorb_ce absorb_scalar
#endif

static void absorb(u64 st[25], const u8 *in, size_t nblocks, int portable)
{
	if (!nblocks)
		return;
	if (portable)
		absorb_scalar(st, in, nblocks, 0);
	else
		absorb_ce(st, in, nblocks, 0);
}

void keccak_permute(u64 st[25], int portable)
{
	if (portable)
		absorb_scalar(st, NULL, 1, 1);
	else
		absorb_ce(st, NULL, 1, 1);
}

static void squeeze32(const u64 st[25], u8 out[32])
{
	int i;

	for (i = 0; i < 4; i++)
		store_le64(out + 8 * i, st[i]);
}

/* Absorbs the final (partial) block with the SHA-3 padding 0x06 ... 0x80. */
static void absorb_final(u64 st[25], const u8 *p, size_t len, int portable)
{
	u8 last[SHA3_256_RATE] = {0};

	memcpy(last, p, len);
	last[len] ^= 0x06;
	last[SHA3_256_RATE - 1] ^= 0x80;
	absorb(st, last, 1, portable);
}

void sha3_256(const u8 *msg, size_t len, u8 out[32], int portable)
{
	u64 st[25] = {0};
	const size_t nfull = len / SHA3_256_RATE;

	absorb(st, msg, nfull, portable);
	absorb_final(st, msg + nfull * SHA3_256_RATE, len - nfull * SHA3_256_RATE,
		     portable);
	squeeze32(st, out);
}

void hmac_sha3_256_setkey(hmac_sha3_256_key *k, const u8 *key, size_t key_len,
			  int portable)
{
	u8 kb[SHA3_256_RATE] = {0}, pad[SHA3_256_RATE];
	int i;

	if (key_len > SHA3_256_RATE) {
		sha3_256(key, key_len, kb, portable);
	} else {
		memcpy(kb, key, key_len);
	}
	k->portable = portable;
	memset(k->inner, 0, sizeof(k->inner));
	memset(k->outer, 0, sizeof(k->outer));
	for (i = 0; i < SHA3_256_RATE; i++)
		pad[i] = kb[i] ^ 0x36;
	absorb(k->inner, pad, 1, portable);
	for (i = 0; i < SHA3_256_RATE; i++)
		pad[i] = kb[i] ^ 0x5c;
	absorb(k->outer, pad, 1, portable);
	memset(kb, 0, sizeof(kb));
	memset(pad, 0, sizeof(pad));
}

void hmac_sha3_256(const hmac_sha3_256_key *k, const u8 *a, size_t a_len,
		   const u8 *b, size_t b_len, u8 out[32])
{
	u64 st[25];
	u8 buf[2 * SHA3_256_RATE], ih[32];
	const size_t nfull = a_len / SHA3_256_RATE;
	const size_t rem = a_len - nfull * SHA3_256_RATE;
	size_t n;
	const u8 *p = buf;

	CHECK(b_len <= 64);
	memcpy(st, k->inner, sizeof(st));
	absorb(st, a, nfull, k->portable);
	memcpy(buf, a + nfull * SHA3_256_RATE, rem);
	if (b_len)
		memcpy(buf + rem, b, b_len);
	n = rem + b_len;
	if (n >= SHA3_256_RATE) {
		absorb(st, buf, 1, k->portable);
		p += SHA3_256_RATE;
		n -= SHA3_256_RATE;
	}
	absorb_final(st, p, n, k->portable);
	squeeze32(st, ih);

	memcpy(st, k->outer, sizeof(st));
	absorb_final(st, ih, 32, k->portable);
	squeeze32(st, out);
}
