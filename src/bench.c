/*
 * concertina-bench: compares Concertina with HCTR2
 * (and AES-XTS as a narrow-block reference) on AArch64, and writes the
 * results as CSV and as LaTeX tables for the paper.
 *
 * Usage: ./concertina-bench [--sizes=32,64,256,512,1024,4096] [--ntries=15]
 *                  [--target-bytes=2097152] [--keybits=128|256]
 *                  [--freq-ghz=X] [--outdir=results] [--no-portable]
 */
#include "common.h"
#include "hctr2.h"
#include "scheme.h"
#include "selftest.h"
#include "xts.h"

#include <errno.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <pthread.h>
#include <sys/sysctl.h>
#endif

#define MAX_SIZES 16
#define MAX_LEN (1u << 20)

/* ------------------------------------------------------------------ */
/* Algorithms under test                                               */
/* ------------------------------------------------------------------ */

typedef void (*setkey_fn)(void *ctx, const u8 *key, size_t key_len);
typedef void (*crypt_fn)(const void *ctx, u8 *dst, const u8 *src, size_t len,
			 const u8 *tweak);

struct alg {
	const char *id, *label, *latex;
	int group;          /* 0: with hash instructions, 1: portable hash */
	int key_factor;     /* 2 for XTS (two AES keys) */
	size_t min_len;     /* minimum message length */
	size_t len_multiple;/* required length granularity */
	size_t ctx_size;
	setkey_fn setkey;
	crypt_fn enc, dec;
};

static void xts_sk(void *c, const u8 *k, size_t l) { xts_setkey(c, k, l); }
static void xts_e(const void *c, u8 *d, const u8 *s, size_t l, const u8 *t) { xts_crypt(c, d, s, l, t, 1); }
static void xts_d(const void *c, u8 *d, const u8 *s, size_t l, const u8 *t) { xts_crypt(c, d, s, l, t, 0); }

static void h2_sk(void *c, const u8 *k, size_t l) { hctr2_setkey(c, k, l, 0); }
static void h2p_sk(void *c, const u8 *k, size_t l) { hctr2_setkey(c, k, l, 1); }
static void h2_e(const void *c, u8 *d, const u8 *s, size_t l, const u8 *t) { hctr2_crypt(c, d, s, l, t, 16, 1); }
static void h2_d(const void *c, u8 *d, const u8 *s, size_t l, const u8 *t) { hctr2_crypt(c, d, s, l, t, 16, 0); }

static void s3_sk(void *c, const u8 *k, size_t l) { scheme_setkey(c, k, l, SCHEME_HMAC_SHA3_256, 0); }
static void s3p_sk(void *c, const u8 *k, size_t l) { scheme_setkey(c, k, l, SCHEME_HMAC_SHA3_256, 1); }
static void s2_sk(void *c, const u8 *k, size_t l) { scheme_setkey(c, k, l, SCHEME_HMAC_SHA256, 0); }
static void s2p_sk(void *c, const u8 *k, size_t l) { scheme_setkey(c, k, l, SCHEME_HMAC_SHA256, 1); }
static void sc_e(const void *c, u8 *d, const u8 *s, size_t l, const u8 *t) { scheme_encrypt(c, d, s, l, t); }
static void sc_d(const void *c, u8 *d, const u8 *s, size_t l, const u8 *t) { scheme_decrypt(c, d, s, l, t); }

static const struct alg algs[] = {
	{"xts", "AES-XTS", "AES-XTS\\textsuperscript{$\\dagger$}", 0, 2, 16, 16,
	 sizeof(xts_ctx), xts_sk, xts_e, xts_d},
	{"hctr2", "HCTR2", "HCTR2", 0, 1, 16, 1, sizeof(hctr2_ctx), h2_sk, h2_e, h2_d},
	{"scheme-sha3", SCHEME_DISPLAY_NAME " (HMAC-SHA3-256)", "\\Scheme{} (HMAC-SHA3-256)", 0, 1,
	 SCHEME_MIN_LEN, 1, sizeof(scheme_ctx), s3_sk, sc_e, sc_d},
	{"scheme-sha256", SCHEME_DISPLAY_NAME " (HMAC-SHA-256)", "\\Scheme{} (HMAC-SHA-256)", 0, 1,
	 SCHEME_MIN_LEN, 1, sizeof(scheme_ctx), s2_sk, sc_e, sc_d},
	{"hctr2-portable", "HCTR2 (portable POLYVAL)", "HCTR2, portable POLYVAL", 1, 1, 16, 1,
	 sizeof(hctr2_ctx), h2p_sk, h2_e, h2_d},
	{"scheme-sha3-portable", SCHEME_DISPLAY_NAME " (portable Keccak)",
	 "\\Scheme{}, portable Keccak", 1, 1, SCHEME_MIN_LEN, 1, sizeof(scheme_ctx), s3p_sk,
	 sc_e, sc_d},
	{"scheme-sha256-portable", SCHEME_DISPLAY_NAME " (portable SHA-256)",
	 "\\Scheme{}, portable SHA-256", 1, 1, SCHEME_MIN_LEN, 1, sizeof(scheme_ctx), s2p_sk,
	 sc_e, sc_d},
};
#define NALGS ((int)(sizeof(algs) / sizeof(algs[0])))

/* ------------------------------------------------------------------ */
/* Parameters and results                                              */
/* ------------------------------------------------------------------ */

static struct {
	size_t sizes[MAX_SIZES];
	int nsizes;
	int ntries;
	size_t target_bytes;
	int keybits;
	double freq_ghz;
	int freq_given;
	const char *outdir;
	int portable;
	int selftest_only;
} P = {{32, 64, 256, 512, 1024, 4096}, 6, 15, 2u << 20, 128, 0, 0, "results", 1, 0};

/* ns per message; negative = not applicable */
static double res[NALGS][MAX_SIZES][2];
static double setkey_ns[NALGS];

static double cpb(double ns, size_t len) { return ns * P.freq_ghz / (double)len; }

/* ------------------------------------------------------------------ */
/* Platform helpers                                                    */
/* ------------------------------------------------------------------ */

static void prefer_performance_core(void)
{
#ifdef __APPLE__
	/* macOS does not allow pinning; the highest QoS class makes the
	 * scheduler place the thread on a performance core. */
	pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
}

static void cpu_name(char *buf, size_t n)
{
	snprintf(buf, n, "unknown AArch64 CPU");
#ifdef __APPLE__
	{
		size_t len = n;

		if (sysctlbyname("machdep.cpu.brand_string", buf, &len, NULL, 0) != 0)
			snprintf(buf, n, "unknown Apple CPU");
	}
#else
	{
		FILE *f = fopen("/proc/device-tree/model", "r");

		if (f) {
			if (!fgets(buf, (int)n, f))
				snprintf(buf, n, "unknown AArch64 CPU");
			fclose(f);
		}
	}
#endif
}

/* Estimates the core clock from a chain of dependent 1-cycle additions. */
static double estimate_freq_ghz(void)
{
	double best = 0;
	int run;

	for (run = 0; run < 5; run++) {
		u64 n = 5000000, a = 0, t0, t1;

		t0 = now_ns();
		__asm__ volatile("1:\n\t"
				 ".rept 64\n\t"
				 "add %[a], %[a], #1\n\t"
				 ".endr\n\t"
				 "subs %[n], %[n], #1\n\t"
				 "b.ne 1b\n\t"
				 : [a] "+r"(a), [n] "+r"(n)
				 :
				 : "cc");
		t1 = now_ns();
		if (t1 > t0) {
			double ghz = 64.0 * 5000000.0 / (double)(t1 - t0);

			if (ghz > best)
				best = ghz;
		}
	}
	return best;
}

static void warm_up(void)
{
	u64 t0 = now_ns();
	volatile u64 x = 0;

	while (now_ns() - t0 < 300000000ull) /* 0.3 s */
		x++;
}

static void fill_random(u8 *p, size_t n)
{
	while (n--)
		*p++ = (u8)rand();
}

/* ------------------------------------------------------------------ */
/* Measurement                                                         */
/* ------------------------------------------------------------------ */

static double time_crypt(crypt_fn fn, const void *ctx, u8 *dst, const u8 *src,
			 size_t len, const u8 *tweak)
{
	const size_t iters = P.target_bytes / len ? P.target_bytes / len : 1;
	double best = 1e300;
	size_t i;
	int t;

	for (i = 0; i < iters / 8 + 1; i++) /* warm caches and branch predictors */
		fn(ctx, dst, src, len, tweak);
	for (t = 0; t < P.ntries; t++) {
		u64 t0 = now_ns(), t1;

		for (i = 0; i < iters; i++)
			fn(ctx, dst, src, len, tweak);
		t1 = now_ns();
		if ((double)(t1 - t0) / (double)iters < best)
			best = (double)(t1 - t0) / (double)iters;
	}
	return best;
}

static double time_setkey(const struct alg *a, void *ctx, const u8 *key, size_t klen)
{
	double best = 1e300;
	int t, i;
	const int iters = 2000;

	for (t = 0; t < P.ntries; t++) {
		u64 t0 = now_ns(), t1;

		for (i = 0; i < iters; i++)
			a->setkey(ctx, key, klen);
		t1 = now_ns();
		if ((double)(t1 - t0) / iters < best)
			best = (double)(t1 - t0) / iters;
	}
	return best;
}

static void run_benchmarks(void)
{
	u8 *pt = malloc(MAX_LEN), *ct = malloc(MAX_LEN), *back = malloc(MAX_LEN);
	u8 key[64], tweak[16];
	const size_t klen = (size_t)P.keybits / 8;
	int ai, si;

	CHECK(pt && ct && back);
	fill_random(pt, MAX_LEN);
	fill_random(key, sizeof(key));
	fill_random(tweak, sizeof(tweak));

	for (ai = 0; ai < NALGS; ai++) {
		const struct alg *a = &algs[ai];
		void *ctx = aligned_alloc(64, (a->ctx_size + 63) / 64 * 64);

		CHECK(ctx);
		for (si = 0; si < P.nsizes; si++)
			res[ai][si][0] = res[ai][si][1] = -1;
		setkey_ns[ai] = -1;
		if (a->group == 1 && !P.portable) {
			free(ctx);
			continue;
		}
		setkey_ns[ai] = time_setkey(a, ctx, key, klen * a->key_factor);
		a->setkey(ctx, key, klen * a->key_factor);
		printf("  %-34s", a->label);
		fflush(stdout);
		for (si = 0; si < P.nsizes; si++) {
			const size_t len = P.sizes[si];

			if (len < a->min_len || len % a->len_multiple) {
				printf("      -");
				continue;
			}
			res[ai][si][0] = time_crypt(a->enc, ctx, ct, pt, len, tweak);
			res[ai][si][1] = time_crypt(a->dec, ctx, back, ct, len, tweak);
			CHECK(!memcmp(back, pt, len)); /* round trip */
			CHECK(memcmp(ct, pt, len));
			printf(" %6.2f", cpb(res[ai][si][0], len));
			fflush(stdout);
		}
		printf("   (enc, cpb)\n");
		free(ctx);
	}
	free(pt);
	free(ct);
	free(back);
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static void print_console_table(void)
{
	int ai, si, op;

	printf("\nCycles per byte (AES-%d, %.3f GHz):\n%-36s %-4s", P.keybits, P.freq_ghz,
	       "Mode", "Dir");
	for (si = 0; si < P.nsizes; si++)
		printf(" %8zu", P.sizes[si]);
	printf("\n");
	for (ai = 0; ai < NALGS; ai++) {
		if (setkey_ns[ai] < 0)
			continue;
		for (op = 0; op < 2; op++) {
			printf("%-36s %-4s", op ? "" : algs[ai].label, op ? "Dec" : "Enc");
			for (si = 0; si < P.nsizes; si++) {
				if (res[ai][si][op] < 0)
					printf(" %8s", "-");
				else
					printf(" %8.2f", cpb(res[ai][si][op], P.sizes[si]));
			}
			printf("\n");
		}
	}
	printf("\nSlowdown relative to HCTR2 (encryption):\n%-36s    ", "");
	for (si = 0; si < P.nsizes; si++)
		printf(" %8zu", P.sizes[si]);
	printf("\n");
	for (ai = 0; ai < NALGS; ai++) {
		if (strncmp(algs[ai].id, "scheme", 6) || setkey_ns[ai] < 0)
			continue;
		printf("%-36s    ", algs[ai].label);
		for (si = 0; si < P.nsizes; si++) {
			const double h = res[1][si][0], s = res[ai][si][0];

			if (h > 0 && s > 0)
				printf(" %7.2fx", s / h);
			else
				printf(" %8s", "-");
		}
		printf("\n");
	}
	printf("\nKey setup:\n");
	for (ai = 0; ai < NALGS; ai++)
		if (setkey_ns[ai] >= 0)
			printf("  %-34s %9.3f us  %10.0f cycles\n", algs[ai].label,
			       setkey_ns[ai] / 1000.0, setkey_ns[ai] * P.freq_ghz);
}

static FILE *open_out(const char *name)
{
	char path[1024];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", P.outdir, name);
	f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "Cannot write %s: %s\n", path, strerror(errno));
		exit(1);
	}
	printf("Wrote %s\n", path);
	return f;
}

static void write_csv(const char *cpu)
{
	FILE *f = open_out("results.csv");
	int ai, si, op;

	fprintf(f, "# cpu=%s, freq_ghz=%.4f, keybits=%d, ntries=%d, target_bytes=%zu\n", cpu,
		P.freq_ghz, P.keybits, P.ntries, P.target_bytes);
	fprintf(f, "mode,direction,message_bytes,ns_per_message,cycles_per_byte,MB_per_s\n");
	for (ai = 0; ai < NALGS; ai++)
		for (si = 0; si < P.nsizes; si++)
			for (op = 0; op < 2; op++) {
				const double ns = res[ai][si][op];

				if (ns < 0)
					continue;
				fprintf(f, "%s,%s,%zu,%.2f,%.3f,%.1f\n", algs[ai].id,
					op ? "dec" : "enc", P.sizes[si], ns, cpb(ns, P.sizes[si]),
					(double)P.sizes[si] / ns * 1000.0);
			}
	for (ai = 0; ai < NALGS; ai++)
		if (setkey_ns[ai] >= 0)
			fprintf(f, "%s,setkey,0,%.2f,,\n", algs[ai].id, setkey_ns[ai]);
	fclose(f);
}

static void latex_rows(FILE *f, int group)
{
	int ai, si, op, first = 1;

	for (ai = 0; ai < NALGS; ai++) {
		if (algs[ai].group != group || setkey_ns[ai] < 0)
			continue;
		if (!first)
			fprintf(f, "\\addlinespace\n");
		first = 0;
		for (op = 0; op < 2; op++) {
			fprintf(f, "%s & %s", op ? "" : algs[ai].latex, op ? "Dec" : "Enc");
			for (si = 0; si < P.nsizes; si++) {
				if (res[ai][si][op] < 0) {
					fprintf(f, " & --");
				} else {
					const double v = cpb(res[ai][si][op], P.sizes[si]);

					fprintf(f, v < 10 ? " & %.2f" : v < 100 ? " & %.1f" : " & %.0f", v);
				}
			}
			fprintf(f, " \\\\\n");
		}
	}
}

static void write_latex(const char *cpu, int freq_measured)
{
	FILE *f = open_out("table.tex");
	int si, ai;
	time_t now = time(NULL);
	char date[32];

	strftime(date, sizeof(date), "%Y-%m-%d %H:%M", localtime(&now));
	fprintf(f, "%% Generated by concertina-bench on %s\n%% CPU: %s, %.3f GHz (%s), AES-%d, "
		   "best of %d runs, compiler: %s\n",
		date, cpu, P.freq_ghz, freq_measured ? "measured" : "given", P.keybits,
		P.ntries, __VERSION__);
	fprintf(f, "%% Requires \\usepackage{booktabs}.\n");
	fprintf(f, "\\providecommand{\\Scheme}{Concertina}\n\n");

	fprintf(f, "\\begin{table}[t]\n\\centering\n");
	fprintf(f, "\\caption{Software performance on %s (one performance core) with "
		   "AES-%d, in cycles per byte. Cycle counts are derived from wall-clock "
		   "time at a core frequency of %.2f~GHz. All modes use the same "
		   "AES implementation based on the ARMv8 Cryptographic Extension.}\n",
		cpu, P.keybits, P.freq_ghz);
	fprintf(f, "\\label{tab:performance}\n\\small\n\\setlength{\\tabcolsep}{3.5pt}\n");
	fprintf(f, "\\begin{tabular}{ll");
	for (si = 0; si < P.nsizes; si++)
		fprintf(f, "r");
	fprintf(f, "}\n\\toprule\n & & \\multicolumn{%d}{c}{Message length (bytes)} \\\\\n",
		P.nsizes);
	fprintf(f, "\\cmidrule(l){3-%d}\nMode & Dir.", P.nsizes + 2);
	for (si = 0; si < P.nsizes; si++)
		fprintf(f, " & %zu", P.sizes[si]);
	fprintf(f, " \\\\\n\\midrule\n");
	latex_rows(f, 0);
	if (P.portable) {
		fprintf(f, "\\midrule\n\\multicolumn{%d}{l}{\\emph{Without hash instructions "
			   "(PMULL, SHA-2 and SHA-3 not used)}} \\\\\n",
			P.nsizes + 2);
		latex_rows(f, 1);
	}
	fprintf(f, "\\bottomrule\n\\multicolumn{%d}{l}{\\footnotesize $^\\dagger$Narrow-block "
		   "mode, listed as a reference only.}\n",
		P.nsizes + 2);
	fprintf(f, "\\end{tabular}\n\\end{table}\n\n");

	fprintf(f, "\\begin{table}[t]\n\\centering\n");
	fprintf(f, "\\caption{Key setup cost on %s with AES-%d. For \\Scheme{}, key setup "
		   "includes the derivation of the six working keys (SP~800-108), the "
		   "expansion of five AES keys and the HMAC key preprocessing.}\n",
		cpu, P.keybits);
	fprintf(f, "\\label{tab:keysetup}\n\\begin{tabular}{lrr}\n\\toprule\n"
		   "Mode & Time ($\\mu$s) & Cycles \\\\\n\\midrule\n");
	for (ai = 0; ai < NALGS; ai++)
		if (setkey_ns[ai] >= 0)
			fprintf(f, "%s & %.3f & %.0f \\\\\n", algs[ai].latex,
				setkey_ns[ai] / 1000.0, setkey_ns[ai] * P.freq_ghz);
	fprintf(f, "\\bottomrule\n\\end{tabular}\n\\end{table}\n");
	fclose(f);
}

/* ------------------------------------------------------------------ */

static void usage(void)
{
	fprintf(stderr,
		"Usage: concertina-bench [--sizes=32,64,256,512,1024,4096] [--ntries=15]\n"
		"               [--target-bytes=2097152] [--keybits=128|256]\n"
		"               [--freq-ghz=X] [--outdir=results] [--no-portable]\n"
		"               [--selftest]\n");
	exit(1);
}

static void parse_args(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strncmp(a, "--sizes=", 8)) {
			char *s = (char *)a + 8, *end;

			P.nsizes = 0;
			while (*s && P.nsizes < MAX_SIZES) {
				unsigned long v = strtoul(s, &end, 10);

				if (end == s || v == 0 || v > MAX_LEN)
					usage();
				P.sizes[P.nsizes++] = v;
				s = (*end == ',') ? end + 1 : end;
			}
		} else if (!strncmp(a, "--ntries=", 9)) {
			P.ntries = atoi(a + 9);
		} else if (!strncmp(a, "--target-bytes=", 15)) {
			P.target_bytes = strtoul(a + 15, NULL, 10);
		} else if (!strncmp(a, "--keybits=", 10)) {
			P.keybits = atoi(a + 10);
		} else if (!strncmp(a, "--freq-ghz=", 11)) {
			P.freq_ghz = atof(a + 11);
			P.freq_given = 1;
		} else if (!strncmp(a, "--outdir=", 9)) {
			P.outdir = a + 9;
		} else if (!strcmp(a, "--no-portable")) {
			P.portable = 0;
		} else if (!strcmp(a, "--selftest")) {
			P.selftest_only = 1;
		} else {
			usage();
		}
	}
	if (P.ntries < 1 || P.nsizes < 1 || (P.keybits != 128 && P.keybits != 256) ||
	    P.target_bytes < 4096)
		usage();
}

int main(int argc, char **argv)
{
	char cpu[128];

	parse_args(argc, argv);
	prefer_performance_core();
	srand(12345);
	cpu_name(cpu, sizeof(cpu));
	cpu[strcspn(cpu, "\n")] = 0;

	printf("concertina-bench: " SCHEME_DISPLAY_NAME " vs. HCTR2\n");
	printf("CPU: %s | SHA-3 instructions: %s | SHA-2 instructions: %s\n", cpu,
	       keccak_have_ce ? "yes" : "no", sha256_have_ce ? "yes" : "no");
	printf("Compiler: %s\n", __VERSION__);
	if (run_selftests(1)) {
		fprintf(stderr, "Self-tests failed; no benchmark is run.\n");
		return 1;
	}
	if (P.selftest_only)
		return 0;
	warm_up();
	if (!P.freq_given)
		P.freq_ghz = estimate_freq_ghz();
	printf("Core frequency: %.3f GHz (%s)\n", P.freq_ghz,
	       P.freq_given ? "given" : "measured with a dependent-add chain");
	printf("Parameters: AES-%d, best of %d runs, %zu bytes per run\n\n", P.keybits,
	       P.ntries, P.target_bytes);
	printf("  %-34s", "Encryption (cycles/byte), sizes:");
	for (int si = 0; si < P.nsizes; si++)
		printf(" %6zu", P.sizes[si]);
	printf("\n");

	run_benchmarks();
	if (!P.freq_given) {
		const double after = estimate_freq_ghz();

		printf("Core frequency after the benchmark: %.3f GHz\n", after);
		if (after < 0.97 * P.freq_ghz || after > 1.03 * P.freq_ghz)
			printf("WARNING: the core frequency changed by more than 3%% during the "
			       "run (thermal throttling?). Let the machine cool down and re-run, "
			       "or fix the frequency with --freq-ghz.\n");
	}
	print_console_table();
	mkdir(P.outdir, 0755);
	printf("\n");
	write_csv(cpu);
	write_latex(cpu, !P.freq_given);
	return 0;
}
