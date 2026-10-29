# concertina-bench: Concertina vs. HCTR2 on AArch64 (Apple M-series or AArch64 Linux).
#
#   make            build ./concertina-bench
#   make test       build and run the self-tests only
#   make bench      build, run the benchmark, write results/results.csv and
#                   results/table.tex
#   make kat        regenerate src/kat_generated.h (needs Python 3 + cryptography)

CC ?= cc
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
# Apple M1 and later: AES, PMULL, SHA-2 and SHA-3 instructions.
ARCHFLAGS ?= -mcpu=apple-m1
else
ARCHFLAGS ?= -march=armv8.2-a+crypto+sha3
endif
OPT ?= -O3
CFLAGS += -std=gnu11 $(OPT) $(ARCHFLAGS) -Wall -Wextra -Wno-pointer-sign \
          -Wno-missing-field-initializers -Isrc -Isrc/testvecs

SRCS = src/aes.c src/polyval.c src/hctr2.c src/keccak.c src/sha256.c \
       src/scheme.c src/xts.c src/selftest.c src/bench.c \
       src/testvecs/hctr2_testvecs.c src/testvecs/polyval_testvecs.c \
       src/testvecs/xctr_testvecs.c
HDRS = $(wildcard src/*.h) src/keccak_round.inc src/kat_generated.h

concertina-bench: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

gen:
	python3 tools/gen_keccak_round.py

test: concertina-bench
	./concertina-bench --selftest

bench: concertina-bench
	./concertina-bench $(BENCHARGS)

kat:
	python3 python/scheme_ref.py

attacks:
	python3 attacks/distinguishers.py

clean:
	rm -f concertina-bench

.PHONY: test bench kat gen attacks clean
