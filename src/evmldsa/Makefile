# evML-DSA reference implementation and benchmarks.
# MODE=2 (ML-DSA-44 leaf, default) or MODE=3 (ML-DSA-65 leaf).
# The release default construction is the SHARED matrix seed analyzed in
# the paper (EVMLDSA_LEGACY=1 in ev_params.h); build with
#   make CONSTRUCTION=0
# to switch to the experimental per-period rho_p variant.
PQREF = ../../third-party/dilithium/ref
MODE ?= 2
CONSTRUCTION ?= 1
CFLAGS += -O3 -Wall -Wextra -I$(PQREF) -DDILITHIUM_MODE=$(MODE) -DEVMLDSA_LEGACY=$(CONSTRUCTION)
CFLAGS65 = $(filter-out -DDILITHIUM_MODE=%,$(CFLAGS)) -DDILITHIUM_MODE=3
PQSRC = $(PQREF)/sign.c $(PQREF)/packing.c $(PQREF)/polyvec.c $(PQREF)/poly.c \
        $(PQREF)/ntt.c $(PQREF)/reduce.c $(PQREF)/rounding.c $(PQREF)/fips202.c \
        $(PQREF)/symmetric-shake.c $(PQREF)/randombytes.c
EVSRC = ev_sha3.c ev_seedtree.c ev_merkle.c evmldsa.c
BENCHLIBS = -lm

all: ev_selftest ev_test ev_c4_selftest ev_c4_selftest65 bench \
      bench_rechain bench_workload figdata_bench extended_bench breakdown_bench sizeof_check

ev_selftest: ev_selftest.c ev_sha3.c ev_seedtree.c ev_merkle.c
	$(CC) $(CFLAGS) -o $@ ev_selftest.c ev_sha3.c ev_seedtree.c ev_merkle.c

ev_test: ev_test.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ ev_test.c $(EVSRC) $(PQSRC)

ev_c4_selftest: ev_c4_selftest.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ ev_c4_selftest.c $(EVSRC) $(PQSRC)

ev_c4_selftest65: ev_c4_selftest.c $(EVSRC)
	$(CC) $(CFLAGS65) -o $@ ev_c4_selftest.c $(EVSRC) $(PQSRC)

bench: bench.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ bench.c $(EVSRC) $(PQSRC) $(BENCHLIBS)

bench65: bench.c $(EVSRC)
	$(CC) $(CFLAGS65) -o $@ bench.c $(EVSRC) $(PQSRC) $(BENCHLIBS)

bench_rechain: bench_rechain.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ bench_rechain.c $(EVSRC) $(PQSRC) $(BENCHLIBS)

bench_workload: bench_workload.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ bench_workload.c $(EVSRC) $(PQSRC) $(BENCHLIBS)

figdata_bench: figdata_bench.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ figdata_bench.c $(EVSRC) $(PQSRC) $(BENCHLIBS)

extended_bench: extended_bench.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ extended_bench.c $(EVSRC) $(PQSRC) $(BENCHLIBS)

breakdown_bench: breakdown_bench.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ breakdown_bench.c $(EVSRC) $(PQSRC) $(BENCHLIBS)

sizeof_check: sizeof_check.c $(EVSRC)
	$(CC) $(CFLAGS) -o $@ sizeof_check.c $(EVSRC) $(PQSRC)

check: all
	./ev_selftest
	./ev_test
	./ev_c4_selftest
	./ev_c4_selftest65

clean:
	rm -f ev_selftest ev_test ev_c4_selftest ev_c4_selftest65 bench bench65 \
	      bench_rechain bench_workload figdata_bench extended_bench \
	      breakdown_bench sizeof_check

.PHONY: all clean check
