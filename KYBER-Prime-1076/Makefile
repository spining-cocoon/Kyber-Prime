CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kex.c kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
HEADERS = params.h kex.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h

.PHONY: all

all: \
  test/test_kyberprime_1076 \
  test/test_kex_1076 \
  test/test_speed_1076


test/test_kyberprime_1076: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c test/test_kyber.c -o test_kyberprime_1076

test/test_kex_1076: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kex.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c test/test_kex.c -o test_kex_1076

test/test_speed_1076: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_speed.c test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c randombytes.c poly_mul.h poly_mul.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c poly_mul.c test/cpucycles.c test/speed_print.c test/test_speed.c -o test_speed_1076


clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf test_kyberprime_1076
	-$(RM) -rf test_kex_1076
	-$(RM) -rf test_speed_1076
	