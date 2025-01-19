#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "fips202.h"

typedef keccak_state xof_state;

#define XOF_BLOCKBYTES SHAKE128_RATE

#define KYBER_shake128_absorb KYBER_NAMESPACE(KYBER_shake128_absorb)
void KYBER_shake128_absorb(keccak_state *s, const uint8_t seed[KYBER_SYMBYTES], uint8_t x, uint8_t y);
#define KYBER_shake256_prf KYBER_NAMESPACE(KYBER_shake256_prf)
void KYBER_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);
#define KYBER_shake256_rkprf KYBER_NAMESPACE(KYBER_shake256_rkprf)
void KYBER_shake256_rkprf(uint8_t out[KYBER_SYMBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) KYBER_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) KYBER_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define kdf1(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)
#define kdf_kex(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define PREFIXLEN 33

#endif 



