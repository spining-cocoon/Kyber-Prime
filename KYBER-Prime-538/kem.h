#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "params.h"

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(unsigned char *ct, unsigned char *K, const unsigned char *pk);

#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(unsigned char *K, const unsigned char *ct, const unsigned char *sk);

#endif
