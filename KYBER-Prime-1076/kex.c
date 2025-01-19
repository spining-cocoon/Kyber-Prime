#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "kex.h"
#include "kem.h"
#include "symmetric.h"

void kex_uake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb)
{
  crypto_kem_keypair(send, sk);
  crypto_kem_enc(send + KYBER_PUBLICKEYBYTES, tk, pkb);
}

void kex_uake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *skb)
{
  uint8_t buf[2*KYBER_SSBYTES];
  crypto_kem_enc(send, buf, recv);
  crypto_kem_dec(buf + KYBER_SSBYTES, recv + KYBER_PUBLICKEYBYTES, skb);
  kdf_kex(k, buf, 2*KYBER_SSBYTES);
}

void kex_uake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk)
{
  unsigned int i;
  uint8_t buf[2*KYBER_SSBYTES];
  crypto_kem_dec(buf, recv, sk);
  for(i=0;i<KYBER_SSBYTES;i++)
    buf[i+KYBER_SSBYTES] = tk[i];
  
  kdf_kex(k, buf, 2*KYBER_SSBYTES);
}

void kex_ake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb)
{
  crypto_kem_keypair(send, sk);
  crypto_kem_enc(send + KYBER_PUBLICKEYBYTES, tk, pkb);
}

void kex_ake_sharedB(uint8_t *send, uint8_t *k, const uint8_t* recv, const uint8_t *skb, const uint8_t *pka)
{
  uint8_t buf[3*KYBER_SSBYTES];
  crypto_kem_enc(send, buf, recv);
  crypto_kem_enc(send + KYBER_CIPHERTEXTBYTES, buf+KYBER_SSBYTES, pka);
  crypto_kem_dec(buf+2*KYBER_SSBYTES, recv + KYBER_PUBLICKEYBYTES, skb);
  kdf_kex(k, buf, 3*KYBER_SSBYTES);
}

void kex_ake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk, const uint8_t *ska)
{
  unsigned int i;
  uint8_t buf[3*KYBER_SSBYTES];
  crypto_kem_dec(buf, recv, sk);
  crypto_kem_dec(buf + KYBER_SSBYTES, recv + KYBER_CIPHERTEXTBYTES, ska);
  for(i=0;i<KYBER_SSBYTES;i++)
    buf[i+2*KYBER_SSBYTES] = tk[i];
  kdf_kex(k, buf, 3*KYBER_SSBYTES);
}
