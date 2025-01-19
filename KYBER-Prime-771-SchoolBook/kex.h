#ifndef KEX_H
#define KEX_H

#include <stdint.h>
#include "params.h"

#define KEX_UAKE_SENDABYTES (KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES)
#define KEX_UAKE_SENDBBYTES (KYBER_CIPHERTEXTBYTES)

#define KEX_AKE_SENDABYTES (KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES)
#define KEX_AKE_SENDBBYTES (2*KYBER_CIPHERTEXTBYTES)

#define KEX_SSBYTES KYBER_SSBYTES

#define kex_uake_initA KYBER_NAMESPACE(kex_uake_initA)
void kex_uake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb);
#define kex_uake_sharedB KYBER_NAMESPACE(kex_uake_sharedB)
void kex_uake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *skb);
#define kex_uake_sharedA KYBER_NAMESPACE(kex_uake_sharedA)
void kex_uake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk);

#define kex_ake_initA KYBER_NAMESPACE(kex_ake_initA)
void kex_ake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb);
#define kex_ake_sharedB KYBER_NAMESPACE(kex_ake_sharedB)
void kex_ake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *skb, const uint8_t *pka);
#define kex_ake_sharedA KYBER_NAMESPACE(kex_ake_sharedA)
void kex_ake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk, const uint8_t *ska);

#endif
