#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key for KYBER-Prime.
**************************************************/
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
    indcpa_keypair(pk, sk);
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    randombytes(sk + KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES, KYBER_SYMBYTES);
    return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates ciphertext and shared
*              secret for given public key
**************************************************/
int crypto_kem_enc(unsigned char *ct, unsigned char *K, const unsigned char *pk)
{
    uint8_t buf[PREFIXLEN + KYBER_SYMBYTES];
    uint8_t kr[2*KYBER_SYMBYTES];

    randombytes(buf + PREFIXLEN, KYBER_SYMBYTES);
    memcpy(buf, pk, PREFIXLEN);

    kdf(kr, buf, PREFIXLEN + KYBER_SYMBYTES);
    indcpa_enc(ct, buf + PREFIXLEN, pk, kr + KYBER_SYMBYTES);

    memcpy(K, kr, KYBER_SYMBYTES);
    return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
**************************************************/
int crypto_kem_dec(unsigned char *K, const unsigned char *ct, const unsigned char *sk)
{
    int fail;
    uint8_t buf[PREFIXLEN + KYBER_SYMBYTES];
    uint8_t kr[2*KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    uint8_t buf2[PREFIXLEN + KYBER_SYMBYTES+KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf + PREFIXLEN, ct, sk); 
    memcpy(buf, pk, PREFIXLEN);

    kdf(kr, buf, PREFIXLEN + KYBER_SYMBYTES);
    indcpa_enc(cmp, buf+PREFIXLEN, pk, kr + KYBER_SYMBYTES); 
    fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    memcpy(buf2, pk, PREFIXLEN);
    memcpy(buf2 + PREFIXLEN, sk + KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES, KYBER_SYMBYTES);
    memcpy(buf2 + PREFIXLEN + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

    kdf1(K, buf2, PREFIXLEN + KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES);

    cmov(K,kr,KYBER_SYMBYTES,!fail);

    return 0;
}