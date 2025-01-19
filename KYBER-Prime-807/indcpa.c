#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES], polyvec *pk, const uint8_t seed[KYBER_SYMBYTES]) {
    size_t i;

    polyvec_tobytes(r, pk);
    for(i=0;i<KYBER_SYMBYTES;i++)
          r[i+KYBER_POLYVECBYTES] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
**************************************************/
static void unpack_pk(polyvec *pk, uint8_t seed[KYBER_SYMBYTES], const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    size_t i;

    polyvec_frombytes(pk, packedpk);
    for(i=0;i<KYBER_SYMBYTES;i++)
      seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key as concatenation of the
*              serialized vector of polynomials sk
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    polyvec_eta_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize secret key from a byte array;
*              approximate inverse of pack_sk
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec_eta_frombytes(sk, packedsk);
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for KYBER-Prime.PKE.
**************************************************/
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[KYBER_K], e, t, s;
    polyvec_p a_star[KYBER_K], t_star, s_star;

    randombytes(buf, KYBER_SYMBYTES);
    hash_g(buf, buf, KYBER_SYMBYTES);

    gen_a(a, publicseed);
    polyvec_getnoise_eta1(&s, noiseseed, nonce++);
    polyvec_getnoise_eta1(&e, noiseseed, nonce++);

    polyvec_matrix_ntt(a_star, a);
    polyvec_ntt(&s_star, &s);

    polyvec_matrix_basemul(&t_star, a_star, &s_star);
    polyvec_invntt(&t, &t_star);

    polyvec_add(&t, &t, &e);
    polyvec_reduce(&t);

    pack_sk(sk, &s);
    pack_pk(pk, &t, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of KYBER-Prime.PKE.
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_CTBYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]) {

    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec r, t, e1, at[KYBER_K], u;
    poly v, e2;
    polyvec_p r_star, t_star, at_star[KYBER_K], u_star;
    poly_p v_star;

    unpack_pk(&t, seed, pk);

    gen_at(at, seed);
    polyvec_getnoise_eta1(&r, coins, nonce++);
    polyvec_getnoise_eta2(&e1, coins, nonce++);
    poly_getnoise_eta2(&e2, coins, nonce++);

    polyvec_matrix_ntt(at_star, at);
    polyvec_ntt(&t_star, &t);
    polyvec_ntt(&r_star, &r);

    polyvec_matrix_basemul(&u_star, at_star, &r_star);
    polyvec_basemul(&v_star, &t_star, &r_star);

    polyvec_invntt(&u, &u_star);
    poly_invntt(&v, &v_star);

    polyvec_add(&u, &u, &e1);
    poly_add(&v, &v, &e2);

    polyvec_reduce(&u);
    polyvec_compress(c, &u);
    poly_con(c + KYBER_POLYVECCOMPRESSEDBYTES_CU, &v, m);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of KYBER-Prime.PKE.
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_CTBYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec u, s;
    polyvec_p u_star, s_star;
    poly mp;
    poly_p mp_star;

    polyvec_decompress(&u, c);
    unpack_sk(&s, sk);

    polyvec_ntt(&s_star, &s);
    polyvec_ntt(&u_star, &u);

    polyvec_basemul(&mp_star, &s_star, &u_star);
    poly_invntt(&mp, &mp_star);

    poly_rec(m, c + KYBER_POLYVECCOMPRESSEDBYTES_CU, &mp);
}