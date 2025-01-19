#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "symmetric.h"

typedef struct{
  poly vec[KYBER_K];
} polyvec;

typedef struct{
  poly_p vec[KYBER_K];
} polyvec_p;

#define gen_a(A, B)  gen_matrix(A,B,0)
#define gen_at(A, B) gen_matrix(A,B,1)

#define GEN_MATRIX_NBLOCKS ((16*KYBER_N*(1 << 13)/(8*q) + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

/**************************************************************/
/************ Matrix of polynomials **************/
/**************************************************************/
#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec a[KYBER_K], const uint8_t seed[KYBER_SYMBYTES], int transposed);

#define polyvec_matrix_ntt KYBER_NAMESPACE(polyvec_matrix_ntt)
void polyvec_matrix_ntt(polyvec_p mathat[KYBER_K], polyvec mat[KYBER_K]);
#define polyvec_matrix_basemul KYBER_NAMESPACE(polyvec_matrix_basemul)
void polyvec_matrix_basemul(polyvec_p *t, const polyvec_p mat[KYBER_K], const polyvec_p *s);

/**************************************************************/
/************ Vectors of polynomials of KYBER_K **************/
/**************************************************************/
#define polyvec_getnoise_eta1 KYBER_NAMESPACE(polyvec_getnoise_eta1)
void polyvec_getnoise_eta1(polyvec *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
#define polyvec_getnoise_eta2 KYBER_NAMESPACE(polyvec_getnoise_eta2)
void polyvec_getnoise_eta2(polyvec *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);


#define polyvec_compress KYBER_NAMESPACE(polyvec_compress)
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_CU], polyvec *a);
#define polyvec_decompress KYBER_NAMESPACE(polyvec_decompress)
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_CU]);

#define polyvec_tobytes KYBER_NAMESPACE(polyvec_tobytes)
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], polyvec *a);
#define polyvec_frombytes KYBER_NAMESPACE(polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

#define polyvec_eta_tobytes KYBER_NAMESPACE(polyvec_eta_tobytes)
void polyvec_eta_tobytes(uint8_t r[KYBER_SECRETVECBYTES], const polyvec *a);
#define polyvec_eta_frombytes KYBER_NAMESPACE(polyvec_eta_frombytes)
void polyvec_eta_frombytes(polyvec *r, const uint8_t a[KYBER_SECRETVECBYTES]);

#define polyvec_ntt KYBER_NAMESPACE(polyvec_ntt)
void polyvec_ntt(polyvec_p *r, polyvec *a);
#define polyvec_invntt KYBER_NAMESPACE(polyvec_invntt)
void polyvec_invntt(polyvec *r, polyvec_p *a);
#define polyvec_basemul KYBER_NAMESPACE(polyvec_basemul)
void polyvec_basemul(poly_p *r, const polyvec_p *a, const polyvec_p *b);


#define polyvec_reduce KYBER_NAMESPACE(polyvec_reduce)
void polyvec_reduce(polyvec *r);
#define polyvec_add KYBER_NAMESPACE(polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);
#define polyvec_sub KYBER_NAMESPACE(polyvec_sub)
void polyvec_sub(polyvec *r, const polyvec *a, const polyvec *b);
#define polyvec_caddq KYBER_NAMESPACE(polyvec_caddq)
void polyvec_caddq(polyvec *r);

#endif
