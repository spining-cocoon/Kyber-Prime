#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"


/**************************************************************/
/************ Matrix of polynomials **************/
/**************************************************************/

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
**************************************************/
static unsigned int rej_uniform(int16_t *r, unsigned int len, const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val;

    ctr = pos = 0;
    while (ctr < len && pos + 2 <= buflen) {
        val = (buf[pos] | ((uint16_t) buf[pos + 1] << 8)) & 0x1fff;
        pos += 2;

        if (val < q) {
            r[ctr++] = val;
        }
    }
    return ctr;
}

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
**************************************************/
void gen_matrix(polyvec a[KYBER_K], const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j;
  unsigned int buflen;
  unsigned char buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES + 1];
  xof_state state;


  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while (ctr < KYBER_N) {
        xof_squeezeblocks(buf, 1, &state);
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, XOF_BLOCKBYTES);
      }
    }
  }
}

/*************************************************
* Name:        polyvec_matrix_ntt
*
* Description: Forward NTT of all polynomials in matrix of size K*K. 
**************************************************/
void polyvec_matrix_ntt(polyvec_p mathat[KYBER_K], polyvec mat[KYBER_K]) {
  unsigned int i, j;

  for(i = 0; i < KYBER_K; i++)
    for(j = 0; j < KYBER_K; j++)
      poly_ntt(&mathat[i].vec[j], &mat[i].vec[j]);
}

/*************************************************
* Name:        polyvec_matrix_basemul
*
* Description: multiplication between matrix(K*K) and vectors(K) in NTT domain. 
**************************************************/
void polyvec_matrix_basemul(polyvec_p *t, const polyvec_p mat[KYBER_K], const polyvec_p *s) {
  unsigned int i;

  for(i = 0; i < KYBER_K; i++)
    polyvec_basemul(&t->vec[i], &mat[i], s);
}

/**************************************************************/
/************ Vectors of polynomials of KYBER_K **************/
/**************************************************************/

/*************************************************
* Name:        polyvec_getnoise_eta1
*
* Description: Sample a vector of polynomials deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA1
**************************************************/
void polyvec_getnoise_eta1(polyvec *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
  unsigned int i;

  for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&r->vec[i], seed, nonce++);
}

/*************************************************
* Name:        polyvec_getnoise_eta2
*
* Description: Sample a vector of polynomials deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA2
**************************************************/
void polyvec_getnoise_eta2(polyvec *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
  unsigned int i;

  for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta2(&r->vec[i], seed, nonce++);
}

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
**************************************************/
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_CU], polyvec *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_compress_11(r + i * KYBER_POLYCOMPRESSEDBYTES_CU, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
**************************************************/
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_CU]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_decompress_11(&r->vec[i], a + i * KYBER_POLYCOMPRESSEDBYTES_CU);
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], polyvec *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);

}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);

}

/*************************************************
* Name:        polyvec_eta_tobytes
*
* Description: Serialize vector of polynomials sampled in cbd;
**************************************************/
void polyvec_eta_tobytes(uint8_t r[KYBER_SECRETVECBYTES], const polyvec *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        polyeta_tobytes(r + i * KYBER_SECRETBYTES, &a->vec[i]);

}

/*************************************************
* Name:        polyvec_eta_frombytes
*
* Description: De-serialize vector of polynomials sampled in cbd;
*              inverse of polyvec_tobytes
**************************************************/
void polyvec_eta_frombytes(polyvec *r, const uint8_t a[KYBER_SECRETVECBYTES]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        polyeta_frombytes(&r->vec[i], a + i * KYBER_SECRETBYTES);

}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
**************************************************/
void polyvec_ntt(polyvec_p *r, polyvec *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_ntt(&r->vec[i], &a->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
**************************************************/
void polyvec_invntt(polyvec *r, polyvec_p *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_invntt(&r->vec[i], &a->vec[i]);
}

/*************************************************
* Name:        polyvec_basemul
*
* Description: Multiply elements of vectors(K) a and vectors(K) b in NTT domain.
**************************************************/
void polyvec_basemul(poly_p *r, const polyvec_p *a, const polyvec_p *b) {
    unsigned int i;
    poly_p t;

    polyp_pointwisemul(r, &a->vec[0], &b->vec[0]);
    for(i=1;i<KYBER_K;i++) {
      polyp_pointwisemul(&t, &a->vec[i], &b->vec[i]);
      polyp_add(r, r, &t);
    }
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
**************************************************/
void polyvec_reduce(polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
**************************************************/
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
/*************************************************
* Name:        polyvec_sub
*
* Description: Sub vectors of polynomials
**************************************************/
void polyvec_sub(polyvec *r, const polyvec *a, const polyvec *b) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
}
/*************************************************
* Name:        polyvec_caddq
*
* Description: For all coefficients of polynomials in vector 
*              add q if coefficient is negative.
**************************************************/
void polyvec_caddq(polyvec *r) {
  unsigned int i;
  for(i = 0; i < KYBER_K; i++)
    poly_caddq(&r->vec[i]);
}
