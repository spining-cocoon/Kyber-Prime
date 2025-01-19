#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"


typedef struct{
  int16_t coeffs[KYBER_N];
} poly;

typedef struct{
  int32_t coeffs[N_PRIME];
} poly_p;


/* --------- Polynomial Arithmetic --------- */
#define poly_mul KYBER_NAMESPACE(poly_mul)
void poly_mul(poly *r, poly *a, poly *b);
#define poly_ntt KYBER_NAMESPACE(poly_ntt)
void poly_ntt(poly_p *r, poly *a);
#define poly_invntt KYBER_NAMESPACE(poly_invntt)
void poly_invntt(poly *r, poly_p *a);
#define polyp_pointwisemul KYBER_NAMESPACE(poly_pointwisemul)
void polyp_pointwisemul(poly_p *r, const poly_p *a, const poly_p *b);


#define poly_reduce KYBER_NAMESPACE(poly_reduce)
void poly_reduce(poly *r);
#define poly_caddq KYBER_NAMESPACE(poly_caddq)
void poly_caddq(poly *r);
#define poly_add KYBER_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define polyp_add KYBER_NAMESPACE(polyp_add)
void polyp_add(poly_p *r, const poly_p *a, const poly_p *b);
#define poly_sub KYBER_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);


/* --------- Polynomial Serialization --------- */
/* --------------- compute key ---------------- */
#define poly_frommsg KYBER_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
#define poly_tomsg KYBER_NAMESPACE(poly_tomsg)
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a);

#define poly_con KYBER_NAMESPACE(poly_con)
void poly_con(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_CV], poly *v, const uint8_t m[KYBER_INDCPA_MSGBYTES]);
#define poly_rec KYBER_NAMESPACE(poly_rec)
void poly_rec(uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t c2[KYBER_POLYCOMPRESSEDBYTES_CV], const poly *su);

/* ------------- generate noise --------------- */
#define poly_getnoise_eta1 KYBER_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
#define poly_getnoise_eta2 KYBER_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

/* ------------ pack uncompressed ------------- */
#define poly_tobytes KYBER_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], poly *a);
#define poly_frombytes KYBER_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

#define polyeta_tobytes KYBER_NAMESPACE(polyeta_tobytes)
void polyeta_tobytes(uint8_t r[KYBER_SECRETBYTES], const poly *a);
#define polyeta_frombytes KYBER_NAMESPACE(polyeta_frombytes)
void polyeta_frombytes(poly *r, const uint8_t a[KYBER_SECRETBYTES]);

/* ------------- pack compressed ------------- */
#define poly_compress_5 KYBER_NAMESPACE(poly_compress_5)
void poly_compress_5(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_CV], poly *a);
#define poly_decompress_5 KYBER_NAMESPACE(poly_decompress_5)
void poly_decompress_5(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_CV]);

#define poly_compress_11 KYBER_NAMESPACE(poly_compress_11)
void poly_compress_11(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_CU], poly *a);
#define poly_decompress_11 KYBER_NAMESPACE(poly_decompress_11)
void poly_decompress_11(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_CU]);

#endif
