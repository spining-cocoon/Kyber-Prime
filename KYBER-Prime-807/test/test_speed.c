#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../kem.h"
#include "../kex.h"
#include "../poly_mul.h"
#include "../reduce.h"
#include "../params.h"
#include "../indcpa.h"
#include "../polyvec.h"
#include "../poly.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 100000

uint64_t t[NTESTS];

static void randombytes(uint8_t *out, size_t outlen) {
  unsigned int i;
  uint8_t buf[8];
  static uint64_t ctr = 0;

  for(i = 0; i < 8; ++i)
    buf[i] = ctr >> 8*i;

  ctr++;
  shake128(out, outlen, buf, 8);
}

static void poly_naivemul(int16_t c[269], const int16_t a[269], const int16_t b[269]) {
  unsigned int i,j;
  int16_t t1[2*269] = {0};
  for(i = 0; i < 269; ++i){
      for(j = 0; j < 269; ++j){
          t1[i+j] = reduce32to16(t1[i+j] + (int32_t)a[i]*b[j]);
      }
  }
  c[0] = barrett_reduceq(t1[0] + t1[269]);
  for(i = 1; i < 268; i++)
    c[i] = barrett_reduceq(t1[i + 268] + t1[i + 269] + t1[i]);
  c[268] = barrett_reduceq(t1[268] + t1[536]);
}

int main()
{
  unsigned int i,j,k;
  uint8_t pk[KYBER_PUBLICKEYBYTES];
  uint8_t sk[KYBER_SECRETKEYBYTES];
  uint8_t ct[KYBER_CIPHERTEXTBYTES];
  uint8_t key[KYBER_SSBYTES];
  uint8_t seed[KYBER_SSBYTES];
  
  polyvec a[KYBER_K];
  polyvec_p ahat[KYBER_K];
  polyvec s, t1, t2, t3;
  polyvec_p shat, that;
  uint8_t nonce = 0;
  
  randombytes(seed, KYBER_SSBYTES);
  gen_a(a, seed);
  polyvec_getnoise_eta1(&s, seed, nonce++);

  //Matrix-vector school-book
   for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly tmp_poly;
    for(j = 0; j < KYBER_K; j++){
      poly_naivemul(t1.vec[j].coeffs, a[j].vec[0].coeffs, s.vec[0].coeffs);
      for(k = 1; k < KYBER_K; k++){
        poly_naivemul(tmp_poly.coeffs, a[j].vec[k].coeffs, s.vec[k].coeffs);
        poly_add(&t1.vec[j], &t1.vec[j], &tmp_poly);
      }
      poly_reduce(&t1.vec[j]);
    }
  }
  print_results("matrix vector school-book:", t, NTESTS);

  //Matrix-vector toom-cook
   for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly tmp_poly;
    for(j = 0; j < KYBER_K; j++){
      poly_mul_acc(t2.vec[j].coeffs, a[j].vec[0].coeffs, s.vec[0].coeffs);
      for(k = 1; k < KYBER_K; k++){
        poly_mul_acc(tmp_poly.coeffs, a[j].vec[k].coeffs, s.vec[k].coeffs);
        poly_add(&t2.vec[j], &t2.vec[j], &tmp_poly);
      }
      poly_reduce(&t2.vec[j]);
    }
  }
  print_results("matrix vector toom-cook:", t, NTESTS);

  //Matrix-vector NTT
  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    polyvec_matrix_ntt(ahat, a);
    polyvec_ntt(&shat, &s);
    polyvec_matrix_basemul(&that, ahat, &shat);
    polyvec_invntt(&t3, &that);
  }
  print_results("matrix vector ntt:", t, NTESTS);


  //Vector-vector school-book
  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly tmp_poly;
    poly_naivemul(t1.vec[0].coeffs, a[0].vec[0].coeffs, s.vec[0].coeffs);
    for(k = 1; k < KYBER_K; k++){
      poly_naivemul(tmp_poly.coeffs, a[0].vec[k].coeffs, s.vec[k].coeffs);
      poly_add(&t1.vec[0], &t1.vec[0], &tmp_poly);
    }
    poly_reduce(&t1.vec[0]);
  
  }
  print_results("vector vector school-book:", t, NTESTS);

  //Vector-vector toom-cook
   for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly tmp_poly;
    poly_mul_acc(t2.vec[0].coeffs, a[0].vec[0].coeffs, s.vec[0].coeffs);
    for(k = 1; k < KYBER_K; k++){
      poly_mul_acc(tmp_poly.coeffs, a[0].vec[k].coeffs, s.vec[k].coeffs);
      poly_add(&t2.vec[0], &t2.vec[0], &tmp_poly);
    }
    poly_reduce(&t2.vec[0]);
  }
  print_results("vetcor vector toomcook:", t, NTESTS);

  //Vector-vector NTT
  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    polyvec_ntt(&ahat[0], &a[0]);
    polyvec_ntt(&shat, &s);
    polyvec_basemul(&that.vec[0], &ahat[0], &shat);
    poly_invntt(&t3.vec[0], &that.vec[0]);
  }
  print_results("vector vector ntt:", t, NTESTS);
  

  //Rq*Rq school-book
  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_naivemul(t1.vec[0].coeffs, a[0].vec[0].coeffs, s.vec[0].coeffs);
  }
  print_results("poly school-book:", t, NTESTS);

  //Rq*Rq school-book
  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_mul_acc(t2.vec[0].coeffs, a[0].vec[0].coeffs, s.vec[0].coeffs);
  }
  print_results("poly toom-cook:", t, NTESTS);

  //Rq*Rq NTT
  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_ntt(&ahat[0].vec[0], &a[0].vec[0]);
    poly_ntt(&shat.vec[0], &s.vec[0]);
    polyp_pointwisemul(&that.vec[0], &ahat[0].vec[0], &shat.vec[0]);
    poly_invntt(&t3.vec[0], &that.vec[0]);
  }
  print_results("poly ntt:", t, NTESTS);
  
  
  /*********** ind-cpa pke*************/
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_keypair(pk, sk);
  }
  print_results("indcpa_keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_enc(ct, key, pk, seed);
  }
  print_results("indcpa_enc: ", t, NTESTS);
  
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_dec(key, ct, sk);
  }
  print_results("indcpa_dec: ", t, NTESTS);


   /*********** ind-cca kem*************/
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair(pk, sk);
  }
  print_results("keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc(ct, key, pk);
  }
  print_results("Encaps: ", t, NTESTS);
  
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_dec(key, ct, sk);
  }
  print_results("Decaps: ", t, NTESTS);
  
  return 0;
}
