#include <stdint.h>
#include "params.h"
#include "reduce.h"

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 64-bit integer a, computes
*              32-bit integer congruent to a * R^-1 mod Q, where R=2^32
**************************************************/
int32_t montgomery_reduceQ(int64_t a)
{
  int32_t t;

  t = (int32_t)a*QINV;
  t = (a - (int64_t)t*Q) >> 32;
  return t;
}

int32_t fQmul(int32_t a, int32_t b) {
  return montgomery_reduceQ((int64_t)a*b);
}

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
**************************************************/
int16_t montgomery_reduceq(int32_t a)
{
  int16_t t;

  t = (int16_t)a*qINV;
  t = (a - (int32_t)t*q) >> 16;
  return t;
}

int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduceq((int32_t)a*b);
}

/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}.
**************************************************/
int16_t barrett_reduceq(int16_t a) {                                                              
  int16_t t;
  const int16_t v = ((1<<26) + q/2)/q;

  t  = ((int32_t)v*a + (1<<25)) >> 26;
  t *= q;
  return a - t;
}

/*************************************************
* Name:        reduce32to16
*
* Description: Given a 32-bit integer a, computes
*              centered representative congruent to a mod q in 16-bit.
**************************************************/
int16_t reduce32to16(int32_t a) {                                                              
  int32_t t;
  t = ((int64_t)a*547409 + (1<<30)) >> 31;
  t = a - t*q;
  return (int16_t)t;
}

/*************************************************
* Name:        caddq
*
* Description: Add q if input coefficient is negative.
**************************************************/
int16_t caddq(int16_t a) {
  a += (a >> 15) & q;
  return a;
}
