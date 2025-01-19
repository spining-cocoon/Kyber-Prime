#include <stdint.h>
#include "params.h"
#include "cbd.h"

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 24-bit integer
*              in little-endian order.
**************************************************/
static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
**************************************************/
void cbd3(poly *r, const uint8_t buf[202]) { 
    unsigned int i,j;
    uint32_t t,d;
    int16_t a,b;

    for(i = 0; i < KYBER_N/4; i++) { 
      t  = load24_littleendian(buf + 3 * i);
      d  = t & 0x00249249;
      d += (t >> 1) & 0x00249249;
      d += (t >> 2) & 0x00249249;

      for(j = 0; j < 4; j++) {
        a = (d >> (6 * j + 0)) & 0x7;
        b = (d >> (6 * j + 3)) & 0x7;
        r->coeffs[4 * i + j] = a - b;
      }
    }

    t = buf[201];
    d  = t & 0x49; 
    d += (t >> 1) & 0x49;
    d += (t >> 2) & 0x49;

    a = (d >> 0) & 0x7;
    b = (d >> 3) & 0x7;
    r->coeffs[268] = a - b;
}