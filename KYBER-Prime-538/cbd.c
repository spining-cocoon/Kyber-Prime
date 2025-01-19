#include <stdint.h>
#include "params.h"
#include "cbd.h"

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
**************************************************/
static uint32_t load32_littleendian(const uint8_t x[4]) {
    uint32_t r;
    r = (uint32_t) x[0];
    r |= (uint32_t) x[1] << 8;
    r |= (uint32_t) x[2] << 16;
    r |= (uint32_t) x[3] << 24;
    return r;
}

/*************************************************
* Name:        cbd4
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=4
**************************************************/
void cbd4(poly *r, const uint8_t buf[269]){
    unsigned int i,j;
    uint32_t t,d;
    int16_t a,b;

    for(i = 0; i < KYBER_N/4; i++){ 
      t = load32_littleendian(buf + 4 * i);
      d  = t & 0x11111111;
      d += (t >> 1) & 0x11111111;
      d += (t >> 2) & 0x11111111;
      d += (t >> 3) & 0x11111111;

      for(j = 0; j < 4; j++) {
        a = (d >> (8 * j + 0)) & 15;
        b = (d >> (8 * j + 4)) & 15;
        r->coeffs[4 * i + j] = a - b;
      }
    }
    t = buf[268];
    d  = t & 0x11; 
    d += (t >> 1) & 0x11;
    d += (t >> 2) & 0x11;
    d += (t >> 3) & 0x11;

    a = (d >> 0) & 15;
    b = (d >> 4) & 15;
    r->coeffs[268] = a - b;
}