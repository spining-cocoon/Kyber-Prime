#include <stddef.h>
#include <stdint.h>
#include "verify.h"

/*************************************************
* Name:        verify
*
* Description: Compare two arrays for equality in constant time.
*
* Arguments:   const uint8_t *a: pointer to first byte array
*              const uint8_t *b: pointer to second byte array
*              size_t len:       length of the byte arrays
*
* Returns 0 if the byte arrays are equal, 1 otherwise
**************************************************/
/*************************************************
* Name:        verify
*
* Description: Compare two arrays for equality in constant time.
**************************************************/
int verify(const uint8_t *a, const uint8_t *b, size_t len)
{
  size_t i;
  uint8_t r = 0;

  for(i=0;i<len;i++)
    r |= a[i] ^ b[i];

  return (-(uint64_t)r) >> 63;
}

/*************************************************
* Name:        cmov
*
* Description: Copy len bytes from x to r if b is 1;
*              don't modify x if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
**************************************************/
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
  size_t i;

  b = -b;
  for(i=0;i<len;i++)
    r[i] ^= b & (r[i] ^ x[i]);
}
