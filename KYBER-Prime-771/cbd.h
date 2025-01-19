#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define cbd2 KYBER_NAMESPACE(cbd2)
void cbd2(poly *r, const uint8_t buf[129]);

#endif
