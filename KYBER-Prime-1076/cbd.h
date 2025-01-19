#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define cbd3 KYBER_NAMESPACE(cbd4)
void cbd3(poly *r, const uint8_t buf[202]);
#endif
