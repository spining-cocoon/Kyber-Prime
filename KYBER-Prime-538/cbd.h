#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define cbd4 KYBER_NAMESPACE(cbd4)
void cbd4(poly *r, const uint8_t buf[269]);
#endif
