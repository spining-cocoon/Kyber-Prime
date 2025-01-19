#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"


#define QINV 2304956161 
#define qINV 3291 


#define montgomery_reduceQ KYBER_NAMESPACE(montgomery_reduceQ)
int32_t montgomery_reduceQ(int64_t a);
#define fQmul KYBER_NAMESPACE(fQmul)
int32_t fQmul(int32_t a, int32_t b);

#define montgomery_reduceq KYBER_NAMESPACE(montgomery_reduceq)
int16_t montgomery_reduceq(int32_t a);
#define fqmul KYBER_NAMESPACE(fqmul)
int16_t fqmul(int16_t a, int16_t b);

#define barrett_reduceq KYBER_NAMESPACE(barrett_reduceq)
int16_t barrett_reduceq(int16_t a);

#define reduce32to16 KYBER_NAMESPACE(reduce32to16)
int16_t reduce32to16(int32_t a);

#define caddq KYBER_NAMESPACE(caddq)
int16_t caddq(int16_t a);

#endif
