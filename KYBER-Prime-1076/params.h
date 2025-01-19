#ifndef PARAMS_H
#define PARAMS_H


#define KYBER_NAMESPACE(s) KYBERprime1076_ref_##s


#define q 6977
#define Q 7508161
#define KYBER_N 269   /* 256-bit key */
#define KYBER_K 4
#define N_PRIME 576
#define KYBER_ETA1 3
#define KYBER_ETA2 3
#define DV 5
#define DU 12

#define KYBER_SYMBYTES  32  /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES   32  /* size in bytes of shared key */

/* length for poly */
#define KYBER_POLYBYTES		438
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

/* length for secret key */
#define KYBER_SECRETBYTES    101
#define KYBER_SECRETVECBYTES	(KYBER_K * KYBER_SECRETBYTES)

/* length for poly v in ct */
#define KYBER_POLYCOMPRESSEDBYTES_CV 169

/* length for poly u.vec[i] and polyvec u in ct */
#define KYBER_POLYCOMPRESSEDBYTES_CU 404
#define KYBER_POLYVECCOMPRESSEDBYTES_CU (KYBER_K * KYBER_POLYCOMPRESSEDBYTES_CU)

/* B.W. for PKE */
#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_SECRETVECBYTES)
#define KYBER_INDCPA_CTBYTES        (KYBER_POLYVECCOMPRESSEDBYTES_CU + KYBER_POLYCOMPRESSEDBYTES_CV)

/* B.W. for KEM */
#define KYBER_PUBLICKEYBYTES        (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES        (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES       (KYBER_INDCPA_CTBYTES)

#endif
