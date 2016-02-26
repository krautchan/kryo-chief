#ifndef RSA_INT_H_
#define RSA_INT_H_

#include <tommath.h>

typedef struct rsa_keypair_t {
	mp_int *p, *q;
	mp_int *public, *secret;
	mp_int *modulus;

	mp_int *dp, *dq, *qi;
} rsa_keypair_t;

#endif
