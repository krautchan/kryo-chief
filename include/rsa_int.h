#ifndef RSA_INT_H_
#define RSA_INT_H_

#include <stdlib.h>
#include <tommath.h>

struct rsa_keypair_t {
	mp_int *p, *q;
	mp_int *public, *secret;
	mp_int *modulus;

	mp_int *dp, *dq, *qi;

	size_t ksize_bytes;
};

#endif
