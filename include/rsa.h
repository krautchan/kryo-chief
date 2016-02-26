#ifndef RSA_H_
#define RSA_H_

#include <tommath.h>

#define KEYSIZE 1024

typedef struct rsa_keypair_t rsa_keypair_t;

rsa_keypair_t *rsa_keypair_gen(const int n_bits, int *status);
void rsa_keypair_free(rsa_keypair_t *pair);

int rsa_enc(mp_int *p, rsa_keypair_t *pair, mp_int *c);
int rsa_dec(mp_int *c, rsa_keypair_t *pair, mp_int *p);

#endif
