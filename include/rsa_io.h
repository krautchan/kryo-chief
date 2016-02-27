#ifndef RSA_IO_H_
#define RSA_IO_H_

#include "rsa.h"

#define INT_SIZE	sizeof(uint32_t)

uint8_t *rsa_serialize_public(rsa_keypair_t *pair, size_t *len);
rsa_keypair_t *rsa_read_public(const uint8_t *data, const size_t len);

uint8_t *rsa_serialize_pair(rsa_keypair_t *pair, size_t *len);
rsa_keypair_t *rsa_read_secret(const uint8_t *data, const size_t len);

uint8_t *rsa_enc_padded(const uint8_t *data, const size_t inlen, rsa_keypair_t *pair, size_t *outlen);
uint8_t *rsa_dec_padded(const uint8_t *data, const size_t inlen, rsa_keypair_t *pair, size_t *outlen);

int rsa_keyid_fromserial(const uint8_t *data, uint8_t *out);

void rsa_keypair_print(rsa_keypair_t *pair);

#endif
