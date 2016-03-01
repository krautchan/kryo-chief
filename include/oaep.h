#ifndef OAEP_H_
#define OAEP_H_

#include <stdint.h>
#include <stdlib.h>

#include "rsa.h"
#include "sha256.h"

#define oaep_minsize(msglen)	(((msglen) + (2 * (SHA256_SIZE)) + 2) * 8)

uint8_t *oaep(const uint8_t *msg, const size_t msglen, const size_t modlen);
uint8_t *inv_oaep(const uint8_t *in, const size_t inlen, const size_t modlen, size_t *msglen);

#endif
			
