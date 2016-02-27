#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stdlib.h>

int sha256(const uint8_t *in, const size_t size, uint8_t *out);

#endif 
