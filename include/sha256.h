#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stdlib.h>

#define SHA256_SIZE		32

int sha256(const uint8_t *in, const size_t size, uint8_t *out);

#endif 
