#ifndef FILECRYPT_H_
#define FILECRYPT_H_

#include <stdint.h>

int file_enc(const char *infile, const char *outfile, const uint8_t *key);
int file_dec(const char *infile, const char *outfile, const uint8_t *key);

#endif
