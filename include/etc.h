#ifndef ETC_H_
#define ETC_H_

#include <stdint.h>
#include <stdlib.h>

#include <tommath.h>

typedef void (*freefunc_t)(void*);

void printaddr(const uint8_t *peer);
void inttoarr(const uint32_t in, uint8_t *out);
uint32_t arrtoint(uint8_t *in);
size_t bitstobytes(const size_t n_bits);
size_t fp_size(FILE *fp);
char *alloc_copy(const char *str);
void xorblock(uint8_t *dat1, uint8_t *dat2, size_t len);
int getrand(uint8_t *dst, int len, void *dat);
void printint(mp_int *i, const char *id);
char *line_in(FILE *fp);

#endif
