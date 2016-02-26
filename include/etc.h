#ifndef ETC_H_
#define ETC_H_

#include <stdint.h>
#include <stdlib.h>

#include <tommath.h>

size_t fp_size(FILE *fp);
char *alloc_copy(const char *str);
void xorblock(uint8_t *dat1, uint8_t *dat2, size_t len);
int getrand(uint8_t *dst, int len, void *dat);
void printint(mp_int *i, const char *id);
char *line_in(FILE *fp);

#endif
