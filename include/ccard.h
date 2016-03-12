#ifndef CCARD_H_
#define CCARD_H_

#include <stdint.h>
#include <stdlib.h>

#define CC_OK		1
#define CC_UNSURE	0
#define CC_BLIST	-1
#define CC_WLIST	-2
#define CC_LENGTH	-3
#define CC_CKSUM	-4
#define CC_KNOWN	-5

void cc_freelists(void);
void cc_save(const uint8_t *num, const size_t len, const char *filename);
int cc_check(const uint8_t *num, const size_t len);

#endif
