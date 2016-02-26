#ifndef CCARD_H_
#define CCARD_H_

#include <stdlib.h>

#define CC_OK		1
#define CC_UNSURE	0
#define CC_BLIST	-1
#define CC_WLIST	-2
#define CC_LENGTH	-3
#define CC_CKSUM	-4

void cc_freelists(void);
int cc_check(const char *num, const size_t len);

#endif
