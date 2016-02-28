#ifndef HFUNCS_H_
#define HFUNCS_H_

#include <stdint.h>
#include <stdlib.h>

#define DEFAULT_HFUNC	hfunc_pearson

size_t hfunc_jenkins(const uint8_t *key, const size_t klen);
size_t hfunc_pearson(const uint8_t *key, const size_t klen);
size_t hfunc_stackov(const uint8_t *key, const size_t klen);

#endif
