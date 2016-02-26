#ifndef FSLIST_H_
#define FSLIST_H_

#include <stdlib.h>

#ifndef PREALLOC_FILES
#define PREALLOC_FILES	8
#endif

typedef struct fslist_t {
	size_t n;
	size_t n_alloced;
	char **filename;
} fslist_t;

void fslist_free(fslist_t *list);
fslist_t *fslist_scan(const char *basedir);

#endif
