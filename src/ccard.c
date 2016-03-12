#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ccard.h"
#include "config.h"
#include "dynarr.h"
#include "etc.h"

#define PREALLOC_LIST	16

static int initialized = 0;
static dynarr_t *blacklist = NULL;
static dynarr_t *whitelist = NULL;

typedef struct blacklist_entry_t {
	uint8_t *prefix;
	size_t len;
} blacklist_entry_t;

typedef struct whitelist_entry_t {
	uint8_t *prefix;
	size_t len;
	uint32_t flags;
} whitelist_entry_t;

static void free_blacklist(void *data) {
	blacklist_entry_t *ent = data;
	free(ent->prefix);
}

static void init_blacklist(const char *src) {
	FILE *fp;
	char *input;
	size_t len;
	blacklist_entry_t listent;

	if((blacklist = dynarr_new(sizeof(blacklist_entry_t), PREALLOC_LIST, free_blacklist)) == NULL) return;
	if((fp = fopen(src, "r")) == NULL) return;

	while(!feof(fp) && (input = line_in(fp))) {
		if((len = strlen(input)) > 0) {
			if((listent.prefix = malloc(len)) == NULL) {
				free(input);
				continue;
			}
			memcpy(listent.prefix, input, len);
			listent.len = len;
			dynarr_add(blacklist, &listent);

		}
		free(input);
	}

	fclose(fp);
}

static void free_whitelist(void *data) {
	whitelist_entry_t *ent = data;
	free(ent->prefix);
}

static void init_whitelist(const char *src) {
	FILE *fp;
	char *input, *tab, *space;
	uint32_t flags, pos;
	size_t len;
	whitelist_entry_t listent;

	if((whitelist = dynarr_new(sizeof(whitelist_entry_t), PREALLOC_LIST, free_whitelist)) == NULL) return;
	if((fp = fopen(src, "r")) == NULL) return;

	while(!feof(fp) && (input = line_in(fp))) {
		if(strlen(input) == 0) 
			free(input);
		else {
			if((tab = strchr(input, '\t')) == NULL)
				continue;

			len = tab - input;
			*tab = '\0';
			tab++;

			flags = 0;
			while((space = strchr(tab, ' ')) != NULL) {
				*space = '\0';
				pos = atoi(tab);
				flags |= (1 << pos);
				tab = space + 1;
			}

			if((listent.prefix = malloc(len)) == NULL) {
				free(input);
				continue;
			}

			memcpy(listent.prefix, input, len);
			listent.len = len;
			listent.flags = flags;
			dynarr_add(whitelist, &listent);

			free(input);
		}
	}

	fclose(fp);
}

static int checklist(const uint8_t *num, size_t len) {
	size_t n, i;
	whitelist_entry_t *whitelist_entry;
	blacklist_entry_t *blacklist_entry;

	n = dynarr_get_size(blacklist);
	for(i = 0; i < n; i++) {
		blacklist_entry = dynarr_get_index(blacklist, i);
		if(!memcmp(num, blacklist_entry->prefix, blacklist_entry->len))
			return CC_BLIST;
	}

	n = dynarr_get_size(whitelist);
	for(i = 0; i < n; i++) {
		whitelist_entry = dynarr_get_index(whitelist, i);
		if(!memcmp(num, whitelist_entry->prefix, whitelist_entry->len)) {
			if(whitelist_entry->flags & (1 << len))
				return CC_OK;
			else
				return CC_LENGTH;
		}
	}

	/* Number is neither blacklisted nor whitelisted */
	return CC_UNSURE;
}

void cc_freelists(void) {
	dynarr_free(blacklist);
	blacklist = NULL;
	dynarr_free(whitelist);
	whitelist = NULL;

	initialized = 0;
}

int cc_check(const uint8_t *num, const size_t len) {
	size_t i;
	char c, check;
	uint32_t sum = 0;
	int ret;

	if(initialized == 0) {
		init_blacklist(CONFIG_DATADIR "ccard_blacklist.txt");
		init_whitelist(CONFIG_DATADIR "ccard_whitelist.txt");
		initialized = 1;
	}

	ret = checklist(num, len);
	if((ret != CC_OK) && (ret != CC_UNSURE))
		return ret;

	if((len < 14) || (len > 19))
		return 0;

	for(i = 0; i < len - 1; i++) {
		c = num[len - i - 2];
		c -= '0';

		if((c < 0) || (c > 9))
			return 0;

		c *= (i % 2) ? 1 : 2;

		if(c > 9) c -= 9;
		sum += c;
	}

	check = num[len - 1] - '0';
	if((sum * 9) % 10 != check)
		return CC_CKSUM;

	return ret;
}
