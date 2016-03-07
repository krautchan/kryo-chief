#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ccard.h"
#include "dynarr.h"
#include "etc.h"

#define PREALLOC_LIST	16

static int initialized = 0;
static dynarr_t *blacklist = NULL;
static dynarr_t *whitelist = NULL;

typedef struct whitelist_entry_t {
	char *prefix;
	uint32_t flags;
} whitelist_entry_t;

static void init_blacklist(const char *src) {
	FILE *fp;
	char *newent;

	if((blacklist = dynarr_new(sizeof(char*), PREALLOC_LIST, NULL)) == NULL) return;
	if((fp = fopen(src, "r")) == NULL) return;

	while(!feof(fp) && (newent = line_in(fp))) {
		if(strlen(newent) > 0)
			dynarr_add(blacklist, newent);
		free(newent);
	}

	fclose(fp);
}

static void free_whitelist(void *data) {
	whitelist_entry_t *ent = data;
	free(ent->prefix);
}

static void init_whitelist(const char *src) {
	FILE *fp;
	char *newent, *tab, *space;
	uint32_t flags, pos;	
	whitelist_entry_t listent;

	if((whitelist = dynarr_new(sizeof(whitelist_entry_t), PREALLOC_LIST, free_whitelist)) == NULL) return;
	if((fp = fopen(src, "r")) == NULL) return;

	while(!feof(fp) && (newent = line_in(fp))) {
		if(strlen(newent) == 0) 
			free(newent);
		else {
			if((tab = strchr(newent, '\t')) == NULL)
				continue;

			*tab = '\0';
			tab++;

			flags = 0;
			while((space = strchr(tab, ' ')) != NULL) {
				*space = '\0';
				pos = atoi(tab);
				flags |= (1 << pos);
				tab = space + 1;
			}

			listent.prefix = newent;
			listent.flags = flags;
			dynarr_add(whitelist, &listent);
		}
	}

	fclose(fp);
}

static int checklist(const char *num, size_t len) {
	size_t n, i;
	char *list_entry;
	whitelist_entry_t *whitelist_entry;

	n = dynarr_get_size(blacklist);
	for(i = 0; i < n; i++) {
		list_entry = dynarr_get_index(blacklist, i);
		if(!strncmp(num, list_entry, strlen(list_entry)))
			return CC_BLIST;
	}

	n = dynarr_get_size(whitelist);
	for(i = 0; i < n; i++) {
		whitelist_entry = dynarr_get_index(whitelist, i);
		list_entry = whitelist_entry->prefix;

		if(!strncmp(num, list_entry, strlen(list_entry))) {
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

int cc_check(const char *num, const size_t len) {
	size_t i;
	char c, check;
	uint32_t sum = 0;
	int ret;

	if(initialized == 0) {
		init_blacklist("etc/ccard_blacklist.txt");
		init_whitelist("etc/ccard_whitelist.txt");
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
