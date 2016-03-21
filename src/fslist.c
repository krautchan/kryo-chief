/* 
 * HTR -- The Heisetrolljan
 * 
 * Copyright (C) 2016  Martin Wolters
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to 
 * the Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA
 * 
 */

#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "etc.h"
#include "fslist.h"

static fslist_t *fslist_new(void) {
	fslist_t *out;

	if((out = malloc(sizeof(fslist_t))) == NULL) return NULL;
	if((out->filename = malloc(PREALLOC_FILES * sizeof(char*))) == NULL) {
		free(out);
		return NULL;
	}

	out->n = 0;
	out->n_alloced = PREALLOC_FILES;

	return out;
}

static int addtolist(const char *filename, fslist_t *list) {
	char **newlist, *newname;
	size_t i;

	if(list->n == list->n_alloced) {
		if((newlist = malloc((list->n + PREALLOC_FILES) * sizeof(char*))) == NULL)
			return 0;

		for(i = 0; i < list->n; i++) 
			newlist[i] = list->filename[i];

		free(list->filename);
		list->filename = newlist;
		list->n_alloced += PREALLOC_FILES;
	}

	if((newname = alloc_copy(filename)) == NULL) return 0;
	
	list->filename[list->n] = newname;
	list->n++;
	return 1;
}

static int add_dir(fslist_t *list, const char *basedir) {
	DIR *dp;
	struct dirent *dirent;
	char fullpath[PATH_MAX];

	if((dp = opendir(basedir)) == NULL) return 0;
	
	while((dirent = readdir(dp)) != NULL) {
		if(!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, ".."))
			continue;

		snprintf(fullpath, PATH_MAX, "%s/%s", basedir, dirent->d_name);

		if(dirent->d_type == DT_REG)
			addtolist(fullpath, list);
		if(dirent->d_type == DT_DIR)
			add_dir(list, fullpath);
	}

	closedir(dp);
	return 1;
}

fslist_t *fslist_scan(const char *basedir) {
	fslist_t *list;

	if((list = fslist_new()) == NULL) return NULL;
	add_dir(list, basedir);

	return list;
}

void fslist_free(fslist_t *list) {
	size_t i;

	if(list == NULL)
		return;

	for(i = 0; i < list->n; i++)
		free(list->filename[i]);
	free(list->filename);
	free(list);
}
