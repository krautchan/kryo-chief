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

#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "etc.h"
#include "fslist.h"
#include "htab.h"
#include "queue.h"
#include "rsa_io.h"
#include "sha256.h"

typedef struct keydb_t {
	htab_t *all_keys;
	queue_t *available_keys;
	uint32_t n_pregen, n_regen;
	const char *basedir;
} keydb_t;

typedef struct dbent_t {
	rsa_keypair_t *pair;
	uint8_t keyid[SHA256_SIZE];
	int issued, released;
} dbent_t;

static keydb_t keydb;
static pthread_mutex_t db_mutex;

int genthread_shutdown = 0;

rsa_keypair_t *release_key(const uint8_t *keyid) {
	FILE *fp;
	dbent_t *dbent;
	rsa_keypair_t *out = NULL;

	pthread_mutex_lock(&db_mutex);
	if((dbent = htab_lookup(keydb.all_keys, keyid, SHA256_SIZE)) == NULL) {
		printf("Unknown key ID!\n");
		goto end;
	}

	if(dbent->issued == 0) {
		printf("Key has not been issued.\n");
		goto end;
	}

	if((fp = fopen(CONFIG_DATADIR "keys_released", "ab")) == NULL) {
		printf("fopen() failed!\n");
		goto end;
	}
	fwrite(keyid, SHA256_SIZE, 1, fp);
	fclose(fp);

	dbent->released = 1;
	out = dbent->pair;

end:
	pthread_mutex_unlock(&db_mutex);
	return out;
}

int is_released(const uint8_t *keyid) {
	dbent_t *dbent;
	int ret = 0;

	pthread_mutex_lock(&db_mutex);

	if((dbent = htab_lookup(keydb.all_keys, keyid, SHA256_SIZE)) == NULL) goto end;
	ret = dbent->released;

end:
	pthread_mutex_unlock(&db_mutex);
	return ret;
}

rsa_keypair_t *issue_key(void) {
	rsa_keypair_t *out = NULL;
	dbent_t *issue, *global;
	FILE *fp;

	pthread_mutex_lock(&db_mutex);

	if((issue = queue_pull(keydb.available_keys)) == NULL) goto fail;
	if(issue->issued == 1) printf("???\n");
	out = issue->pair;

	if((global = htab_lookup(keydb.all_keys, issue->keyid, SHA256_SIZE)) == NULL) {
		queue_push(keydb.available_keys, issue);
		out = NULL;
		goto fail;
	}

	if((fp = fopen(CONFIG_DATADIR "keys_issued", "ab")) == NULL) {
		queue_push(keydb.available_keys, issue);
		out = NULL;
		goto fail;
	}

	fwrite(issue->keyid, SHA256_SIZE, 1, fp);
	fclose(fp);

	global->issued = 1;
fail:
	pthread_mutex_unlock(&db_mutex);
	return out;
}

static int saveent(dbent_t *ent, uint8_t *keyid) {
	FILE *fp;
	uint8_t *serial;
	char *filename, buf[3];
	size_t serial_len, filename_len, i;

	if((serial = rsa_serialize_pair(ent->pair, &serial_len)) == NULL) {
		printf("rsa_serialize_pair() failed!\n");
		return 0;
	}

	if((rsa_keyid_fromserial(serial, keyid)) == 0) {
		printf("rsa_keyid_fromserial() failed!\n");
		free(serial);
		return 0;
	}

	filename_len = strlen(keydb.basedir) + strlen(CONFIG_KEYFILE_EXT) + 2 * SHA256_SIZE + 2;
	if((filename = malloc(filename_len)) == NULL) {
		printf("malloc() failed!\n");
		free(serial);
		return 0;
	}

	memset(filename, 0, filename_len);
	sprintf(filename, "%s/", keydb.basedir);
	for(i = 0; i < SHA256_SIZE; i++) {
		sprintf(buf, "%02x", keyid[i]);
		strcat(filename, buf);
	}
	strcat(filename, CONFIG_KEYFILE_EXT);

	if((fp = fopen(filename, "wb")) == NULL) {
		printf("fopen() failed!\n");
		free(filename);
		free(serial);
		return 0;
	}

	fwrite(serial, serial_len, 1, fp);
	fclose(fp);

	free(filename);
	free(serial);

	return 1;
}

static dbent_t *mknewpair(int *status) {
	dbent_t *out;

	*status = 0;
	if((out = malloc(sizeof(dbent_t))) == NULL) return NULL;
	if((out->pair = rsa_keypair_gen(CONFIG_RSA_KSIZE, status)) == NULL) return NULL;

	out->issued = 0;
	out->released = 0;

	*status = 1;
	return out;	
}

static int keydb_insert(dbent_t *newent, const int issued) {
	if((issued != 1) &&
		(queue_push(keydb.available_keys, newent) != 1))
		return 0;

	if((htab_insert(keydb.all_keys, newent->keyid, SHA256_SIZE, newent)) != 1)
		return 0;

	return 1;
}

static void keydb_free(void) {
	htab_free(keydb.all_keys);
	queue_free(keydb.available_keys);
	pthread_mutex_destroy(&db_mutex);
}

static void *generator_thread(void *arg) {
	int status;
	dbent_t *newent;
	size_t n_keys;

	printf("generator_thread(): Starting.\n");

	while(genthread_shutdown == 0) {
		n_keys = queue_get_size(keydb.available_keys);

		if(n_keys > keydb.n_regen) {
			sleep(CONFIG_KEYGEN_SLEEP);
			continue;
		}

		while((genthread_shutdown == 0) && (n_keys < keydb.n_pregen)) {
			printf("generator_thread(): Need to generate more keys. (I have %zd/%"PRIu32")\n", n_keys, keydb.n_pregen);
			
			if((newent = mknewpair(&status)) != NULL) {
				pthread_mutex_lock(&db_mutex);
				saveent(newent, newent->keyid);
				keydb_insert(newent, 0);
				pthread_mutex_unlock(&db_mutex);
			}
			
			n_keys = queue_get_size(keydb.available_keys);
			if(n_keys == keydb.n_pregen)
				printf("generator_thread(): Precalculation finished.\n");

			sleep(1);
		}
	}

	printf("generator_thread(): Shutting down.\n");
	keydb_free();
	genthread_shutdown = 2;
	pthread_exit(NULL);
}

static int read_keyfile(const char *filename, htab_t *issued, htab_t *released) {
	FILE *fp;
	size_t filesize;
	uint8_t *data;
	rsa_keypair_t *newpair;
	dbent_t *newent;
	int ret = 0;

	pthread_mutex_lock(&db_mutex);

	printf("Reading file '%s'... ", filename);
	if((fp = fopen(filename, "rb")) == NULL) goto end;

	filesize = fp_size(fp);
	if((data = malloc(filesize)) == NULL) goto closefp;
	if(fread(data, filesize, 1, fp) == 0) goto freedata;
	if((newpair = rsa_read_secret(data, filesize)) == NULL) goto freedata;
	if((newent = malloc(sizeof(dbent_t))) == NULL) goto freepair;
	if(rsa_keyid_fromserial(data, newent->keyid) == 0) goto freenew;

	newent->issued = newent->released = 0;
	if(htab_lookup(issued, newent->keyid, SHA256_SIZE) != NULL)
		newent->issued = 1;
	if(htab_lookup(released, newent->keyid, SHA256_SIZE) != NULL)
		newent->released = 1;

	newent->pair = newpair;

	if(keydb_insert(newent, newent->issued) == 0) goto freenew;

	ret = 1;

	printf("(%c%c) ", newent->issued ? 'I' : '/', newent->released ? 'R' : '/');

freenew:
	if(ret == 0) free(newent);
freepair:
	if(ret == 0) rsa_keypair_free(newpair);
freedata:
	free(data);
closefp:
	fclose(fp);
end:
	printf("%s\n", (ret == 0) ? "Failed!" : "OK!");

	pthread_mutex_unlock(&db_mutex);
	return ret;
}

static int read_dir(const char *basedir, htab_t *issued, htab_t *released) {
	size_t i;
	fslist_t *list;

	if((list = fslist_scan(basedir)) == NULL) return 0;

	for(i = 0; i < list->n; i++)
		read_keyfile(list->filename[i], issued, released);

	fslist_free(list);
	return 1;
}

static void free_dbent(void *data) {
	dbent_t *entry = data;

	if(entry == NULL) return;

	rsa_keypair_free(entry->pair);
	free(entry);
}

static void read_kidlist(const char *filename, htab_t *table) {
	FILE *fp;
	uint8_t data[SHA256_SIZE];
	int ret;

	printf("read_kidlist: %s\n", filename);

	if((fp = fopen(filename, "rb")) == NULL) return;

	while(!feof(fp)) {
		if((ret = fread(data, SHA256_SIZE, 1, fp)) == 1) {
			htab_insert(table, data, SHA256_SIZE, data);
		}
	}

	fclose(fp);
}

int keydb_init(const char *basedir, const uint32_t n_pregen, const uint32_t n_regen) {
	htab_t *issued, *released;
	keydb.n_pregen = n_pregen;
	keydb.n_regen = n_regen;
	keydb.basedir = basedir;
	int ret = 0;

	pthread_mutex_init(&db_mutex, NULL);

	if((issued = htab_new(CONFIG_KEYTAB_SIZE, NULL, NULL)) == NULL) return 0;
	if((released = htab_new(CONFIG_KEYTAB_SIZE, NULL, NULL)) == NULL) goto freeissued;

	read_kidlist(CONFIG_DATADIR "keys_issued", issued);
	read_kidlist(CONFIG_DATADIR "keys_released", released);

	if((keydb.all_keys = htab_new(CONFIG_KEYTAB_SIZE, NULL, free_dbent)) == NULL) goto freereleased;
	if((keydb.available_keys = queue_new()) == NULL) goto freeall;

	printf("keydb_init(): Scanning direcotory '%s'...\n", basedir);
	if(read_dir(basedir, issued, released) == 0) goto freeall;
	printf("keydb_init(): Got %lu keys. \n", queue_get_size(keydb.available_keys));

	ret = 1;
	goto freereleased;

freeall:
	htab_free(keydb.all_keys);
freereleased:
	htab_free(released);
freeissued:
	htab_free(issued);

	return ret;
}

int keydb_spawngen(void) {
	pthread_t genthread;
	int status;

	if((status = pthread_create(&genthread, NULL, generator_thread, NULL)) != 0) {
		fprintf(stderr, "keydb_spawngen(): pthread_create() failed.\n");
		return 0;
	}
	pthread_detach(genthread);

	return 1;
}
