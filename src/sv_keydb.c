#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "etc.h"
#include "fslist.h"
#include "htab.h"
#include "rsa_io.h"
#include "sha256.h"

typedef struct keydb_t {
	htab_t *keytable;
	htab_t *issued_keys;
	htab_t *released_keys;
	uint32_t n_pregen, n_regen, n_keys;
	const char *basedir;
} keydb_t;

typedef struct dbent_t {
	rsa_keypair_t *pair;
	int issued, released;
} dbent_t;

static keydb_t keydb;
static pthread_mutex_t db_mutex;

int genthread_shutdown = 0;

static int saveent(dbent_t *ent, uint8_t *keyid) {
	FILE *fp;
	uint8_t *serial;
	char *filename, buf[3];
	size_t serial_len, filename_len, i;

	printf("Serializing... ");
	fflush(stdout);
	if((serial = rsa_serialize_pair(ent->pair, &serial_len)) == NULL) {
		printf("Failed!\n");
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

	printf("Done.\n");
	free(filename);
	free(serial);

	return 1;
}

static dbent_t *mknewpair(int *status) {
	dbent_t *out;

	*status = 0;
	if((out = malloc(sizeof(dbent_t))) == NULL) return NULL;
	printf("mknewpair(): Generating %d-bit key... ", CONFIG_RSA_KSIZE);
	fflush(stdout);
	if((out->pair = rsa_keypair_gen(CONFIG_RSA_KSIZE, status)) == NULL) return NULL;

	out->issued = 0;
	out->released = 0;

	*status = 1;
	return out;	
}

static int keydb_insert(dbent_t *newent, uint8_t *keyid) {
	int ret;
	
	pthread_mutex_lock(&db_mutex);
	
	if((ret = htab_insert(keydb.keytable, keyid, SHA256_SIZE, newent)) == 1)
		keydb.n_keys++;

	pthread_mutex_unlock(&db_mutex);
	
	return ret;
}

static void *generator_thread(void *arg) {
	int status;
	dbent_t *newent;
	uint8_t keyid[SHA256_SIZE];

	printf("generator_thread(): Starting.\n");

	while(genthread_shutdown == 0) {
		if(keydb.n_keys >= keydb.n_regen) {
			sleep(CONFIG_KEYGEN_SLEEP);
			continue;
		}

		while(keydb.n_keys < keydb.n_pregen) {
			printf("generator_thread(): Need to generate more keys. (I have %" PRIu32 "/%" PRIu32 ")\n", keydb.n_keys, keydb.n_pregen);
			if((newent = mknewpair(&status)) != NULL) {
				saveent(newent, keyid);
				keydb_insert(newent, keyid);
			}
			if(keydb.n_keys == keydb.n_pregen)
				printf("generator_thread(): Precalculation finished.\n");
			sleep(1);
		}
	}
	pthread_exit(NULL);
}

static int read_keyfile(const char *filename) {
	FILE *fp;
	size_t filesize;
	uint8_t *data, keyid[SHA256_SIZE];
	rsa_keypair_t *newpair;
	dbent_t *newent;
	int ret = 0;

	printf("Reading file '%s'... ", filename);
	if((fp = fopen(filename, "rb")) == NULL) printf("fopen() failed!\n");
	
	filesize = fp_size(fp);
	if((data = malloc(filesize)) == NULL) goto closefp;
	if(fread(data, filesize, 1, fp) == 0) goto freedata;
	if((newpair = rsa_read_secret(data, filesize)) == NULL) goto freedata;
	if((newent = malloc(sizeof(dbent_t))) == NULL) goto freepair;
	if(rsa_keyid_fromserial(data, keyid) == 0) goto freenew;

	newent->pair = newpair;
	newent->issued = 0;
	newent->released = 0;

	if(keydb_insert(newent, keyid) == 0) goto freenew;

	ret = 1;

freenew:
	if(ret == 0) free(newent);
freepair:
	if(ret == 0) rsa_keypair_free(newpair);
freedata:
	free(data);
closefp:
	fclose(fp);
	
	printf("%s\n", (ret == 0) ? "Failed!" : "OK!");
	return ret;
}

static int read_dir(const char *basedir) {
	size_t i;
	fslist_t *list;
	
	if((list = fslist_scan(basedir)) == NULL) return 0;

	for(i = 0; i < list->n; i++)
		read_keyfile(list->filename[i]);

	fslist_free(list);
	return 1;
}

static void free_dbent(void *data) {
	dbent_t *entry = data;

	if(entry == NULL) return;

	rsa_keypair_free(entry->pair);
	free(entry);
}

int keydb_init(const char *basedir, const uint32_t n_pregen, const uint32_t n_regen) {
	keydb.n_keys = 0;
	keydb.n_pregen = n_pregen;
	keydb.n_regen = n_regen;
	keydb.basedir = basedir;

	pthread_mutex_init(&db_mutex, NULL);

	if((keydb.keytable = htab_new(CONFIG_KEYTAB_SIZE, NULL, free_dbent)) == NULL)
		return 0;
	if((keydb.issued_keys = htab_new(CONFIG_KEYTAB_SIZE, NULL, NULL)) == NULL)
		goto freetab;
	if((keydb.released_keys = htab_new(CONFIG_KEYTAB_SIZE, NULL, NULL)) == NULL)
		goto freeissued;

	printf("keydb_init(): Scanning direcotory '%s'...\n", basedir);
	if(read_dir(basedir) == 0) goto freereleased;

	printf("keydb_init(): Got %" PRIu32 " keys. \n", keydb.n_keys);

	return 1;

freereleased:
	htab_free(keydb.released_keys);
freeissued:
	htab_free(keydb.issued_keys);
freetab:
	htab_free(keydb.keytable);
	return 0;
}

void keydb_free(void) {
	htab_free(keydb.keytable);
	htab_free(keydb.issued_keys);
	htab_free(keydb.released_keys);
	pthread_mutex_destroy(&db_mutex);
}

pthread_t keydb_spawngen(void) {
	pthread_t genthread;
	int status;

	if((status = pthread_create(&genthread, NULL, generator_thread, NULL)) != 0) {
		fprintf(stderr, "keydb_spawngen(): pthread_create() failed.\n");
		return 0;
	}
	return genthread;
}
