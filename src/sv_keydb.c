#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "etc.h"
#include "fslist.h"
#include "rsa_io.h"

typedef struct keydb_t {
	uint32_t n_pregen, n_regen, n_keys;
	const char *basedir;
} keydb_t;

typedef struct dbent_t {
	rsa_keypair_t *pair;
	int issued, released;
} dbent_t;

static keydb_t keydb;

int genthread_shutdown = 0;

static int saveent(dbent_t *ent) {
	FILE *fp;
	uint8_t *serial, keyid[32];
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

	filename_len = strlen(keydb.basedir) + strlen(CONFIG_KEYFILE_EXT) + 2 * 32 + 2;
	if((filename = malloc(filename_len)) == NULL) {
		printf("malloc() failed!\n");
		free(serial);
		return 0;
	}

	memset(filename, 0, filename_len);
	sprintf(filename, "%s/", keydb.basedir);
	for(i = 0; i < 32; i++) {
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
	printf("Generating %d-bit key... ", CONFIG_RSA_KSIZE);
	fflush(stdout);
	if((out->pair = rsa_keypair_gen(CONFIG_RSA_KSIZE, status)) == NULL) return NULL;

	out->issued = 0;
	out->released = 0;

	*status = 1;
	return out;	
}

static void *generator_thread(void *arg) {
	int status;
	dbent_t *newent;

	printf("generator_thread(): Starting.\n");

	while(genthread_shutdown == 0) {
		while(keydb.n_keys < keydb.n_regen) {
			printf("generator_thread(): Need to generate more keys. (I have %lu/%lu)\n", keydb.n_keys, keydb.n_pregen);
			if((newent = mknewpair(&status)) != NULL) {
				if(saveent(newent) != 0)
					keydb.n_keys++;
			}
			sleep(1);
		}
		sleep(CONFIG_KEYGEN_SLEEP);
	}
	pthread_exit(NULL);
}

static int read_keyfile(const char *filename) {
	FILE *fp;
	size_t filesize;
	uint8_t *data;
	rsa_keypair_t *newpair;

	printf("Reading file '%s'... ", filename);
	if((fp = fopen(filename, "rb")) == NULL) {
		printf("fopen() failed!\n");
		return 0;
	}
	
	filesize = fp_size(fp);
	if((data = malloc(filesize)) == NULL) {
		printf("malloc() failed!\n");
		fclose(fp);
		return 0;
	}

	if(fread(data, filesize, 1, fp) == 0) {
		printf("fread() failed!\n");
		fclose(fp);
		free(data);
		return 0;
	}

	if((newpair = rsa_read_secret(data, filesize)) == NULL) {
		printf("rsa_read_secret() failed!\n");
		fclose(fp);
		free(data);
		return 0;
	}

	printf("OK.\n");
	return 1;
}

static void read_dir(const char *basedir) {
	size_t i;
	fslist_t *list;
	
	if((list = fslist_scan(basedir)) == NULL) return;

	for(i = 0; i < list->n; i++)
		if(read_keyfile(list->filename[i]) == 1) 
			keydb.n_keys++;

	fslist_free(list);
}

int keydb_init(const char *basedir, const uint32_t n_pregen, const uint32_t n_regen) {
	keydb.n_keys = 0;
	keydb.n_pregen = n_pregen;
	keydb.n_regen = n_regen;
	keydb.basedir = basedir;

	printf("keydb_init(): Scanning direcotory '%s'...\n", basedir);
	read_dir(basedir);
	printf("keydb_init(): Got %lu keys. \n", keydb.n_keys);

	return 1;
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
