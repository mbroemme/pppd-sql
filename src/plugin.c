/*
 *  plugin.c -- Challenge Handshake Authentication Protocol for the
 *              Point-to-Point Protocol (PPP) shared functions.
 *
 *  Copyright (c) 2008 Maik Broemme <mbroemme@plusserver.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* plugin includes. */
#include "plugin.h"
#include "str.h"

/* generic includes. */
#include <string.h>

/* this function set whether the peer must authenticate itself to us via CHAP. */
int32_t pppd__chap_check(void) {

	/* return one, because we need to ask peer everytime for authentication. */
	return 1;
}

/* this function set whether the peer must authenticate itself to us via PAP. */
int32_t pppd__pap_check(void) {

	/* return one, because we need to ask peer everytime for authentication. */
	return 1;
}

/* this function will look for a valid client ip address. */
void pppd__ip_choose(uint32_t *addrp) {

	/* set ip address to client one fetched from database. */
	*addrp = client_ip;
}

/* this function set whether the plugin is allowed to set client ip addresses. */
int32_t pppd__allowed_address(uint32_t addr) {

	/* check if ip address is equal to client address from database. */
	if (addr != client_ip) {

		/* seems that we are using an invalid ip address. */
		return 0;
	}

	/* return one, because we are allowed to assign ip addresses. */
	return 1;
}

/* this function verify the given password. */
int32_t pppd__verify_password(uint8_t *passwd, uint8_t *secret_name, uint8_t *encrpytion, uint8_t *key) {

	/* some common variables. */
	uint8_t passwd_aes[SIZE_AES];
	uint8_t passwd_key[SIZE_AES];
	uint8_t passwd_md5[SIZE_MD5];
	uint8_t *passwd_crypt = NULL;
	uint32_t count        = 0;
	int32_t passwd_size   = 0;
	int32_t temp_size     = 0;
	EVP_MD_CTX ctx_md5;
	EVP_CIPHER_CTX ctx_aes;

	/* cleanup the static array. */
	memset(passwd_aes, 0, sizeof(passwd_aes));
	memset(passwd_key, 0, sizeof(passwd_key));
	memset(passwd_md5, 0, sizeof(passwd_md5));

	/* check if we use no algorithm. */
	if (strcasecmp((char *)encrpytion, "NONE") == 0) {

		/* check if we found valid password. */
		if (strcmp((char *)passwd, (char *)secret_name) != 0) {

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}
	}

	/* check if we use des crypt algorithm. */
	if (strcasecmp((char *)encrpytion, "CRYPT") == 0) {

		/* check if secret from database is shorter than an expected crypt() result. */
		if (strlen((char *)secret_name) < (SIZE_CRYPT * 2)) {

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* check if password was successfully encrypted. */
		if ((passwd_crypt = (uint8_t *)DES_crypt((char *)passwd, (char *)key)) == NULL) {

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* loop through every byte and compare it. */
		for (count = 0; count < (strlen((char *)secret_name) / 2); count++) {

			/* check if our hex value matches the hash byte. (this isn't the fastest way, but hash is everytime 13 byte) */
			if (htoi(secret_name[2 * count]) * 16 + htoi(secret_name[2 * count + 1]) != passwd_crypt[count]) {

				/* clear the memory with the hash, so nobody is able to dump it. */
				memset(passwd_crypt, 0, sizeof(passwd_crypt));

				/* return with error and terminate link. */
				return PPPD_SQL_ERROR_PASSWORD;
			}
		}
	}

	/* check if we use md5 hashing algorithm. */
	if (strcasecmp((char *)encrpytion, "MD5") == 0) {

		/* check if secret from database is shorter than an expected md5 hash. */
		if (strlen((char *)secret_name) < (SIZE_MD5 * 2)) {

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* initialize the openssl context. */
		EVP_MD_CTX_init(&ctx_md5);

		/* check if cipher initialization is working. */
		if (EVP_DigestInit_ex(&ctx_md5, EVP_md5(), NULL) == 0) {

			/* cleanup cipher context to prevent memory dumping. */
			EVP_MD_CTX_cleanup(&ctx_md5);

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* encrypt the input buffer. */
		if (EVP_DigestUpdate(&ctx_md5, passwd, strlen((char *)passwd)) == 0) {

			/* cleanup cipher context to prevent memory dumping. */
			EVP_MD_CTX_cleanup(&ctx_md5);

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* encrypt the last block from input buffer. */
		if (EVP_DigestFinal_ex(&ctx_md5, passwd_md5, (uint32_t *)&passwd_size) == 0) {

			/* cleanup cipher context to prevent memory dumping. */
			EVP_MD_CTX_cleanup(&ctx_md5);

			/* clear the memory with the hash, so nobody is able to dump it. */
			memset(passwd_md5, 0, sizeof(passwd_md5));

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* cleanup cipher context to prevent memory dumping. */
		EVP_MD_CTX_cleanup(&ctx_md5);

		/* loop through every byte and compare it. */
		for (count = 0; count < (strlen((char *)secret_name) / 2); count++) {

			/* check if our hex value matches the hash byte. (this isn't the fastest way, but hash is everytime 16 byte) */
			if (htoi(secret_name[2 * count]) * 16 + htoi(secret_name[2 * count + 1]) != passwd_md5[count]) {

				/* clear the memory with the hash, so nobody is able to dump it. */
				memset(passwd_md5, 0, sizeof(passwd_md5));

				/* return with error and terminate link. */
				return PPPD_SQL_ERROR_PASSWORD;
			}
		}

		/* clear the memory with the hash, so nobody is able to dump it. */
		memset(passwd_md5, 0, sizeof(passwd_md5));
	}

	/* check if we use aes block cipher algorithm. */
	if (strcasecmp((char *)encrpytion, "AES") == 0) {

		/* check if secret from database is shorter than an expected minimum aes size. */
		if (strlen((char *)secret_name) < (SIZE_AES * 2)) {

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* check if we have to truncate source pointer. */
		if (strlen((char *)key) < 16) {

			/* copy the key to the static buffer. */
			memcpy(passwd_key, key, strlen((char *)key));
		} else {

			/* copy the key to the static buffer. */
			memcpy(passwd_key, key, 16);
		}

		/* initialize the openssl context. */
		EVP_CIPHER_CTX_init(&ctx_aes);

		/* check if cipher initialization is working. */
		if (EVP_EncryptInit_ex(&ctx_aes, EVP_aes_128_ecb(), NULL, passwd_key, NULL) == 0) {

			/* cleanup cipher context to prevent memory dumping. */
			EVP_CIPHER_CTX_cleanup(&ctx_aes);

			/* clear the memory with the aes key, so nobody is able to dump it. */
			memset(passwd_key, 0, sizeof(passwd_key));

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* encrypt the input buffer. */
		if (EVP_EncryptUpdate(&ctx_aes, passwd_aes, &passwd_size, passwd, strlen((char *)passwd)) == 0) {

			/* cleanup cipher context to prevent memory dumping. */
			EVP_CIPHER_CTX_cleanup(&ctx_aes);

			/* clear the memory with the aes key and buffer, so nobody is able to dump it. */
			memset(passwd_aes, 0, sizeof(passwd_aes));
			memset(passwd_key, 0, sizeof(passwd_key));

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* encrypt the last block from input buffer. */
		if (EVP_EncryptFinal_ex(&ctx_aes, passwd_aes + passwd_size, &temp_size) == 0) {

			/* cleanup cipher context to prevent memory dumping. */
			EVP_CIPHER_CTX_cleanup(&ctx_aes);

			/* clear the memory with the aes key and buffer, so nobody is able to dump it. */
			memset(passwd_aes, 0, sizeof(passwd_aes));
			memset(passwd_key, 0, sizeof(passwd_key));

			/* return with error and terminate link. */
			return PPPD_SQL_ERROR_PASSWORD;
		}

		/* cleanup cipher context to prevent memory dumping. */
		EVP_CIPHER_CTX_cleanup(&ctx_aes);

		/* compute final size. */
		passwd_size += temp_size;

		/* loop through every byte and compare it. */
		for (count = 0; count < (strlen((char *)secret_name) / 2); count++) {

			/* check if our hex value matches the hash byte. (this isn't the fastest way, but okay) */
			if (htoi(secret_name[2 * count]) * 16 + htoi(secret_name[2 * count + 1]) != passwd_aes[count]) {

				/* clear the memory with the aes key and buffer, so nobody is able to dump it. */
				memset(passwd_aes, 0, sizeof(passwd_aes));
				memset(passwd_key, 0, sizeof(passwd_key));

				/* return with error and terminate link. */
				return PPPD_SQL_ERROR_PASSWORD;
			}
		}

		/* clear the memory with the aes key and buffer, so nobody is able to dump it. */
		memset(passwd_aes, 0, sizeof(passwd_aes));
		memset(passwd_key, 0, sizeof(passwd_key));
	}

	/* if no error was found, establish link. */
	return 0;
}
