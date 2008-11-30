/*
 *  auth-pgsql.c -- Challenge Handshake Authentication Protocol and Password
 *                  Authentication Protocol for the Point-to-Point Protocol
 *                  (PPP) via PostgreSQL.
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

/* generic includes. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

/* generic plugin includes. */
#include "plugin.h"
#include "plugin-pgsql.h"
#include "str.h"

/* auth plugin includes. */
#include "auth-pgsql.h"

/* this function handles the PQerrorMessage() result. */
int32_t pppd__pgsql_error(uint8_t *error_message) {

	/* some common variables. */
	uint8_t *error_token;
	uint32_t first = 0;

	/* show error header. */
	error("Plugin %s: Fatal Error Message (PostgreSQL):\n", PLUGIN_NAME_PGSQL);

	/* loop though error message and separate it by tab delimiter. */
	while ((error_token = pppd__strsep(&error_message, (unsigned char *)"\t")) != NULL) {

		/* check if we show first line. */
		if (first == 0) {

			/* show the detailed error. */
			error("Plugin %s: * %s\n", PLUGIN_NAME_PGSQL, error_token);

			/* increase counter. */
			first++;
		} else {

			/* show the detailed error. */
			error("Plugin %s:   %s\n", PLUGIN_NAME_PGSQL, error_token);
		}
	}

	/* if no error was found, return zero. */
	return 0;
}

/* this function return the password from database. */
int32_t pppd__pgsql_password(uint8_t *name, uint8_t *secret_name, int32_t *secret_length) {

	/* some common variables. */
	uint8_t *token_pgsql_uri;
	uint8_t *token_pgsql_host;
	uint8_t *token_pgsql_port;
	uint8_t query[1024];
	uint8_t query_extended[1024];
	uint8_t connection_info[1024];
	int32_t is_null  = 0;
	uint32_t count   = 0;
	uint32_t found   = 0;
	uint8_t *row     = 0;
	uint8_t *field   = NULL;
	PGresult *result = NULL;
	PGconn *pgsql    = NULL;

	/* check if all information are supplied. */
	if (pppd_pgsql_host		== NULL ||
	    pppd_pgsql_user		== NULL ||
	    pppd_pgsql_pass		== NULL ||
	    pppd_pgsql_pass_encryption	== NULL ||
	    pppd_pgsql_database		== NULL ||
	    pppd_pgsql_table		== NULL ||
	    pppd_pgsql_column_user	== NULL ||
	    pppd_pgsql_column_pass	== NULL ||
	    pppd_pgsql_column_ip	== NULL) {

		/* something failed on postgresql initialization. */
		error("Plugin %s: PostgreSQL information are not complete\n", PLUGIN_NAME_PGSQL);

		/* return with error and terminate link. */
		return SQL_ERROR_INCOMPLETE;
	}

	/* loop through all server tokens. */
	while ((token_pgsql_uri = pppd__strsep(&pppd_pgsql_host, (unsigned char *)",")) != NULL) {

		/* extract host and port. */
		token_pgsql_host = pppd__strsep(&token_pgsql_uri, (unsigned char *)":");
		token_pgsql_port = pppd__strsep(&token_pgsql_uri, (unsigned char *)":");

		/* strip away leading and trailing whitespaces. */
		token_pgsql_host = pppd__strstrip(token_pgsql_host);
		token_pgsql_port = pppd__strstrip(token_pgsql_port);

		/* clear connection info from previous connection. */
		memset(connection_info, 0, sizeof(connection_info));

		/* create the connection information for postgresql. */
		snprintf((char *)connection_info, 1024, "host='%s' port='%s' user='%s' password='%s' dbname='%s' connect_timeout='%i'", token_pgsql_host, token_pgsql_port, pppd_pgsql_user, pppd_pgsql_pass, pppd_pgsql_database, pppd_pgsql_connect_timeout);

		/* loop through number of connection retries. */
		for (count = pppd_pgsql_retry_connect; count > 0 ; count--) {

			/* connect to postgresql database. */
			pgsql = PQconnectdb((char *)connection_info);

			/* check if postgresql connection was successfully established. */
			if (PQstatus(pgsql) != CONNECTION_OK) {

				/* check if it was last connection try. */
				if (count == 1) {

					/* something on establishing connection failed. */
					pppd__pgsql_error((uint8_t *)PQerrorMessage(pgsql));
				}
			} else {

				/* found working postgresql server. */
				info("Plugin %s: Using PostgreSQL server %s\n", PLUGIN_NAME_PGSQL, token_pgsql_host);

				/* indicate that we found working postgresql server. */
				found = 1;

				/* found working connection, so break loop. */
				break;
			}
		}

		/* check if we found working postgresql server. */
		if (found == 1) {

			/* found working connection, so break loop. */
			break;
		}
	}

	/* check if no connection was established, very bad :) */
	if (found == 0) {

		/* something on establishing connection failed. */
		error("Plugin %s: No working PostgreSQL server found\n", PLUGIN_NAME_PGSQL);

		/* close the connection. */
		PQfinish(pgsql);

		/* return with error and terminate link. */
		return SQL_ERROR_CONNECT;
	}

	/* build query for database. */
	snprintf((char *)query, 1024, "SELECT %s, %s FROM %s WHERE %s='%s'", pppd_pgsql_column_pass, pppd_pgsql_column_ip, pppd_pgsql_table, pppd_pgsql_column_user, name);

	/* check if we have an additional postgresql condition. */
	if (pppd_pgsql_condition != NULL) {

		/* build extended query for database. */
		snprintf((char *)query_extended, 1024, " AND %s", pppd_pgsql_condition);

		/* only write 1023 bytes, because strncat writes 1023 bytes plus the terminating null byte. */
		strncat((char *)query, (char *)query_extended, 1023);
	}

	/* set successful execution value to zero. */
	found = 0;

	/* loop through number of connection retries. */
	for (count = pppd_pgsql_retry_query; count > 0 ; count--) {

		/* check if query was successfully executed. */
		if ((result = PQexec(pgsql, (char *)query)) != NULL) {

			/* indicate that we fetch a result. */
			found = 1;

			/* query result was ok, so break loop. */
			break;
		}

		/* clear memory to avoid leaks. */
		PQclear(result);
	}

	/* check if no query was executed successfully, very bad :) */
	if (found == 0) {

		/* something on executing query failed. */
		pppd__pgsql_error((uint8_t *)PQerrorMessage(pgsql));

		/* close the connection. */
		PQfinish(pgsql);

		/* return with error and terminate link. */
		return SQL_ERROR_QUERY;
	}

	/* check if postgresql should return data. */
	if (PQnfields(result) == 0) {

		/* something on executing query failed. */
		pppd__pgsql_error((uint8_t *)PQerrorMessage(pgsql));

		/* clear memory to avoid leaks. */
		PQclear(result);

		/* close the connection. */
		PQfinish(pgsql);

		/* return with error and terminate link. */
		return SQL_ERROR_QUERY;
	}

	/* check if we have multiple user accounts. */
	if ((PQntuples(result) > 1) && (pppd_pgsql_ignore_multiple == 0)) {

		/* multiple user accounts found. */
		error("Plugin %s: Multiple accounts for %s found in database\n", PLUGIN_NAME_PGSQL, name);

		/* clear memory to avoid leaks. */
		PQclear(result);

		/* close the connection. */
		PQfinish(pgsql);

		/* return with error and terminate link. */
		return SQL_ERROR_QUERY;
	}

	/* loop through all columns. */
	for (count = 0; count < PQnfields(result); count++) {

		/* fetch postgresql field name. */
		field = (uint8_t *)PQfname(result, count);

		/* fetch NULL information. */
		is_null = PQgetisnull(result, 0, count);

		/* first check what result we should get. */
		if (is_null == 0) {

			/* fetch column. */
			row = (uint8_t *)PQgetvalue(result, 0, count);
		} else {

			/* set row to string NULL. */
			row = (uint8_t *)"NULL";
		}

		/* check if column is NULL. */
		if ((is_null == 1) && (pppd_pgsql_ignore_null == 0)) {

			/* NULL user account found. */
			error("Plugin %s: The column %s for %s is NULL in database\n", PLUGIN_NAME_PGSQL, field, name);

			/* clear the memory with the password, so nobody is able to dump it. */
			memset(secret_name, 0, sizeof(secret_name));

			/* clear memory to avoid leaks. */
			PQclear(result);

			/* close the connection. */
			PQfinish(pgsql);

			/* return with error and terminate link. */
			return SQL_ERROR_QUERY;
		}

		/* check if we found password. */
		if (strcmp((char *)field, (char *)pppd_pgsql_column_pass) == 0) {

			/* cleanup memory. */
			memset(secret_name, 0, sizeof(secret_name));

			/* copy password to secret. */
			strncpy((char *)secret_name, (char *)row, MAXSECRETLEN);
			*secret_length = strlen((char *)secret_name);
		}

		/* check if we found client ip. */
		if (strcmp((char *)field, (char *)pppd_pgsql_column_ip) == 0) {

			/* check if ip address was successfully converted into binary data. */
			if (inet_aton((char *)row, (struct in_addr *) &client_ip) == 0) {

				/* error on converting ip address.*/
				error("Plugin %s: IP address %s is not valid\n", PLUGIN_NAME_PGSQL, row);

				/* clear the memory with the password, so nobody is able to dump it. */
				memset(secret_name, 0, sizeof(secret_name));

				/* clear memory to avoid leaks. */
				PQclear(result);

				/* close the connection. */
				PQfinish(pgsql);

				/* return with error and terminate link. */
				return SQL_ERROR_QUERY;
			}
		}
	}

	/* clear memory to avoid leaks. */
	PQclear(result);

	/* close the connection. */
	PQfinish(pgsql);

	/* if no error was found, return zero. */
	return 0;
}

/* this function check the chap authentication information against a postgresql database. */
int32_t pppd__chap_verify_pgsql(char *name, char *ourname, int id, struct chap_digest_type *digest, unsigned char *challenge, unsigned char *response, char *message, int message_space) {

	/* some common variables. */
	uint8_t secret_name[MAXSECRETLEN];
	int32_t secret_length = 0;
	int32_t ok            = 0;

	/* check if postgresql fetching was successful. */
	if (pppd__pgsql_password((uint8_t *)name, secret_name, &secret_length) < 0) {

		/* return with error and terminate link. */
		return 0;
	}

	/* check the discovered secret against the client's response. */
	ok = digest->verify_response(id, name, secret_name, secret_length, challenge, response, message, message_space);

	/* clear the memory with the password, so nobody is able to dump it. */
	memset(secret_name, 0, sizeof(secret_name));

	/* return status of password verification. */
	return ok;
}

/* this function check the pap authentication information against a postgresql database. */
int32_t pppd__pap_auth_pgsql(char *user, char *passwd, char **msgp, struct wordlist **paddrs, struct wordlist **popts) {

	/* some common variables. */
	uint8_t hash[16];
	uint8_t secret_name[MAXSECRETLEN];
	int32_t secret_length = 0;
	uint32_t count        = 0;
	MD5_CTX ctx;

	/* check if pgsql fetching was successful. */
	if (pppd__pgsql_password((uint8_t *)user, secret_name, &secret_length) < 0) {

		/* return with error and terminate link. */
		return 0;
	}

	/* check if we use no algorithm. */
	if (strcasecmp((char *)pppd_pgsql_pass_encryption, "NONE") == 0) {

		/* check if we found valid password. */
		if (strcmp((char *)passwd, (char *)secret_name) != 0) {

			/* clear the memory with the password, so nobody is able to dump it. */
			memset(secret_name, 0, sizeof(secret_name));

			/* return with error and terminate link. */
			return 0;
		}
	}

	/* check if we use md5 hashing algorithm. */
	if (strcasecmp((char *)pppd_pgsql_pass_encryption, "MD5") == 0) {

		/* check if secret from database is shorter than an expected md5 hash. */
		if (strlen((char *)secret_name) < 32) {

			/* clear the memory with the hash, so nobody is able to dump it. */
			memset(secret_name, 0, sizeof(secret_name));

			/* return with error and terminate link. */
			return 0;
		}

		/* compute md5 hash. */
		MD5_Init(&ctx);
		MD5_Update(&ctx, passwd, strlen(passwd));
		MD5_Final(hash, &ctx);

		/* loop through every byte and compare it. */
		for (count = 0; count < (strlen((char *)secret_name) / 2); count++) {

			/* check if our hex value matches the hash byte. (this isn't the fastest way, but hash is everytime 16 byte) */
			if (htoi(secret_name[2 * count]) * 16 + htoi(secret_name[2 * count + 1]) != hash[count]) {

				/* clear the memory with the hash, so nobody is able to dump it. */
				memset(secret_name, 0, sizeof(secret_name));
				memset(hash, 0, sizeof(hash));

				/* return with error and terminate link. */
				return 0;
			}
		}
	}

	/* if no error was found, establish link. */
	return 1;
}
