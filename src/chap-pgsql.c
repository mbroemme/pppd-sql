/*
 *  chap-pgsql.c -- Challenge Handshake Authentication Protocol for the
 *                  Point-to-Point Protocol (PPP) via PostgreSQL.
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
#include <string.h>

/* generic plugin includes. */
#include "plugin-pgsql.h"
#include "str.h"

/* chap plugin includes. */
#include "chap-pgsql.h"

/* this function check the chap authentication information against a postgresql database. */
int32_t pppd__chap_verify_pgsql(char *name, char *ourname, int id, struct chap_digest_type *digest, unsigned char *challenge, unsigned char *response, char *message, int message_space) {

	/* some common variables. */
	uint8_t *token_pgsql_uri;
	uint8_t *token_pgsql_host;
	uint8_t *token_pgsql_port;
	uint8_t connection_info[1024];
	uint32_t count		= 0;
	uint32_t found		= 0;
	PGconn *pgsql		= NULL;

	/* check if all information are supplied. */
	if (pppd_pgsql_host		== NULL ||
	    pppd_pgsql_database		== NULL ||
	    pppd_pgsql_user		== NULL ||
	    pppd_pgsql_pass		== NULL ||
	    pppd_pgsql_table		== NULL ||
	    pppd_pgsql_column_user	== NULL ||
	    pppd_pgsql_column_pass	== NULL ||
	    pppd_pgsql_column_ip	== NULL) {

		/* something failed on mysql initialization. */
		error("Plugin %s: The PostgreSQL information are not complete\n", PLUGIN_NAME_PGSQL);

		/* return with error and terminate link. */
		return 0;
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
		snprintf((char *)connection_info, 1024, "host='%s' port='%s' user='%s' pass='%s' dbname='%s' connect_timeout='%i'", token_pgsql_host, token_pgsql_port, pppd_pgsql_user, pppd_pgsql_pass, pppd_pgsql_database, pppd_pgsql_connect_timeout);

		/* loop through number of connection retries. */
		for (count = pppd_pgsql_retry_connect; count > 0 ; count--) {

			/* connect to postgresql database. */
			pgsql = PQconnectdb((char *)connection_info);

			/* check if postgresql connection was successfully established. */
			if (PQstatus(pgsql) != CONNECTION_OK) {

				/* check if it was last connection try. */
				if (count == 1) {

					/* something on establishing connection failed. */
					warn("Plugin %s: Warning PostgreSQL server %s not working\n", PLUGIN_NAME_PGSQL, token_pgsql_host);
				}
			} else {

				/* found working postgresql server. */
				info("Plugin %s: Using PostgreSQL server %s\n", PLUGIN_NAME_PGSQL, token_pgsql_host);

				/* indicate that we found working mysql server. */
				found = 1;

				/* found working connection, so break loop. */
				break;
			}
		}

		/* check if we found working mysql server. */
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
		return 0;
	}

	/* return status of password verification. */
	return 0;
}
