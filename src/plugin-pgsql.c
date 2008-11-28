/*
 *  plugin-pgsql.c -- PostgreSQL Authentication plugin for Point-to-Point
 *                    Protocol (PPP).
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

/* generic plugin includes. */
#include "plugin.h"
#include "plugin-pgsql.h"

/* plugin auth includes. */
#include "auth-pgsql.h"

/* global define to indicate that plugin only works with compile time pppd. */
uint8_t pppd_version[]			= VERSION;

/* global configuration variables. */
uint8_t *pppd_pgsql_host		= NULL;
uint8_t *pppd_pgsql_user		= NULL;
uint8_t *pppd_pgsql_pass		= NULL;
uint8_t *pppd_pgsql_database		= NULL;
uint8_t *pppd_pgsql_table		= NULL;
uint8_t *pppd_pgsql_column_user		= NULL;
uint8_t *pppd_pgsql_column_pass		= NULL;
uint8_t *pppd_pgsql_column_ip		= NULL;
uint8_t *pppd_pgsql_condition		= NULL;
uint32_t pppd_pgsql_ignore_multiple	= 0;
uint32_t pppd_pgsql_ignore_null		= 0;
uint32_t pppd_pgsql_connect_timeout	= 5;
uint32_t pppd_pgsql_retry_connect	= 5;
uint32_t pppd_pgsql_retry_query		= 5;

/* client ip address must be stored in global variable, because at IPCP time
 * we no longer know the username.
 */
uint32_t client_ip			= 0;

/* extra option structure. */
option_t options[] = {
	{ "pgsql-host", o_string, &pppd_pgsql_host, "Set PostgreSQL server host"},
	{ "pgsql-user", o_string, &pppd_pgsql_user, "Set PostgreSQL username"},
	{ "pgsql-pass", o_string, &pppd_pgsql_pass, "Set PostgreSQL password"},
	{ "pgsql-pass-encryption", o_string, &pppd_pgsql_pass_encryption, "Set PostgreSQL password encryption algorithm"},
	{ "pgsql-database", o_string, &pppd_pgsql_database, "Set PostgreSQL database name"},
	{ "pgsql-table", o_string, &pppd_pgsql_table, "Set PostgreSQL authentication table"},
	{ "pgsql-column-user", o_string, &pppd_pgsql_column_user, "Set PostgreSQL username field"},
	{ "pgsql-column-pass", o_string, &pppd_pgsql_column_pass, "Set PostgreSQL password field"},
	{ "pgsql-column-ip", o_string, &pppd_pgsql_column_ip, "Set PostgreSQL client ip address field"},
	{ "pgsql-condition", o_string, &pppd_pgsql_condition, "Set PostgreSQL condition clause"},
	{ "pgsql-ignore-multiple", o_bool, &pppd_pgsql_ignore_multiple, "Set PostgreSQL to cover first row from multiple rows", 0 | 1},
	{ "pgsql-ignore-null", o_bool, &pppd_pgsql_ignore_null, "Set PostgreSQL to cover NULL results as string", 0 | 1},
	{ "pgsql-connect-timeout", o_int, &pppd_pgsql_connect_timeout, "Set PostgreSQL connection timeout"},
	{ "pgsql-retry-connect", o_int, &pppd_pgsql_retry_connect, "Set PostgreSQL connection retries"},
	{ "pgsql-retry-query", o_int, &pppd_pgsql_retry_query, "Set PostgreSQL query retries"},
	{ NULL }
};

/* plugin initilization routine. */
void plugin_init(void) {

	/* show initialization information. */
	info("Plugin %s: pppd-sql-%s initialized, compiled pppd-%s, linked pgsql-%s\n", PLUGIN_NAME_PGSQL, PACKAGE_VERSION, pppd_version, PLUGIN_VERSION_PGSQL);

	/* add hook for chap authentication. */
	chap_check_hook		= pppd__chap_check;
	chap_verify_hook	= pppd__chap_verify_pgsql;

	/* add hook for pap authentication. */
	pap_check_hook		= pppd__pap_check;
	pap_auth_hook		= pppd__pap_auth_pgsql;

	/* plugin is aware of assigning ip addresses on IPCP negotiation. */
	ip_choose_hook		= pppd__ip_choose;
	allowed_address_hook	= pppd__allowed_address;

	/* point extra options to our array. */
	add_options(options);
}
