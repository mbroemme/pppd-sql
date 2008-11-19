/*
 *  plugin-mysql.c -- MySQL Authentication plugin for Point-to-Point
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
#include "plugin-mysql.h"

/* plugin chap includes. */
#include "chap.h"
#include "chap-mysql.h"

/* global define to indicate that plugin only works with compile time pppd. */
uint8_t pppd_version[]			= VERSION;

/* global configuration variables. */
uint8_t *pppd_mysql_host		= NULL;
uint8_t *pppd_mysql_user		= NULL;
uint8_t *pppd_mysql_pass		= NULL;
uint8_t *pppd_mysql_database		= NULL;
uint8_t *pppd_mysql_table		= NULL;
uint8_t *pppd_mysql_column_user		= NULL;
uint8_t *pppd_mysql_column_pass		= NULL;
uint8_t *pppd_mysql_column_ip		= NULL;
uint8_t *pppd_mysql_condition		= NULL;
uint32_t pppd_mysql_ignore_multiple	= 0;
uint32_t pppd_mysql_ignore_null		= 0;
uint32_t pppd_mysql_connect_timeout	= 5;
uint32_t pppd_mysql_retry_connect	= 5;
uint32_t pppd_mysql_retry_query		= 5;

/* client ip address must be stored in global variable, because at IPCP time
 * we no longer know the username.
 */
uint32_t client_ip			= 0;

/* extra option structure. */
option_t options[] = {
	{ "mysql-host", o_string, &pppd_mysql_host, "Set MySQL server host"},
	{ "mysql-user", o_string, &pppd_mysql_user, "Set MySQL username"},
	{ "mysql-pass", o_string, &pppd_mysql_pass, "Set MySQL password"},
	{ "mysql-database", o_string, &pppd_mysql_database, "Set MySQL database name"},
	{ "mysql-table", o_string, &pppd_mysql_table, "Set MySQL authentication table"},
	{ "mysql-column-user", o_string, &pppd_mysql_column_user, "Set MySQL username field"},
	{ "mysql-column-pass", o_string, &pppd_mysql_column_pass, "Set MySQL password field"},
	{ "mysql-column-ip", o_string, &pppd_mysql_column_ip, "Set MySQL client ip address field"},
	{ "mysql-condition", o_string, &pppd_mysql_condition, "Set MySQL condition clause"},
	{ "mysql-ignore-multiple", o_bool, &pppd_mysql_ignore_multiple, "Set MySQL to cover first row from multiple rows", 0 | 1},
	{ "mysql-ignore-null", o_bool, &pppd_mysql_ignore_null, "Set MySQL to cover NULL results as string", 0 | 1},
	{ "mysql-connect-timeout", o_int, &pppd_mysql_connect_timeout, "Set MySQL connection timeout"},
	{ "mysql-retry-connect", o_int, &pppd_mysql_retry_connect, "Set MySQL connection retries"},
	{ "mysql-retry-query", o_int, &pppd_mysql_retry_query, "Set MySQL query retries"},
	{ NULL }
};

/* plugin initilization routine. */
void plugin_init(void) {

	/* show initialization information. */
	info("Plugin %s: pppd-sql-%s initialized, compiled pppd-%s, linked mysql-%s\n", PLUGIN_NAME_MYSQL, PACKAGE_VERSION, pppd_version, PLUGIN_VERSION_MYSQL);

	/* add hook for chap authentication. */
	chap_check_hook		= pppd__chap_check;
	chap_verify_hook	= pppd__chap_verify_mysql;

	/* plugin is aware of assigning ip addresses on IPCP negotiation. */
	ip_choose_hook		= pppd__ip_choose;
	allowed_address_hook	= pppd__allowed_address;

	/* point extra options to our array. */
	add_options(options);
}
