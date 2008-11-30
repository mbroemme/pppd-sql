/*
 *  plugin-mysql.h -- MySQL Authentication plugin for Point-to-Point
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

#ifndef _PLUGIN_MYSQL_H
#define _PLUGIN_MYSQL_H

/* configuration includes. */
#include "config.h"

/* autoconf declares VERSION which is declared in pppd.h too. */
#ifdef VERSION
#undef VERSION
#endif

/* generic includes. */
#include <stdint.h>

/* ppp includes. */
#include <pppd/chap-new.h>
#include <pppd/md5.h>
#include <pppd/pppd.h>

/* mysql includes. */
#include <mysql/mysql.h>

/* global define to indicate that plugin only works with compile time pppd. */
extern uint8_t pppd_version[];

/* global configuration variables. */
extern uint8_t *pppd_mysql_host;
extern uint8_t *pppd_mysql_user;
extern uint8_t *pppd_mysql_pass;
extern uint8_t *pppd_mysql_pass_encryption;
extern uint8_t *pppd_mysql_pass_key;
extern uint8_t *pppd_mysql_database;
extern uint8_t *pppd_mysql_table;
extern uint8_t *pppd_mysql_column_user;
extern uint8_t *pppd_mysql_column_pass;
extern uint8_t *pppd_mysql_column_ip;
extern uint8_t *pppd_mysql_condition;
extern uint32_t pppd_mysql_ignore_multiple;
extern uint32_t pppd_mysql_ignore_null;
extern uint32_t pppd_mysql_connect_timeout;
extern uint32_t pppd_mysql_retry_connect;
extern uint32_t pppd_mysql_retry_query;

/* extra option structure. */
extern option_t options[];

/* plugin initialization routine. */
void plugin_init(
	void
);

#endif					/* _PLUGIN_MYSQL_H */
