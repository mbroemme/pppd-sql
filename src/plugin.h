/*
 *  plugin.h -- Challenge Handshake Authentication Protocol for the
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

#ifndef _PLUGIN_H
#define _PLUGIN_H

/* generic includes. */
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

/* define errors. */
#define SQL_ERROR_INCOMPLETE		-1	/* the supplied sql information from configuration file are not complete. */
#define SQL_ERROR_INIT			-2	/* the initialization of the sql structure failed. */
#define SQL_ERROR_OPTION		-3	/* some unknown sql options were given. */
#define SQL_ERROR_CONNECT		-4	/* none of the supplied sql servers are working. */
#define SQL_ERROR_QUERY			-5	/* the given sql query failed. */

/* define constants. */
#define SIZE_MD5			16	/* the size of a MD5 hash. */
#define SIZE_CRYPT			13	/* the size of the crypt() DES result. */

/* client ip address must be stored in global variable, because at IPCP time
 * we no longer know the username.
 */
extern uint32_t client_ip;

/* this function set whether the peer must authenticate itself to us via CHAP. */
int32_t pppd__chap_check(
	void
);

/* this function set whether the peer must authenticate itself to us via PAP. */
int32_t pppd__pap_check(
	void
);

/* this function will look for a valid client ip address. */
void pppd__ip_choose(
	uint32_t	*addrp
);

/* this function set whether the plugin is allowed to set client ip addresses. */
int32_t pppd__allowed_address(
	uint32_t	addr
);

#endif					/* _PLUGIN_H */
