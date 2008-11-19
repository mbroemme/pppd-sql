/*
 *  chap.c -- Challenge Handshake Authentication Protocol for the
 *            Point-to-Point Protocol (PPP) shared functions.
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

/* plugin includes. */
#include "chap.h"

/* this function will look for a valid client ip address. */
void pppd__ip_choose(uint32_t *addrp) {

	/* set ip address to client one fetched from database. */
	*addrp = client_ip;
}

/* this function set whether the peer must authenticate itself to us. */
int32_t pppd__chap_check(void) {

	/* return one, because we need to ask peer everytime for authentication. */
	return 1;
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
