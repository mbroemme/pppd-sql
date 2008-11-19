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

	/* return status of password verification. */
	return 0;
}
