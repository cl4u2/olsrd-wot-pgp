/*
 * OLSR ad-hoc routing table management protocol
 * Copyright (C) 2004 Andreas T�nnesen (andreto@ifi.uio.no)
 *
 * This file is part of olsrd-unik.
 *
 * UniK olsrd is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * UniK olsrd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with olsrd-unik; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#ifndef _OLSR_HASHING
#define _OLSR_HASHING

#define	HASHSIZE	32
#define	HASHMASK	(HASHSIZE - 1)

extern int ipversion;

olsr_u32_t
olsr_hashing(union olsr_ip_addr *);


#endif
