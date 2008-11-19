/*
 * Web of Trust OLSR plugin
 *
 * Copyright (c) 2008 by Claudio Pisa (clauz at ninux dot org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or 
 * without modification, are permitted provided that the following 
 * conditions are met:
 *
 * * Redistributions of source code must retain the above copyright 
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright 
 *   notice, this list of conditions and the following disclaimer in 
 *   the documentation and/or other materials provided with the 
 *   distribution.
 * * The name of the author may not be used to endorse or promote 
 *   products derived from this software without specific prior written 
 *   permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Simple but slow linear-search map.
 * From an IP prefix find the associated trust value. 
 *
 */


#ifndef _OLSRD_WOT_PREFIX_TO_TRUST_MAP
#define _OLSRD_WOT_PREFIX_TO_TRUST_MAP

#include <stdlib.h>
#include "olsr_types.h"
#include "defs.h"
#include "routing_table.h"
#include <string.h>
#include <gpgme.h>

typedef struct olsr_ip_prefix * pfx2trust_map_key_t;
typedef gpgme_validity_t pfx2trust_map_value_t;

#define P2T_KEYSIZE sizeof(struct olsr_ip_prefix) 
#define P2T_NULL_KEY NULL 
#define P2T_NULL_VALUE GPGME_VALIDITY_UNDEFINED 

struct pfx2trust_map_node
{
		pfx2trust_map_key_t key;
		pfx2trust_map_value_t value;
		struct pfx2trust_map_node *next;
};

/* new map */
struct pfx2trust_map_node *pfx2trust_map_new(void);

/* update key-value association */
void pfx2trust_map_update(struct pfx2trust_map_node *map, pfx2trust_map_key_t key, pfx2trust_map_value_t value);

/* lookup value from key */
pfx2trust_map_value_t pfx2trust_map_lookup(struct pfx2trust_map_node *map, pfx2trust_map_key_t key);

/* delete value from key */
int pfx2trust_map_delete(struct pfx2trust_map_node *map, pfx2trust_map_key_t key);

/* destroy map */
void pfx2trust_map_destroy(struct pfx2trust_map_node *map);

#endif
