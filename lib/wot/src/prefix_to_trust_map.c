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

#include "prefix_to_trust_map.h" 

int pfx2trust_key_cmp(pfx2trust_map_key_t key1, pfx2trust_map_key_t key2);
void pfx2trust_key_copy(pfx2trust_map_key_t *key1, pfx2trust_map_key_t key2);
void pfx2trust_map_init(struct pfx2trust_map_node *node);
void pfx2trust_map_insert(struct pfx2trust_map_node *headnode, pfx2trust_map_key_t key, pfx2trust_map_value_t value);

#ifdef DEBUG
void printkey(pfx2trust_map_key_t key);

void 
printkey(pfx2trust_map_key_t key)
{
	printf("[WOT] key prefix: %x length: %x\n", key->prefix.v4.s_addr, key->prefix_len);
}
#endif

int pfx2trust_key_cmp(pfx2trust_map_key_t key1, pfx2trust_map_key_t key2)
{ /* Compare keys and return 0 if keys are not equal */
  /* TODO: make this function IPv6-aware */
		int ret = 1;

		if(key1 == NULL || key2 == NULL)
				return 0;

#ifdef DEBUG
		printkey(key1);
		printkey(key2);
#endif

		ret = ret && (key1->prefix_len == key2->prefix_len);
		ret = ret && (key1->prefix.v4.s_addr == key2->prefix.v4.s_addr);

		return ret; 
}

void pfx2trust_key_copy(pfx2trust_map_key_t *key1, pfx2trust_map_key_t key2)
{
		/* Make a copy of key2 in key1 */
		if(key2 == NULL) {*key1 = NULL; return;}

		*key1 = (pfx2trust_map_key_t) malloc(P2T_KEYSIZE);  

		memmove(*key1, key2, P2T_KEYSIZE);

#ifdef DEBUG
		printkey(*key1);
		printkey(key2);
		if(pfx2trust_key_cmp(*key1, key2)) 
			printf("copy OK\n");
		else
			printf("copy NOT ok\n");
#endif
}

void 
pfx2trust_map_init(struct pfx2trust_map_node *node)
{
		node->key = P2T_NULL_KEY;
		node->value = P2T_NULL_VALUE;
		node->next = NULL;
}

struct pfx2trust_map_node * 
pfx2trust_map_new(void)
{
		struct pfx2trust_map_node *newnode;
		newnode = (struct pfx2trust_map_node *) malloc(sizeof(struct pfx2trust_map_node));
		pfx2trust_map_init(newnode);
		return newnode;
}

void 
pfx2trust_map_insert(struct pfx2trust_map_node *headnode, pfx2trust_map_key_t key, pfx2trust_map_value_t value)
{
		struct pfx2trust_map_node *curnode;
		/* find the last node */
		curnode = headnode;
		while(curnode->next != NULL)
				curnode = curnode->next;
		curnode->next = pfx2trust_map_new();
		pfx2trust_key_copy(&curnode->next->key, key);
		curnode->next->value = value;

#ifdef DEBUG
		printf("[WOT] inserted...\n");
		if(pfx2trust_key_cmp(curnode->next->key, key)) 
			printf("insertion OK\n");
		else
			printf("insertion NOT ok\n");
#endif

}

pfx2trust_map_value_t 
pfx2trust_map_lookup(struct pfx2trust_map_node *headnode, pfx2trust_map_key_t key)
{
		struct pfx2trust_map_node *curnode;
#ifdef DEBUG
		printf("[WOT] Looking up... \n");
		printkey(key);
#endif
		if(headnode == NULL) printf("WTF?!\n");
		if(key == P2T_NULL_KEY) printf("WTFK?!\n");

		curnode = headnode;
		while(curnode != NULL)
		{
			if(pfx2trust_key_cmp(curnode->key, key))
				return curnode->value;
			curnode = curnode->next;
		}

#ifdef DEBUG
		printf("[WOT] Key not found... \n");
#endif
		/* key not found */
		return P2T_NULL_VALUE;
}

void 
pfx2trust_map_update(struct pfx2trust_map_node *headnode, pfx2trust_map_key_t key, pfx2trust_map_value_t value)
{
		struct pfx2trust_map_node *curnode;
#ifdef DEBUG
		printf("[WOT] updating ... ");
		printf("prefix: %x len: %x ", key->prefix.v4.s_addr, key->prefix_len);
		printf("value: %d\n", value);
#endif
		for(curnode = headnode; curnode != NULL; curnode = curnode->next)
				if(pfx2trust_key_cmp(curnode->key, key)) {
						curnode->value = value;
						return;
				}
		/* key not found */
		pfx2trust_map_insert(headnode, key, value);
#ifdef DEBUG
		printf("[WOT] updated...\n");
#endif
}

int
pfx2trust_map_delete(struct pfx2trust_map_node *headnode, pfx2trust_map_key_t key)
{
		struct pfx2trust_map_node *curnode;
		struct pfx2trust_map_node *nextnode;
		struct pfx2trust_map_node *nextnextnode;
		curnode = headnode;
		while(curnode != NULL){
				nextnode = curnode->next;
				if(nextnode != NULL && pfx2trust_key_cmp(nextnode->key, key))
				{
					nextnextnode = nextnode->next;
					free(nextnode->key);
					//free(nextnode->value);
					free(nextnode);
					curnode->next = nextnextnode;
					return 0;
				} else {
					curnode = nextnode;
				}
		}
		return 1;
}

void 
pfx2trust_map_destroy(struct pfx2trust_map_node *map)
{
		struct pfx2trust_map_node *curnode;
		struct pfx2trust_map_node *nextnode;
		curnode = map;
		while(curnode != NULL){
				nextnode = curnode->next;
				free(curnode->key);
				//free(curnode->value);
				free(curnode);
				curnode = nextnode;
		}

}

