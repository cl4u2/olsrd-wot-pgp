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

#include "ip_to_email_map.h" 
int ip2email_key_cmp(ip2email_map_key_t key1, ip2email_map_key_t key2);
void ip2email_map_init(struct ip2email_map_node *node);
void ip2email_map_insert(struct ip2email_map_node *headnode, ip2email_map_key_t key, ip2email_map_value_t value);

int 
ip2email_key_cmp(ip2email_map_key_t key1, ip2email_map_key_t key2)
{ /* Compare keys and return 0 if keys are not equal */
	return key1 == key2; 
}

void 
ip2email_map_init(struct ip2email_map_node *node)
{
		node->key = I2E_NULL_KEY;
		node->value = I2E_NULL_VALUE;
		node->next = NULL;
}

struct ip2email_map_node * 
ip2email_map_new(void)
{
		struct ip2email_map_node *newnode;
		newnode = (struct ip2email_map_node *) malloc(sizeof(struct ip2email_map_node));
		ip2email_map_init(newnode);
		return newnode;
}

void 
ip2email_map_insert(struct ip2email_map_node *headnode, ip2email_map_key_t key, ip2email_map_value_t value)
{
		struct ip2email_map_node *curnode;
		/* find the last node */
		curnode = headnode;
		while(curnode->next != NULL)
				curnode = curnode->next;
		curnode->next = ip2email_map_new();
		curnode->next->key = key;
		curnode->next->value = value;
}

ip2email_map_value_t 
ip2email_map_lookup(struct ip2email_map_node *headnode, ip2email_map_key_t key)
{
		struct ip2email_map_node *curnode;
		for(curnode = headnode; curnode != NULL; curnode = curnode->next)
				if(ip2email_key_cmp(curnode->key, key))
						return curnode->value;

		/* key not found */
		return I2E_NULL_VALUE;
}

void 
ip2email_map_update(struct ip2email_map_node *headnode, ip2email_map_key_t key, ip2email_map_value_t value)
{
		struct ip2email_map_node *curnode;
		for(curnode = headnode; curnode != NULL; curnode = curnode->next)
				if(ip2email_key_cmp(curnode->key, key)) {
						curnode->value = value;
						return;
				}
		/* key not found */
		ip2email_map_insert(headnode, key, value);
}

ip2email_map_key_t 
ip2email_map_delete(struct ip2email_map_node *headnode, int key)
{
		struct ip2email_map_node *curnode;
		struct ip2email_map_node *nextnode;
		struct ip2email_map_node *nextnextnode;
		curnode = headnode;
		while(curnode != NULL){
				nextnode = curnode->next;
				if(nextnode != NULL && ip2email_key_cmp(nextnode->key, key))
				{
					nextnextnode = nextnode->next;
					//free(nextnode->key);
					free(nextnode->value);
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
ip2email_map_destroy(struct ip2email_map_node *map)
{
		struct ip2email_map_node *curnode;
		struct ip2email_map_node *nextnode;
		curnode = map;
		while(curnode != NULL){
				nextnode = curnode->next;
				//free(curnode->key);
				free(curnode->value);
				free(curnode);
				curnode = nextnode;
		}

}

