/*
 * Copyright (c) 2005, Bruno Randolf <bruno.randolf@4g-systems.biz>
 * Copyright (c) 2004, Andreas T�nnesen(andreto-at-olsr.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * * Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice, 
 *   this list of conditions and the following disclaimer in the documentation 
 *   and/or other materials provided with the distribution.
 * * Neither the name of the UniK olsr daemon nor the names of its contributors 
 *   may be used to endorse or promote products derived from this software 
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* $Id: nameservice.c,v 1.9 2005/03/13 22:25:05 br1 Exp $ */

/*
 * Dynamic linked library for UniK OLSRd
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "nameservice.h"
#include "olsrd_copy.h"


/* send buffer: huge */
static char buffer[10240];

/* config parameters */
static char my_filename[MAX_FILE + 1];
static char my_add_hosts[MAX_FILE + 1];
static char my_suffix[MAX_SUFFIX];
int my_interval = EMISSION_INTERVAL;
double my_timeout = NAME_VALID_TIME;

/* the database (using hashing) */
struct db_entry* list[HASHSIZE];
struct name_entry *my_names = NULL;
olsr_bool name_table_changed = OLSR_TRUE;


/**
 * do initialization
 */
void
name_constructor() 
{
	int i;
	
#ifdef WIN32
	int len;

	GetWindowsDirectory(my_filename, MAX_FILE - 12);

	len = strlen(my_filename);
 
	if (my_filename[len - 1] != '\\')
 		my_filename[len++] = '\\';
 
	strcpy(my_filename + len, "hosts_olsr");
#else
	strcpy(my_filename, "/var/run/hosts_olsr");
#endif

	my_suffix[0] = '\0';
	my_add_hosts[0] = '\0';
	
	/* init list */
	for(i = 0; i < HASHSIZE; i++) {
		list[i] = NULL;
	}
}


/**
 * called for all plugin parameters
 */
int
register_olsr_param(char *key, char *value)
{
	if(!strcmp(key, "name")) {
		// name for main address
		struct name_entry *tmp;
		tmp = malloc(sizeof(struct name_entry));
		tmp->name = strndup( value, MAX_NAME );
		tmp->len = strlen( tmp->name );
		tmp->type = NAME_HOST;
		// will be set to main_addr later
		memset(&tmp->ip, 0, sizeof(tmp->ip));
		tmp->next = my_names;
		my_names = tmp;
		
		printf("\nNAME PLUGIN: parameter name: %s (main address)\n", tmp->name);
	} 
	else if(!strcmp(key, "filename")) {
		strncpy( my_filename, value, MAX_FILE );
		printf("\nNAME PLUGIN: parameter filename: %s\n", my_filename);
	}
	else if(!strcmp(key, "interval")) {
		my_interval = atoi(value);
		printf("\nNAME PLUGIN: parameter interval: %d\n", my_interval);
	}
	else if(!strcmp(key, "timeout")) {
		my_timeout = atof(value);
		printf("\nNAME PLUGIN: parameter timeout: %f\n", my_timeout);
	}
	else if(!strcmp(key, "suffix")) {
		strncpy(my_suffix, value, MAX_SUFFIX);
		printf("\nNAME PLUGIN: parameter suffix: %s\n", my_suffix);
	}
	else if(!strcmp(key, "addhosts")) {
		strncpy(my_add_hosts, value, MAX_FILE);
		printf("\nNAME PLUGIN: parameter additional host: %s\n", my_add_hosts);
	}
	else {
		// assume this is an IP address and hostname
		struct in_addr ip;
		
		if (inet_aton(key, &ip)) {
			// the IP is validated later
			struct name_entry *tmp;
			tmp = malloc(sizeof(struct name_entry));
			tmp->name = strndup( value, MAX_NAME );
			tmp->len = strlen( tmp->name );
			tmp->type = NAME_HOST;
			tmp->ip.v4 = ip.s_addr;
			tmp->next = my_names;
			my_names = tmp;
			printf("\nNAME PLUGIN: parameter %s (%s)\n", tmp->name,
				olsr_ip_to_string(&tmp->ip));
		} 
		else {
			printf("\nNAME PLUGIN: invalid IP %s, fix your config!\n", key);
		}
	}

	return 1;
}


/**
 * last initialization
 *
 * we have to do this here because some things like main_addr 
 * are not known before
 *
 * this is beause of the order in which the plugin is initzalized 
 * by the plugin loader:
 *   - first the parameters are sent
 *   - then register_olsr_data() from olsrd_plugin.c is called
 *     which sets up main_addr and some other variables
 *   - register_olsr_data() then then finally calls this function
 */
int
olsr_plugin_init()
{
	struct name_entry *name;
	struct name_entry *prev=NULL;

	/* fixup names and IP addresses */
	for (name = my_names; name != NULL; name = name->next) {
		if (name->ip.v4 == 0) {
			// insert main_addr
			memcpy(&name->ip, main_addr, ipsize);
			prev = name;
		} else {
			// IP from config file
			// check if we are allowed to announce a name for this IP
			// we can only do this if we also announce the IP
			 
			if (!allowed_ip(&name->ip)) {
				olsr_printf(1, "NAME PLUGIN: name for unknown IP %s not allowed, fix your config!\n", 
					olsr_ip_to_string(&name->ip));
				if (prev!=NULL) {
					prev->next = name->next;
					free(name->name);
					free(name);
				}
			}
			else {
				prev = name;
			}
		}
	}
	
	/* register functions with olsrd */
	olsr_parser_add_function(&olsr_parser, PARSER_TYPE, 1);
	olsr_register_timeout_function(&olsr_timeout);
	olsr_register_scheduler_event(&olsr_event, NULL, my_interval, 0, NULL);

	return 1;
}


/**
 * called at unload: free everything
 */
void
olsr_plugin_exit()
{
	int i;
	struct db_entry **tmp;
	struct db_entry *to_delete;
	
	olsr_printf(2, "NAME PLUGIN: exit. cleaning up...\n");
	
	free_name_entry_list(&my_names);
	
	/* free list entries */
	for(i = 0; i < HASHSIZE; i++)
	{
		tmp = &list[i];
		while(*tmp != NULL)
		{
			to_delete = *tmp;
			*tmp = (*tmp)->next;
			free_name_entry_list(&to_delete->names);
			free(to_delete);
			to_delete = NULL;
		}
	}
}


/**
 * A timeout function called every time
 * the scheduler is polled: time out old list entries
 */
void
olsr_timeout()
{
	struct db_entry **tmp;
	struct db_entry *to_delete;
	int index;

	for(index=0;index<HASHSIZE;index++)
	{
		for (tmp = &list[index]; *tmp != NULL; )
		{
			/* check if the entry is timed out */
			if (olsr_timed_out(&(*tmp)->timer))
			{
				to_delete = *tmp;
				*tmp = (*tmp)->next;
				
				olsr_printf(2, "NAME PLUGIN: %s timed out... deleting\n", 
					olsr_ip_to_string(&to_delete->originator));
	
				/* Delete */
				free_name_entry_list(&to_delete->names);
				free(to_delete);
				name_table_changed = OLSR_TRUE;
			} else {
				tmp = &(*tmp)->next;
			}
		}
	}
	write_name_table();
}


/**
 * Scheduled event: generate and send NAME packet
 */
void
olsr_event(void *foo)
{
	union olsr_message *message = (union olsr_message*)buffer;
	struct interface *ifn;
	int namesize;
  
	/* looping trough interfaces */
	for (ifn = ifs; ifn ; ifn = ifn->int_next) 
	{
		olsr_printf(3, "NAME PLUGIN: Generating packet - [%s]\n", ifn->int_name);

		/* fill message */
		if(ipversion == AF_INET)
		{
			/* IPv4 */
			message->v4.olsr_msgtype = MESSAGE_TYPE;
			message->v4.olsr_vtime = double_to_me(my_timeout);
			memcpy(&message->v4.originator, main_addr, ipsize);
			message->v4.ttl = MAX_TTL;
			message->v4.hopcnt = 0;
			message->v4.seqno = htons(get_msg_seqno());
			
			namesize = encap_namemsg((struct namemsg*)&message->v4.message);
			namesize = namesize + sizeof(struct olsrmsg);
			
			message->v4.olsr_msgsize = htons(namesize);
		}
		else
		{
			/* IPv6 */
			message->v6.olsr_msgtype = MESSAGE_TYPE;
			message->v6.olsr_vtime = double_to_me(my_timeout);
			memcpy(&message->v6.originator, main_addr, ipsize);
			message->v6.ttl = MAX_TTL;
			message->v6.hopcnt = 0;
			message->v6.seqno = htons(get_msg_seqno());
			
			namesize = encap_namemsg((struct namemsg*)&message->v6.message);
			namesize = namesize + sizeof(struct olsrmsg6);
			
			message->v6.olsr_msgsize = htons(namesize);
		}
		
		if(net_outbuffer_push(ifn, (olsr_u8_t *)message, namesize) != namesize ) {
			/* send data and try again */
			net_output(ifn);
			if(net_outbuffer_push(ifn, (olsr_u8_t *)message, namesize) != namesize ) {
				olsr_printf(1, "NAME PLUGIN: could not send on interface: %s\n", ifn->int_name);
			}
		}
	}
}


/**
 * Parse name olsr message of NAME type
 */
void
olsr_parser(union olsr_message *m, struct interface *in_if, union olsr_ip_addr *in_addr)
{
	struct namemsg *namemessage;
	union olsr_ip_addr originator;
	double vtime;
	int size;

	/* Fetch the originator of the messsage */
	memcpy(&originator, &m->v4.originator, ipsize);
		
	/* Fetch the message based on IP version */
	if(ipversion == AF_INET) {
		vtime = me_to_double(m->v4.olsr_vtime);
		size = ntohs(m->v4.olsr_msgsize);
		namemessage = (struct namemsg*)&m->v4.message;
	}
	else {
		vtime = me_to_double(m->v6.olsr_vtime);
		size = ntohs(m->v6.olsr_msgsize);
		namemessage = (struct namemsg*)&m->v4.message;
	}

	/* Check if message originated from this node. 
	If so - back off */
	if(memcmp(&originator, main_addr, ipsize) == 0)
		return;

	/* Check that the neighbor this message was received from is symmetric. 
	If not - back off*/
	if(check_neighbor_link(in_addr) != SYM_LINK) {
		olsr_printf(3, "NAME PLUGIN: Received msg from NON SYM neighbor %s\n", olsr_ip_to_string(in_addr));
		return;
	}

	/* Check if this message has been processed before
	* Remeber that this also registeres the message as
	* processed if nessecary
	*/
	if(!check_dup_proc(&originator, ntohs(m->v4.seqno))) {
		/* If so - do not process */
		goto forward;
	}

	update_name_entry(&originator, namemessage, size, vtime);

forward:
	/* Forward the message if nessecary
	* default_fwd does all the work for us! */
	default_fwd(m, &originator, ntohs(m->v4.seqno), in_if, in_addr);
}


/**
 * Encapsulate a name message into a packet. 
 *
 * It assumed that there is enough space in the buffer to do this!
 *
 * Returns: the length of the message that was appended
 */
int
encap_namemsg(struct namemsg* msg)
{
	struct name_entry *my_name = my_names;
	struct name* to_packet;
	char* pos = (char*)msg + sizeof(struct namemsg);
	short i=0;
        int k;
	for (my_name = my_names; my_name!=NULL; my_name = my_name->next)
	{
		olsr_printf(3, "NAME PLUGIN: Announcing name %s (%s) %d\n", 
			my_name->name, olsr_ip_to_string(&my_name->ip), my_name->len);
			
		to_packet = (struct name*)pos;
		to_packet->type = htons(my_name->type);
		to_packet->len = htons(my_name->len);
		memcpy(&to_packet->ip, &my_name->ip, ipsize);
		pos += sizeof(struct name);
		strncpy(pos, my_name->name, my_name->len);
		pos += my_name->len;
		// padding to 4 byte boundaries
                for (k = my_name->len; (k & 3) != 0; k++)
			*pos++ = '\0';
		i++;
	}
	msg->nr_names = htons(i);
	msg->version = htons(NAME_PROTOCOL_VERSION);
	return pos - (char*)msg; //length
}


/**
 * decapsulate a name message and update name_entries if necessary
 */
void
decap_namemsg( struct namemsg *msg, int size, struct name_entry **to )
{
	char *pos, *end_pos;
	struct name_entry *tmp;
	struct name *from_packet; 
	int i;
	
	olsr_printf(4, "NAME PLUGIN: decapsulating name msg (size %d)\n", size);
	
	if (ntohs(msg->version) != NAME_PROTOCOL_VERSION) {
		olsr_printf(3, "NAME PLUGIN: ignoring wrong version %d\n", msg->version);
		return;
	}
	
	// for now ist easier to just delete everything, than
	// to update selectively
	free_name_entry_list(to);
	
	/* now add the names from the message */
	pos = (char*)msg + sizeof(struct namemsg);
	end_pos = pos + size - sizeof(struct name*); // at least one struct name hast to be left
	
	for (i=ntohs(msg->nr_names); i > 0 && pos<end_pos; i--) 
	{
		from_packet = (struct name*)pos;
		
		tmp = olsr_malloc(sizeof(struct name_entry), "new name_entry");		
		tmp->type = ntohs(from_packet->type);
		tmp->len = ntohs(from_packet->len) > MAX_NAME ? MAX_NAME : ntohs(from_packet->len);
		tmp->name = olsr_malloc(tmp->len+1, "new name_entry name");
		memcpy(&tmp->ip, &from_packet->ip, ipsize);
		pos += sizeof(struct name);
		strncpy(tmp->name, pos, tmp->len);
		tmp->name[tmp->len] = '\0';

		olsr_printf(3, "NAME PLUGIN: New name %s (%s) %d %d\n", 
			tmp->name, olsr_ip_to_string(&tmp->ip), tmp->len, tmp->type);

		// queue to front
		tmp->next = *to;
		*to = tmp;

		// name + padding
		pos += 1 + ((tmp->len - 1) | 3);
	}
	if (i!=0)
		olsr_printf(4, "NAME PLUGIN: Lost %d names due to length inconsistency\n", i);
}


/**
 * Update or register a new name entry
 */
void
update_name_entry(union olsr_ip_addr *originator, struct namemsg *msg, int msg_size, double vtime)
{
	int hash;
	struct db_entry *entry;

	olsr_printf(3, "NAME PLUGIN: Received Name Message from %s\n", 
		olsr_ip_to_string(originator));

	hash = olsr_hashing(originator);

	/* find the entry for originator */
	for (entry = list[hash]; entry != NULL; entry = entry->next)
	{
		if (memcmp(originator, &entry->originator, ipsize) == 0) {
			// found
			olsr_printf(4, "NAME PLUGIN: %s found\n", 
				olsr_ip_to_string(originator));
		
			decap_namemsg(msg, msg_size, &entry->names);
 			
			olsr_get_timestamp(vtime * 1000, &entry->timer);
			
			name_table_changed = OLSR_TRUE;
			return;
		}
	}

	olsr_printf(3, "NAME PLUGIN: New entry %s\n", 
		olsr_ip_to_string(originator));
		
	/* insert a new entry */
	entry = olsr_malloc(sizeof(struct db_entry), "new db_entry");
	memcpy(&entry->originator, originator, ipsize);
	olsr_get_timestamp(vtime * 1000, &entry->timer);
	entry->names = NULL;
	// queue to front
	entry->next = list[hash];
	list[hash] = entry;
	
	decap_namemsg(msg, msg_size, &entry->names);

	name_table_changed = OLSR_TRUE;
}


/**
 * write names to a file in /etc/hosts compatible format
 */
void
write_name_table()
{
	int hash;
	struct name_entry *name;
	struct db_entry *entry;
	FILE* hosts;
	FILE* add_hosts;
	int c=0;
	time_t currtime;
  
	if(!name_table_changed)
		return;

	olsr_printf(2, "NAME PLUGIN: writing hosts file\n");
		      
	hosts = fopen( my_filename, "w" );
	if (hosts == NULL) {
		olsr_printf(2, "NAME PLUGIN: cant write hosts file\n");
		return;
	}
	
	fprintf(hosts, "### this /etc/hosts file is overwritten regularly by olsrd\n");
	fprintf(hosts, "### do not edit\n\n");
	
	// copy content from additional hosts filename
	if (my_add_hosts[0] != '\0') {
		add_hosts = fopen( my_add_hosts, "r" );
		if (add_hosts == NULL) {
			olsr_printf(2, "NAME PLUGIN: cant open additional hosts file\n");
		}
		else {
			fprintf(hosts, "### contents from '%s' ###\n\n", my_add_hosts);
			while ((c = getc(add_hosts)) != EOF)
				putc(c, hosts);
		}
		fclose(add_hosts);		
		fprintf(hosts, "\n### olsr names ###\n\n");
	}
	
	// write own names
	for (name = my_names; name != NULL; name = name->next) {
		fprintf(hosts, "%s\t%s%s\t# myself\n", olsr_ip_to_string(&name->ip),
			name->name, my_suffix );
	}
	
	// write received names
	for(hash = 0; hash < HASHSIZE; hash++) 
	{
		for(entry = list[hash]; entry != NULL; entry = entry->next)
		{
			for (name = entry->names; name != NULL; name = name->next) 
			{
				olsr_printf(6, "%s\t%s%s", olsr_ip_to_string(&name->ip), name->name, my_suffix);
				olsr_printf(6, "\t#%s\n", olsr_ip_to_string(&entry->originator));
				
				fprintf(hosts, "%s\t%s%s", olsr_ip_to_string(&name->ip), name->name, my_suffix);
				fprintf(hosts, "\t# %s\n", olsr_ip_to_string(&entry->originator));
			}
		}
	}

	if(time(&currtime)) {
		fprintf(hosts, "\n### written by olsrd at %s", ctime(&currtime));
	}
	  
	fclose(hosts);
	name_table_changed = OLSR_FALSE;
}

/**
 * completely free a list of name_entries
 */
void 
free_name_entry_list(struct name_entry **list) 
{
	struct name_entry **tmp = list;
	struct name_entry *to_delete;
	while (*tmp != NULL) {
		to_delete = *tmp;
		*tmp = (*tmp)->next;
		free( to_delete->name );
		free( to_delete );
		to_delete = NULL;
	}
}


/**
 * we only allow names for IP addresses which we are
 * responsible for: 
 * so the IP must either be from one of the interfaces
 * or inside a HNA which we have configured 
 */
olsr_bool
allowed_ip(union olsr_ip_addr *addr)
{
	struct hna4_entry *hna4;
	struct olsr_if *ifs;
	
	olsr_printf(6, "checking %s\n", olsr_ip_to_string(addr));
	
	for(ifs = cfg->interfaces; ifs; ifs = ifs->next)
	{
		struct interface *rifs = ifs->interf;
		olsr_printf(6, "interface %s\n", olsr_ip_to_string(&rifs->ip_addr));
		if (COMP_IP(&rifs->ip_addr, addr)) {
			olsr_printf(6, "MATCHED\n");
			return OLSR_TRUE;
			
		}
	}
	
	for (hna4 = cfg->hna4_entries; hna4; hna4 = hna4->next)
	{
		olsr_printf(6, "HNA %s/%s\n", 
			olsr_ip_to_string(&hna4->net),
			olsr_ip_to_string(&hna4->netmask));
		
		if ( hna4->netmask.v4 != 0 && (addr->v4 & hna4->netmask.v4) == hna4->net.v4 ) {
			olsr_printf(6, "MATCHED\n");
			return OLSR_TRUE;
		}
	}
	return OLSR_FALSE;
}
