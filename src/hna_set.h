/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Andreas T�nnesen(andreto@olsr.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * * Redistributions of source code must retain the above copyright 
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright 
 *   notice, this list of conditions and the following disclaimer in 
 *   the documentation and/or other materials provided with the 
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its 
 *   contributors may be used to endorse or promote products derived 
 *   from this software without specific prior written permission.
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
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 * $Id: hna_set.h,v 1.9 2004/11/21 11:28:56 kattemat Exp $
 */



#ifndef _OLSR_HNA
#define _OLSR_HNA

#include "hashing.h"
#include "packet.h"

/* hna_netmask declared in packet.h */

struct hna_net
{
  union olsr_ip_addr A_network_addr;
  union hna_netmask  A_netmask;
  struct timeval     A_time;
  struct hna_net     *next;
  struct hna_net     *prev;
};

struct hna_entry
{
  union olsr_ip_addr A_gateway_addr;
  struct hna_net     networks;
  struct hna_entry   *next;
  struct hna_entry   *prev;
};

struct hna_entry hna_set[HASHSIZE];
size_t netmask_size;

int
olsr_init_hna_set(void);


struct hna_net *
olsr_lookup_hna_net(struct hna_net *, union olsr_ip_addr *, union hna_netmask *);


struct hna_entry *
olsr_lookup_hna_gw(union olsr_ip_addr *);



struct hna_entry *
olsr_add_hna_entry(union olsr_ip_addr *);


struct hna_net *
olsr_add_hna_net(struct hna_entry *, union olsr_ip_addr *, union hna_netmask *);


void
olsr_update_hna_entry(union olsr_ip_addr *, union olsr_ip_addr *, union hna_netmask *, float);


void
olsr_time_out_hna_set(void *);


void
delete_hna_net(struct hna_net *);


void
delete_hna_entry(struct hna_entry *);

void
olsr_print_hna_set(void);

#endif
