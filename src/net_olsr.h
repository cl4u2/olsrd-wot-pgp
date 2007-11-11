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
 * $Id: net_olsr.h,v 1.16 2007/11/11 22:51:54 bernd67 Exp $
 */



#ifndef _NET_OLSR
#define _NET_OLSR

#include "defs.h"
#include "interfaces.h"
#include "process_routes.h"

#include <arpa/inet.h>
#include <net/if.h>

typedef int (*packet_transform_function)(olsr_u8_t *, int *);

struct ipaddr_str {
    char buf[MAX(INET6_ADDRSTRLEN, INET_ADDRSTRLEN)];
};

/*
 * Macros for comparing and copying IP addresses
 */
static INLINE int ip4cmp(const struct in_addr *a, const struct in_addr *b) { return ntohl(a->s_addr) - ntohl(b->s_addr); }
static INLINE int ip4equal(const struct in_addr *a, const struct in_addr *b) { return a->s_addr == b->s_addr; }

static INLINE int ip6cmp(const struct in6_addr *a, const struct in6_addr *b) { return memcmp(a, b, sizeof(*a)); }
static INLINE int ip6equal(const struct in6_addr *a, const struct in6_addr *b) { return ip6cmp(a, b) == 0; }

int ipcmp(const union olsr_ip_addr *a, const union olsr_ip_addr *b);
static INLINE int ipequal(const union olsr_ip_addr *a, const union olsr_ip_addr *b) { return ipcmp(a, b) == 0; }

/* Do not use this - this is as evil as the COPY_IP() macro was and only used in
 * source which also needs cleanups.
 */
static INLINE void genipcopy(void *dst, const void *src) { memcpy(dst, src, olsr_cnf->ipsize); }


void
net_set_disp_pack_out(olsr_bool);

void
init_net(void);

int
net_add_buffer(struct interface *);

int
net_remove_buffer(struct interface *);

int
net_outbuffer_bytes_left(const struct interface *);

olsr_u16_t
net_output_pending(const struct interface *);

int
net_reserve_bufspace(struct interface *, int);

int
net_outbuffer_push(struct interface *, const void *, const olsr_u16_t);

int
net_outbuffer_push_reserved(struct interface *, const void *, const olsr_u16_t);

int
net_output(struct interface *);

int
net_sendroute(struct rt_entry *, struct sockaddr *);

int
olsr_prefix_to_netmask(union olsr_ip_addr *, const olsr_u16_t);

olsr_u16_t
olsr_netmask_to_prefix(const union olsr_ip_addr *);

const char *
sockaddr_to_string(struct ipaddr_str * const , const struct sockaddr *);

const char *
ip4_to_string(struct ipaddr_str * const buf, const struct in_addr);

const char *
ip6_to_string(struct ipaddr_str * const buf, const struct in6_addr * const addr6);

const char *
olsr_ip_to_string(struct ipaddr_str * const buf, const union olsr_ip_addr *);

const char *
sockaddr_to_string(struct ipaddr_str * const buf, const struct sockaddr *);

const char *
olsr_ip_prefix_to_string(const struct olsr_ip_prefix *prefix);

int
add_ptf(packet_transform_function);

int
del_ptf(packet_transform_function);

olsr_bool
olsr_validate_address(const union olsr_ip_addr *);

void
olsr_add_invalid_address(const union olsr_ip_addr *);

#endif
