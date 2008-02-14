/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Andreas Tønnesen(andreto@olsr.org)
 *                     includes code by Bruno Randolf
 *                     includes code by Andreas Lopatic
 *                     includes code by Sven-Ola Tuecke
 *                     includes code by Lorenz Schori
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
 */

/*
 * Dynamic linked library for the olsr.org olsr daemon
 */

 
#include <sys/types.h>
#include <sys/socket.h>
#if !defined WIN32
#include <sys/select.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#include "ipcalc.h"
#include "olsr.h"
#include "olsr_types.h"
#include "neighbor_table.h"
#include "two_hop_neighbor_table.h"
#include "mpr_selector_set.h"
#include "tc_set.h"
#include "hna_set.h"
#include "mid_set.h"
#include "link_set.h"
#include "socket_parser.h"
#include "net_olsr.h"

#include "olsrd_txtinfo.h"
#include "olsrd_plugin.h"


#ifdef WIN32
#define close(x) closesocket(x)
#endif


static int ipc_socket;
static int ipc_open;
static int ipc_connection;
static int ipc_socket_up;


/* IPC initialization function */
static int plugin_ipc_init(void);

static void  send_info(int neighonly);

static void ipc_action(int);

static void ipc_print_neigh_link(void);

static void ipc_print_routes(void);

static void ipc_print_topology(void);

static void ipc_print_hna(void);

static void ipc_print_mid(void);

#define TXT_IPC_BUFSIZE 256
static int ipc_sendf(const char* format, ...) __attribute__((format(printf, 1, 2)));

/**
 *Do initialization here
 *
 *This function is called by the my_init
 *function in uolsrd_plugin.c
 */
int
olsrd_plugin_init(void)
{
    /* Initial IPC value */
    ipc_open = 0;
    ipc_socket_up = 0;

    plugin_ipc_init();
    return 1;
}


/**
 * destructor - called at unload
 */
void olsr_plugin_exit(void)
{
    if(ipc_open)
        close(ipc_socket);
}



static int
plugin_ipc_init(void)
{
    struct sockaddr_storage sst;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    olsr_u32_t yes = 1;
    socklen_t addrlen;

    /* Init ipc socket */
    if ((ipc_socket = socket(olsr_cnf->ip_version, SOCK_STREAM, 0)) == -1) {
#ifndef NODEBUG
        olsr_printf(1, "(TXTINFO) socket()=%s\n", strerror(errno));
#endif
        return 0;
    } else {
        if (setsockopt(ipc_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes)) < 0) {
#ifndef NODEBUG
            olsr_printf(1, "(TXTINFO) setsockopt()=%s\n", strerror(errno));
#endif
            return 0;
        }

#if defined __FreeBSD__ && defined SO_NOSIGPIPE
        if (setsockopt(ipc_socket, SOL_SOCKET, SO_NOSIGPIPE, (char *)&yes, sizeof(yes)) < 0) {
            perror("SO_REUSEADDR failed");
            return 0;
        }
#endif
        /* Bind the socket */

        /* complete the socket structure */
        memset(&sst, 0, sizeof(sst));
        if (olsr_cnf->ip_version == AF_INET) {
           sin = (struct sockaddr_in *)&sst;
           sin->sin_family = AF_INET;
           addrlen = sizeof(struct sockaddr_in);
#ifdef SIN6_LEN
           sin->sin_len = addrlen;
#endif
           sin->sin_addr.s_addr = INADDR_ANY;
           sin->sin_port = htons(ipc_port);
        } else {
           sin6 = (struct sockaddr_in6 *)&sst;
           sin6->sin6_family = AF_INET6;
           addrlen = sizeof(struct sockaddr_in6);
#ifdef SIN6_LEN
           sin6->sin6_len = addrlen;
#endif
           sin6->sin6_addr = in6addr_any;
           sin6->sin6_port = htons(ipc_port);
        }
      
        /* bind the socket to the port number */
        if (bind(ipc_socket, (struct sockaddr *) &sst, addrlen) == -1) {
#ifndef NODEBUG
            olsr_printf(1, "(TXTINFO) bind()=%s\n", strerror(errno));
#endif
            return 0;
        }

        /* show that we are willing to listen */
        if (listen(ipc_socket, 1) == -1) {
#ifndef NODEBUG
            olsr_printf(1, "(TXTINFO) listen()=%s\n", strerror(errno));
#endif
            return 0;
        }

        /* Register with olsrd */
        add_olsr_socket(ipc_socket, &ipc_action);
        
#ifndef NODEBUG
        olsr_printf(2, "(TXTINFO) listening on port %d\n",ipc_port);
#endif
        ipc_socket_up = 1;
    }
    return 1;
}


static void ipc_action(int fd)
{
    struct sockaddr_storage pin;
    struct sockaddr_in *sin4;
    struct sockaddr_in6 *sin6;
    char addr[INET6_ADDRSTRLEN];
    fd_set rfds;
    struct timeval tv;
    int neighonly = 0;

    socklen_t addrlen = sizeof(struct sockaddr_storage);

    if(ipc_open)
        return;

    if ((ipc_connection = accept(fd, (struct sockaddr *)  &pin, &addrlen)) == -1) {
#ifndef NODEBUG
        olsr_printf(1, "(TXTINFO) accept()=%s\n", strerror(errno));
#endif
        return;
    }

    tv.tv_sec = tv.tv_usec = 0;
    if (olsr_cnf->ip_version == AF_INET) {
        sin4 = (struct sockaddr_in *)&pin;
        if (inet_ntop(olsr_cnf->ip_version, &sin4->sin_addr, addr,
           INET6_ADDRSTRLEN) == NULL)
             addr[0] = '\0';
        if (!ip4equal(&sin4->sin_addr, &ipc_accept_ip.v4)) {
            olsr_printf(1, "(TXTINFO) From host(%s) not allowed!\n", addr);
            close(ipc_connection);
            return;
        }
    } else {
        sin6 = (struct sockaddr_in6 *)&pin;
        if (inet_ntop(olsr_cnf->ip_version, &sin6->sin6_addr, addr,
           INET6_ADDRSTRLEN) == NULL)
             addr[0] = '\0';
       /* Use in6addr_any (::) in olsr.conf to allow anybody. */
        if (!ip6equal(&in6addr_any, &ipc_accept_ip.v6) &&
           !ip6equal(&sin6->sin6_addr, &ipc_accept_ip.v6)) {
            olsr_printf(1, "(TXTINFO) From host(%s) not allowed!\n", addr);
            close(ipc_connection);
            return;
        }
    }
    ipc_open = 1;
#ifndef NODEBUG
    olsr_printf(2, "(TXTINFO) Connect from %s\n",addr);
#endif
      
    /* purge read buffer to prevent blocking on linux*/
    FD_ZERO(&rfds);
    FD_SET((unsigned int)ipc_connection, &rfds); /* Win32 needs the cast here */
    if(0 <= select(ipc_connection+1, &rfds, NULL, NULL, &tv)) {
        char requ[128];
        ssize_t s = recv(ipc_connection, (void*)&requ, sizeof(requ), 0); /* Win32 needs the cast here */
        if (0 < s) {
            requ[s] = 0;
            /* To print out neighbours only on the Freifunk Status
             * page the normal output is somewhat lengthy. The
             * header parsing is sufficient for standard wget.
             */
            neighonly = (0 != strstr(requ, "/neighbours"));
        }
    }

    send_info(neighonly);
	  
    close(ipc_connection);
    ipc_open = 0;
}

static void ipc_print_neigh_link(void)
{
    struct ipaddr_str buf1, buf2;
    struct neighbor_entry *neigh;
    struct neighbor_2_list_entry *list_2;
    struct link_entry *link = NULL;
    int index, thop_cnt;

    ipc_sendf("Table: Links\nLocal IP\tremote IP\tHysteresis\tLinkQuality\tlost\ttotal\tNLQ\tETX\n");

    /* Link set */
    link = link_set;
    while(link)	{
	ipc_sendf( "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t\n",
                   olsr_ip_to_string(&buf1, &link->local_iface_addr),
                   olsr_ip_to_string(&buf2, &link->neighbor_iface_addr),
                   olsr_etx_to_string(link->L_link_quality), 
                   olsr_etx_to_string(link->loss_link_quality),
                   link->lost_packets, 
                   link->total_packets,
                   olsr_etx_to_string(link->neigh_link_quality), 
                   olsr_etx_to_string(olsr_calc_link_etx(link)));
        link = link->next;
    }
    ipc_sendf("\nTable: Neighbors\nIP address\tSYM\tMPR\tMPRS\tWillingness\t2 Hop Neighbors\n");

    /* Neighbors */
    for(index = 0; index < HASHSIZE; index++) {
        for(neigh = neighbortable[index].next;
            neigh != &neighbortable[index];
            neigh = neigh->next) {
            ipc_sendf("%s\t%s\t%s\t%s\t%d\t", 
                      olsr_ip_to_string(&buf1, &neigh->neighbor_main_addr),
                      (neigh->status == SYM) ? "YES" : "NO",
                      neigh->is_mpr ? "YES" : "NO",
                      olsr_lookup_mprs_set(&neigh->neighbor_main_addr) ? "YES" : "NO",
                      neigh->willingness);
            thop_cnt = 0;

            for(list_2 = neigh->neighbor_2_list.next;
                list_2 != &neigh->neighbor_2_list;
                list_2 = list_2->next)
                {
                    //size += sprintf(&buf[size], "<option>%s</option>\n", olsr_ip_to_string(&buf1, &list_2->neighbor_2->neighbor_2_addr));
                    thop_cnt ++;
                }
            ipc_sendf("%d\n", thop_cnt);
	}
    }
    ipc_sendf("\n");
}

static void ipc_print_routes(void)
{
    struct ipaddr_str buf1, buf2;
    struct rt_entry *rt;
    struct avl_node *rt_tree_node;

    ipc_sendf("Table: Routes\nDestination\tGateway\tMetric\tETX\tInterface\n");

    /* Walk the route table */
    for (rt_tree_node = avl_walk_first(&routingtree);
         rt_tree_node;
         rt_tree_node = avl_walk_next(rt_tree_node)) {

        rt = rt_tree_node->data;

        ipc_sendf( "%s/%d\t%s\t%d\t%s\t%s\t\n",
                   olsr_ip_to_string(&buf1, &rt->rt_dst.prefix),
                   rt->rt_dst.prefix_len,
                   olsr_ip_to_string(&buf2, &rt->rt_best->rtp_nexthop.gateway),
                   rt->rt_best->rtp_metric.hops,
                   olsr_etx_to_string(rt->rt_best->rtp_metric.etx),
                   if_ifwithindex_name(rt->rt_best->rtp_nexthop.iif_index));
    }
    ipc_sendf("\n");

}

static void ipc_print_topology(void)
{
    struct tc_entry *tc;
    
    ipc_sendf("Table: Topology\nDestination IP\tLast hop IP\tLQ\tILQ\tETX\n");

    /* Topology */  
    OLSR_FOR_ALL_TC_ENTRIES(tc) {
        struct tc_edge_entry *tc_edge;
        OLSR_FOR_ALL_TC_EDGE_ENTRIES(tc, tc_edge) {
            struct ipaddr_str dstbuf, addrbuf;
            ipc_sendf( "%s\t%s\t%s\t%s\t%s\n", 
                       olsr_ip_to_string(&dstbuf, &tc_edge->T_dest_addr),
                       olsr_ip_to_string(&addrbuf, &tc->addr), 
                       olsr_etx_to_string(tc_edge->link_quality),
                       olsr_etx_to_string(tc_edge->inverse_link_quality),
                       olsr_etx_to_string(olsr_calc_tc_etx(tc_edge)));

        } OLSR_FOR_ALL_TC_EDGE_ENTRIES_END(tc, tc_edge);
    } OLSR_FOR_ALL_TC_ENTRIES_END(tc);

    ipc_sendf("\n");
}

static void ipc_print_hna(void)
{
    int size;
    int index;
    struct ip_prefix_list *hna;

    size = 0;

    ipc_sendf("Table: HNA\nNetwork\tNetmask\tGateway\n");

    /* Announced HNA entries */
    if (olsr_cnf->ip_version == AF_INET) {
        for(hna = olsr_cnf->hna_entries; hna != NULL; hna = hna->next) {
            struct ipaddr_str addrbuf, mainaddrbuf;
            ipc_sendf("%s\t%d\t%s\n",
                      olsr_ip_to_string(&addrbuf, &hna->net.prefix),
                      hna->net.prefix_len,
                      olsr_ip_to_string(&mainaddrbuf, &olsr_cnf->main_addr));
        }
    } else {
        for(hna = olsr_cnf->hna_entries; hna != NULL; hna = hna->next) {
            struct ipaddr_str addrbuf, mainaddrbuf;
            ipc_sendf("%s\t%d\t%s\n",
                      olsr_ip_to_string(&addrbuf, &hna->net.prefix),
                      hna->net.prefix_len,
                      olsr_ip_to_string(&mainaddrbuf, &olsr_cnf->main_addr));
        }
    }

    /* HNA entries */
    for(index = 0; index < HASHSIZE; index++) {
        struct hna_entry *tmp_hna;
        /* Check all entrys */
        for (tmp_hna = hna_set[index].next; tmp_hna != &hna_set[index]; tmp_hna = tmp_hna->next) {
            /* Check all networks */
            struct hna_net *tmp_net;
            for (tmp_net = tmp_hna->networks.next; tmp_net != &tmp_hna->networks; tmp_net = tmp_net->next) {
                struct ipaddr_str addrbuf, mainaddrbuf;
                ipc_sendf("%s\t%d\t%s\n",
                          olsr_ip_to_string(&addrbuf, &tmp_net->A_network_addr),
                          tmp_net->prefixlen,
                          olsr_ip_to_string(&mainaddrbuf, &tmp_hna->A_gateway_addr));
            }
	}
    }
    ipc_sendf("\n");
}

static void ipc_print_mid(void)
{
    int index;
    unsigned short is_first;
    struct mid_entry *entry;
    struct mid_address *alias;

    ipc_sendf("Table: MID\nIP\tAliases\n");

    /* MID */
    for(index = 0; index < HASHSIZE; index++) {
        entry = mid_set[index].next;
        
        while( entry != &mid_set[index] ) {
            struct ipaddr_str buf;
            ipc_sendf( olsr_ip_to_string(&buf,  &entry->main_addr ) );
            alias = entry->aliases;
            is_first = 1;

            while( alias ) {
                ipc_sendf( "%s%s",
                           ( is_first ? "\t" : ";" ),
                           olsr_ip_to_string(&buf,  &alias->alias )
                           );

                alias = alias->next_alias;
                is_first = 0;
            }
            entry = entry->next;
            ipc_sendf("\n");
        }
    }
    ipc_sendf("\n");
}


static void  send_info(int neighonly)
{
    /* Print minimal http header */
    ipc_sendf("HTTP/1.0 200 OK\n");
    ipc_sendf("Content-type: text/plain\n\n");

    /* Print tables to IPC socket */
	
    /* links + Neighbors */
    ipc_print_neigh_link();
	
    /* topology */
    if (!neighonly) ipc_print_topology();
	
    /* hna */
    if (!neighonly) ipc_print_hna();

    /* mid */
    if (!neighonly) ipc_print_mid();

    /* routes */
    if (!neighonly) ipc_print_routes();
}

/*
 * In a bigger mesh, there are probs with the fixed
 * bufsize. Because the Content-Length header is
 * optional, the sprintf() is changed to a more
 * scalable solution here.
 */
 
static int  ipc_sendf(const char* format, ...)
{
    char txtnetbuf[TXT_IPC_BUFSIZE];

    va_list arg;
    int rv;
#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __MacOSX__
    int flags = 0;
#else
    int flags = MSG_NOSIGNAL;
#endif
    va_start(arg, format);
    rv = vsnprintf(txtnetbuf, sizeof(txtnetbuf), format, arg);
    va_end(arg);
    if(ipc_socket_up) {
        if (0 > send(ipc_connection, txtnetbuf, rv, flags)) {
#ifndef NODEBUG
            olsr_printf(1, "(TXTINFO) Failed sending data to client!\n");
#endif
            close(ipc_connection);
            return - 1;
        }
    }
    return rv;
}

/*
 * Local Variables:
 * mode: c
 * style: linux
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
