/*
 * Secure OLSR plugin
 * Copyright (C) 2004 Andreas T�nnesen (andreto@ifi.uio.no)
 *
 * This file is part of the secure OLSR plugin(solsrp) for UniK olsrd.
 *
 * Solsrp is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * solsrp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with olsrd-unik; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


/*
 * Dynamic linked library example for UniK OLSRd
 */

#ifndef _OLSRD_PLUGIN_DEFS
#define _OLSRD_PLUGIN_DEFS


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "olsr_plugin_io.h"

/* Use this as PARSER_TYPE to receive ALL messages! */
#define PROMISCUOUS 0xffffffff



#define PLUGIN_NAME    "OLSRD signature plugin"
#define PLUGIN_VERSION "0.3"
#define PLUGIN_AUTHOR   "Andreas T�nnesen"
#define MOD_DESC PLUGIN_NAME " " PLUGIN_VERSION " by " PLUGIN_AUTHOR
#define PLUGIN_INTERFACE_VERSION 1

/* The type of message you will use */
#define MESSAGE_TYPE 10

/* The type of messages we will receive - can be set to promiscuous */
#define PARSER_TYPE MESSAGE_TYPE

#define TYPE_CHALLENGE 11
#define TYPE_CRESPONSE 12
#define TYPE_RRESPONSE 13

#define TIMED_OUT(s1) \
        timercmp(s1, now, <)

/****************************************************************************
 *           Various datastructures and definitions from olsrd              *
 ****************************************************************************/

/*
 * TYPES SECTION
 */

/* types */
#include <sys/types.h>

typedef u_int8_t        olsr_u8_t;
typedef u_int16_t       olsr_u16_t;
typedef u_int32_t       olsr_u32_t;
typedef int8_t          olsr_8_t;
typedef int16_t         olsr_16_t;
typedef int32_t         olsr_32_t;



/*
 * VARIOUS DEFINITIONS
 */

union olsr_ip_addr
{
  olsr_u32_t v4;
  struct in6_addr v6;
};

union hna_netmask
{
  olsr_u32_t v4;
  olsr_u16_t v6;
};

#define MAX_TTL               0xff


/*
 *Link Types
 */

#define UNSPEC_LINK           0
#define ASYM_LINK             1
#define SYM_LINK              2
#define LOST_LINK             3
#define HIDE_LINK             4
#define MAX_LINK              4


/*
 * Mantissa scaling factor
 */

#define VTIME_SCALE_FACTOR    0.0625


/*
 * Hashing
 */

#define	HASHSIZE	32
#define	HASHMASK	(HASHSIZE - 1)

#define MAXIFS         8 /* Maximum number of interfaces (from defs.h) in uOLSRd */

#define	MAXMESSAGESIZE		512	/* max broadcast size */


/****************************************************************************
 *                          INTERFACE SECTION                               *
 ****************************************************************************/

/**
 *A struct containing all necessary information about each
 *interface participating in the OLSD routing
 */
struct interface 
{
  /* IP version 4 */
  struct	sockaddr int_addr;		/* address */
  struct	sockaddr int_netmask;		/* netmask */
  struct	sockaddr int_broadaddr;         /* broadcast address */
  /* IP version 6 */
  struct        sockaddr_in6 int6_addr;         /* Address */
  struct        sockaddr_in6 int6_multaddr;     /* Multicast */
  /* IP independent */
  union         olsr_ip_addr ip_addr;
  int           olsr_socket;                    /* The broadcast socket for this interface */
  int	        int_metric;			/* metric of interface */
  int	        int_flags;			/* see below */
  char	        *int_name;			/* from kernel if structure */
  int           if_index;                       /* Kernels index of this interface */
  int           if_nr;                          /* This interfaces index internally*/
  int           is_wireless;                    /* wireless interface or not*/
  olsr_u16_t    olsr_seqnum;                    /* Olsr message seqno */
  struct	interface *int_next;
};

/* Ifchange actions */

#define IFCHG_IF_ADD           1
#define IFCHG_IF_REMOVE        2
#define IFCHG_IF_UPDATE        3


/****************************************************************************
 *                            PACKET SECTION                                *
 ****************************************************************************/

struct sig_msg
{
  olsr_u8_t     type;
  olsr_u8_t     algorithm;
  olsr_u16_t    reserved;

  time_t        timestamp;
  char          signature[20];
};

/*
 * OLSR message (several can exist in one OLSR packet)
 */

struct olsrmsg
{
  olsr_u8_t     olsr_msgtype;
  olsr_u8_t     olsr_vtime;
  olsr_u16_t    olsr_msgsize;
  olsr_u32_t    originator;
  olsr_u8_t     ttl;
  olsr_u8_t     hopcnt;
  olsr_u16_t    seqno;

  /* YOUR PACKET GOES HERE */
  struct sig_msg sig;

};


/*
 * Challenge response messages
 */

struct challengemsg
{
  olsr_u8_t     olsr_msgtype;
  olsr_u8_t     olsr_vtime;
  olsr_u16_t    olsr_msgsize;
  olsr_u32_t    originator;
  olsr_u8_t     ttl;
  olsr_u8_t     hopcnt;
  olsr_u16_t    seqno;

  olsr_u32_t    destination;
  olsr_u32_t    challenge;

  char          signature[20];

};



struct c_respmsg
{
  olsr_u8_t     olsr_msgtype;
  olsr_u8_t     olsr_vtime;
  olsr_u16_t    olsr_msgsize;
  olsr_u32_t    originator;
  olsr_u8_t     ttl;
  olsr_u8_t     hopcnt;
  olsr_u16_t    seqno;

  olsr_u32_t    destination;
  olsr_u32_t    challenge;
  time_t        timestamp;

  char          res_sig[20];

  char          signature[20];

};


struct r_respmsg
{
  olsr_u8_t     olsr_msgtype;
  olsr_u8_t     olsr_vtime;
  olsr_u16_t    olsr_msgsize;
  olsr_u32_t    originator;
  olsr_u8_t     ttl;
  olsr_u8_t     hopcnt;
  olsr_u16_t    seqno;

  olsr_u32_t    destination;
  time_t        timestamp;

  char          res_sig[20];

  char          signature[20];
};


/*
 *IPv6
 */

struct olsrmsg6
{
  olsr_u8_t        olsr_msgtype;
  olsr_u8_t        olsr_vtime;
  olsr_u16_t       olsr_msgsize;
  struct in6_addr  originator;
  olsr_u8_t        ttl;
  olsr_u8_t        hopcnt;
  olsr_u16_t       seqno;

  /* YOUR PACKET GOES HERE */
  struct sig_msg   sig;
};

/*
 * Generic OLSR packet - DO NOT ALTER
 */

struct olsr 
{
  olsr_u16_t	  olsr_packlen;		/* packet length */
  olsr_u16_t	  olsr_seqno;
  struct olsrmsg  olsr_msg[1];          /* variable messages */
};


struct olsr6
{
  olsr_u16_t	    olsr_packlen;        /* packet length */
  olsr_u16_t	    olsr_seqno;
  struct olsrmsg6   olsr_msg[1];         /* variable messages */
};


/* 
 * ALWAYS USE THESE WRAPPERS TO
 * ENSURE IPv4 <-> IPv6 compability 
 */

union olsr_message
{
  struct olsrmsg v4;
  struct olsrmsg6 v6;
};

union olsr_packet
{
  struct olsr v4;
  struct olsr6 v6;
};


/***************************************************************************
 *                 Functions provided by uolsrd_plugin.c                   *
 *                  Similar to their siblings in olsrd                     *
 ***************************************************************************/

char ipv6_buf[100]; /* buffer for IPv6 inet_htop */

/* All these could optionally be fetched from olsrd */

olsr_u32_t
olsr_hashing(union olsr_ip_addr *);

void
olsr_get_timestamp(olsr_u32_t, struct timeval *);

void
olsr_init_timer(olsr_u32_t, struct timeval *);

int
olsr_timed_out(struct timeval *);

char *
olsr_ip_to_string(union olsr_ip_addr *);



/****************************************************************************
 *                Function pointers to functions in olsrd                   *
 *              These allow direct access to olsrd functions                *
 ****************************************************************************/

/* The multi-purpose funtion. All other functions are fetched trough this */
int (*olsr_plugin_io)(int, void *, size_t);

/* add a prser function */
void (*olsr_parser_add_function)(void (*)(union olsr_message *, struct interface *, union olsr_ip_addr *), 
				 int, int);

/* Register a timeout function */
int (*olsr_register_timeout_function)(void (*)());

/* Register a scheduled event */
int (*olsr_register_scheduler_event)(void (*)(), float, float, olsr_u8_t *);

/* Get the next message seqno in line */
olsr_u16_t (*get_msg_seqno)();

/* Transmit package */
int (*net_output)(struct interface*);

/* Check the duplicate table for prior processing */
int (*check_dup_proc)(union olsr_ip_addr *, olsr_u16_t);

/* Default forward algorithm */
int (*default_fwd)(union olsr_message *, 
		   union olsr_ip_addr *, 
		   olsr_u16_t,  
		   struct interface *, 
		   union olsr_ip_addr *);

/* Add a socket to the main olsrd select loop */
void (*add_olsr_socket)(int, void(*)(int));

/* Remove a socket from the main olsrd select loop */
int (*remove_olsr_socket)(int, void(*)(int));

/* get the link status to a neighbor */
int (*check_neighbor_link)(union olsr_ip_addr *);

/* Mantissa/exponen conversions */
olsr_u8_t (*double_to_me)(double);

double (*me_to_double)(olsr_u8_t);

/* olsrd printf wrapper */
int (*olsr_printf)(int, char *, ...);

/* olsrd malloc wrapper */
void *(*olsr_malloc)(size_t, const char *);

/* Add hna net IPv4 */
void (*add_local_hna4_entry)(union olsr_ip_addr *, union hna_netmask *);

/* Remove hna net IPv4 */
int (*remove_local_hna4_entry)(union olsr_ip_addr *, union hna_netmask *);

/* Add hna net IPv6 */
void (*add_local_hna6_entry)(union olsr_ip_addr *, union hna_netmask *);

/* Remove hna net IPv6 */
int (*remove_local_hna6_entry)(union olsr_ip_addr *, union hna_netmask *);

/* Add a packet transform function */
int (*add_ptf)(int(*)(char *, int *));

/* Remove a packet transform function */
int (*del_ptf)(int(*)(char *, int *));

/* Socket input function */
void (*olsr_input)(int);

/* Packet parser function */
void (*parse_packet)(struct olsr *, int, struct interface *, union olsr_ip_addr *);

/* Map interface by socket */
struct interface * (*if_ifwithsock)(int);

/* Map interface by address */
struct interface * (*if_ifwithaddr)(union olsr_ip_addr *);

/* Add an ifchange function */
int (*add_ifchgf)(int(*)(struct interface *, int));

/* Remove an ifchange function */
int (*del_ifchgf)(int(*)(struct interface *, int));



/****************************************************************************
 *                             Data from olsrd                              *
 *           NOTE THAT POINTERS POINT TO THE DATA USED BY OLSRD!            *
 *               NEVER ALTER DATA POINTED TO BY THESE POINTERS              * 
 *                   UNLESS YOU KNOW WHAT YOU ARE DOING!!!                  *
 ****************************************************************************/
/**
 * The interface list from olsrd
 */

struct interface   *ifs;

/* These two are set automatically by olsrd at load time */
int                ipversion;  /* IPversion in use */
union olsr_ip_addr *main_addr; /* Main address */


size_t             ipsize;     /* Size of the ipadresses used */
struct timeval     *now;       /* the olsrds schedulers idea of current time */

/* Data that can be altered by your plugin */
char               *buffer;    /* The packet buffer - put your packet here */
int                *outputsize;/* Pointer to the outputsize - set the size of your packet here */
int                *maxmessagesize;

/****************************************************************************
 *                Functions that the plugin MUST provide                    *
 ****************************************************************************/


/* Initialization function */
int
olsr_plugin_init();

/* IPC initialization function */
int
plugin_ipc_init();

/* Destructor function */
void
olsr_plugin_exit();

/* Mulitpurpose funtion */
int
plugin_io(int, void *, size_t);

#endif
