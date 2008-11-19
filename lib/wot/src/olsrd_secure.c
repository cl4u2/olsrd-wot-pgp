/*
 * Web of Trust OLSR plugin
 *
 * From the Secure OLSR plugin
 * http://www.olsr.org
 * Copyright (c) 2004, Andreas Tønnesen(andreto@olsr.org)
 * modified in 2008 by Claudio Pisa (clauz at ninux dot org)
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
 * * Neither the name of olsrd, olsr.org nor the names of its 
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
 */


/*
 * Dynamic linked library for the olsr.org olsr daemon
 */

#include "olsrd_secure.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef linux
#include <linux/in_route.h>
#endif
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "defs.h"
#include "ipcalc.h"
#include "olsr.h"
#include "socket_parser.h"
#include "parser.h"
#include "scheduler.h"
#include "net_olsr.h"
#include "kernel_routes.h"
#include "olsrd_plugin.h"
#include "process_routes.h"

/* OpenPGP stuff */
#include "wot_olsrd.h"

#ifdef USE_OPENSSL
	#include <openssl/sha.h>
	#define CHECKSUM SHA1
#else
	#include "md5.h"
	static void
	MD5_checksum(const olsr_u8_t *data, const olsr_u16_t data_len, olsr_u8_t *hashbuf)
	{
	  MD5_CTX context;
	
	  MD5Init(&context);
	  MD5Update(&context, data, data_len);
	  MD5Final(hashbuf, &context);
	}
	
	#define CHECKSUM MD5_checksum
#endif

#define SCHEME PGP_SIG

#ifdef OS
#undef OS
#endif

#ifdef WIN32
#define close(x) closesocket(x)
#undef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#define OS "Windows"
#endif
#ifdef linux
#define OS "GNU/Linux"
#endif
#ifdef __FreeBSD__
#define OS "FreeBSD"
#endif

#ifndef OS
#define OS "Undefined"
#endif

static struct timeval now;

/* Timestamp node */
struct stamp
{
  union olsr_ip_addr addr;
  /* Timestamp difference */
  int diff;
  olsr_u32_t cmsg_challenge;
  olsr_u32_t cres_challenge;
  olsr_u8_t validated;
  clock_t valtime; /* Validity time */
  clock_t conftime; /* Reconfiguration time */
  struct stamp *prev;
  struct stamp *next;
};

/* Seconds to cache a valid timestamp entry */
#define TIMESTAMP_HOLD_TIME 40
/* Seconds to cache a not verified timestamp entry */
#define EXCHANGE_HOLD_TIME 5

static struct stamp timestamps[HASHSIZE];

char keyname[MAX_KEY_NAME_SIZE+1];
char passphrase[MAX_PASSPHRASE_SIZE+1];
char gpgfilename[FILENAME_MAX+1];
char gpghomedir[FILENAME_MAX+1];
char passphrasehelper[FILENAME_MAX+1];

static int send_challenge(struct interface *olsr_if, const union olsr_ip_addr *);
static int send_cres(struct interface *olsr_if, union olsr_ip_addr *, union olsr_ip_addr *, olsr_u32_t, struct stamp *);
static int send_rres(struct interface *olsr_if, union olsr_ip_addr *, union olsr_ip_addr *, olsr_u32_t);
static int parse_challenge(struct interface *olsr_if, char *);
static int parse_cres(struct interface *olsr_if, char *);
static int parse_rres(char *);
static int check_auth(struct interface *olsr_if, char *, int *);
static int add_signature(olsr_u8_t *, int*);
static int validate_packet(struct interface *olsr_if, const char *, int*);
static char *secure_preprocessor(char *packet, struct interface *olsr_if, union olsr_ip_addr *from_addr, int *length);
static void timeout_timestamps(void*);
static int check_timestamp(struct interface *olsr_if, const union olsr_ip_addr *, time_t);
static struct stamp *lookup_timestamp_entry(const union olsr_ip_addr *);
int add_olsr_v4_route(struct rt_entry *r);
int del_olsr_v4_route(struct rt_entry *r);

/**
 *Do initialization here
 *
 *This function is called by the my_init
 *function in uolsrd_plugin.c
 */

int
secure_plugin_init(void)
{
  int i;


  /* Initialize the timestamp database */
  for(i = 0; i < HASHSIZE; i++)
    {
      timestamps[i].next = &timestamps[i];
      timestamps[i].prev = &timestamps[i];
    }
  olsr_printf(1, "Timestamp database initialized\n");

  /* Register the packet transform function */
  add_ptf(&add_signature);

  olsr_preprocessor_add_function(&secure_preprocessor);
  
  /* Register timeout - poll every 2 seconds */
  olsr_start_timer(2 * MSEC_PER_SEC, 0, OLSR_TIMER_PERIODIC,
                   &timeout_timestamps, NULL, 0);
  
  /* register route adding functions */
  olsr_addroute_function = add_olsr_v4_route;
  olsr_delroute_function = del_olsr_v4_route;

  /* Initialize gpgme structures */
  return wotplugin_init();

}

int add_olsr_v4_route(struct rt_entry *r) {
  return wotplugin_add_policy_route(r);
}

int del_olsr_v4_route(struct rt_entry *r) {
  return wotplugin_del_policy_route(r); 
}


int
plugin_ipc_init(void)
{
  return 1;
}

/*
 * destructor - called at unload
 */
void
secure_plugin_exit(void)
{
  /* Finalize gpgme structures */
  wotplugin_finish();
  olsr_preprocessor_remove_function(&secure_preprocessor);
}


#if 0
/**
 *Scheduled event
 */
static void
olsr_event(void)
{

}
#endif

#if 0
static int
ipc_send(char *data __attribute__((unused)), int size __attribute__((unused)))
{
  return 1;
}
#endif

static char *
secure_preprocessor(char *packet, struct interface *olsr_if, union olsr_ip_addr *from_addr, int *length)
{
  struct olsr *olsr = (struct olsr *)packet;
  struct ipaddr_str buf;
  
  /*
   * Check for challenge/response messages
   */
  check_auth(olsr_if, packet, length);

  /*
   * Check signature
   */

  if(!validate_packet(olsr_if, packet, length))
  {
    olsr_printf(1, "[WOT]Rejecting packet from %s\n", olsr_ip_to_string(&buf, from_addr));
    return NULL;
  }

  olsr_printf(1, "[WOT]Packet from %s OK size %d\n", olsr_ip_to_string(&buf, from_addr), *length);

  /* Fix OLSR packet header */
  olsr->olsr_packlen = htons(*length);
  return packet;
}



/**
 * Check a incoming OLSR packet for
 * challenge/responses.
 * They need not be verified as they
 * are signed in the message.
 *
 */
static int
check_auth(struct interface *olsr_if, char *pck, int *size __attribute__((unused)))
{

  olsr_printf(3, "[WOT]Checking packet for challenge response message...\n");

  switch(pck[4])
    {
    case(TYPE_CHALLENGE):
      parse_challenge(olsr_if, &pck[4]);
      break;

    case(TYPE_CRESPONSE):
      parse_cres(olsr_if, &pck[4]);
      break;

    case(TYPE_RRESPONSE):
      parse_rres(&pck[4]);
      break;

    default:
      return 0;
    }

  return 1;
}



/**
 * Packet transform function
 * Build a SHA-1/MD5 hash of the original message
 * + the signature message(-digest) + key
 *
 * Then add the signature message to the packet and
 * increase the size
 */
int
add_signature(olsr_u8_t *pck, int *size)
{
  struct s_olsrmsg *msg;
#ifdef DEBUG
  unsigned int i;
  int j;
  const olsr_u8_t *sigmsg;                                                                                        
#endif
  
  olsr_printf(2, "[WOT]Adding signature for packet size %d\n", *size);
  fflush(stdout);
  
  msg = (struct s_olsrmsg *)&pck[*size];
  /* Update size */
  ((struct olsr*)pck)->olsr_packlen = htons(*size + sizeof(struct s_olsrmsg));
  
  /* Fill packet header */
  msg->olsr_msgtype = MESSAGE_TYPE;
  msg->olsr_vtime = 0;
  msg->olsr_msgsize = htons(sizeof(struct s_olsrmsg));
  memcpy(&msg->originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
  msg->ttl = 1;
  msg->hopcnt = 0;
  msg->seqno = htons(get_msg_seqno());
  
  /* Fill subheader */
  msg->sig.type = ONE_CHECKSUM;
  msg->sig.algorithm = SCHEME;
  memset(&msg->sig.reserved, 0, 2);
  
  /* Add timestamp */
  msg->sig.timestamp = htonl(now.tv_sec);
  olsr_printf(3, "[WOT]timestamp: %ld\n", now.tv_sec);
  
  /* Set the new size */
  *size += sizeof(struct s_olsrmsg);
  /* gpg-sign the message */
  return wotplugin_sign(pck, size, msg);

#ifdef DEBUG
  olsr_printf(1, "Signature message:\n");

  j = 0;
  sigmsg = (olsr_u8_t *)msg;

  for(i = 0; i < sizeof(struct s_olsrmsg); i++)
    {
      olsr_printf(1, "  %3i", sigmsg[i]);
      j++;
      if(j == 4)
	{
	  olsr_printf(1, "\n");
	  j = 0;
	}
    }
#endif

  olsr_printf(3, "[WOT] Message signed\n");

  return 1;
}



static int
validate_packet(struct interface *olsr_if, const char *pck, int *size)
{
  const struct s_olsrmsg *sig;
  time_t rec_time;
  int packetscanner;
  olsr_u16_t msglen;

  olsr_printf(3, "[WOT]verifying message (size %d)\n", *size);

  /* Scan the entire packet for the last message */
  packetscanner = 6;
  olsr_printf(3, "[WOT]packet scanner: %d", packetscanner);
  memmove(&msglen, &pck[packetscanner], sizeof(olsr_u16_t));

  while(packetscanner + ntohs(msglen) < *size) 
  { 
	  /* avoid infinite loops */
	  if(ntohs(msglen)== 0)
			  return 0;
	  packetscanner += ntohs(msglen);
	  olsr_printf(3, ", %d", packetscanner);
	  memmove(&msglen, &pck[packetscanner], sizeof(olsr_u16_t));
  }
  packetscanner -= 2;
  olsr_printf(3, " => %d\n", packetscanner);

  /* The last message */
  sig = (const struct s_olsrmsg *)&pck[packetscanner];
  //TODO: verify packet sanity here?

  /*
  if((sig->olsr_msgtype != MESSAGE_TYPE) || 
     (sig->olsr_vtime != 0) ||
     (sig->ttl != 1) ||
     (sig->hopcnt != 0))
    {
      olsr_printf(1, "[WOT]Packet not sane!\n");
      return 0;
    }
    */

  /* gpg-verify the signature in the message */
  if(wotplugin_verify((const olsr_u8_t *)pck, size, sig)) 
  { 
      olsr_printf(3, "[WOT]Signature verified\n");
  }
  else
  {
      olsr_printf(1, "[WOT]Signature missmatch\n");
      return 0;
  }

  /* Check timestamp */
  rec_time = ntohl(sig->sig.timestamp);

  if(!check_timestamp(olsr_if, (const union olsr_ip_addr *)&sig->originator, rec_time))
    {
      struct ipaddr_str buf;
      olsr_printf(1, "[WOT]Timestamp missmatch in packet from %s!\n",
		  olsr_ip_to_string(&buf, (const union olsr_ip_addr *)&sig->originator));
      return 0;
    }

  olsr_printf(1, "[WOT]Received timestamp %ld diff: %ld\n", rec_time, now.tv_sec - rec_time);

  /* Remove signature message */
  *size = packetscanner;
  return 1;
}


int
check_timestamp(struct interface *olsr_if, const union olsr_ip_addr *originator, time_t tstamp)
{
  struct stamp *entry;
  int diff;

  entry = lookup_timestamp_entry(originator);

  if(!entry)
    {
      /* Initiate timestamp negotiation */

      send_challenge(olsr_if, originator);

      return 0;
    }

  if(!entry->validated)
    {
      olsr_printf(1, "[WOT]Message from non-validated host!\n");
      return 0;
    }

  diff = entry->diff - (now.tv_sec - tstamp);

  olsr_printf(3, "[WOT]Timestamp slack: %d\n", diff);

  if((diff > UPPER_DIFF) || (diff < LOWER_DIFF))
    {
      olsr_printf(1, "[WOT]Timestamp scew detected!!\n");
      return 0;
    }

  /* ok - update diff */
  entry->diff = ((now.tv_sec - tstamp) + entry->diff) ?
    ((now.tv_sec - tstamp) + entry->diff) / 2 : 0;

  olsr_printf(3, "[WOT]Diff set to : %d\n", entry->diff);

  /* update validtime */

  entry->valtime = GET_TIMESTAMP(TIMESTAMP_HOLD_TIME * 1000);

  return 1;
}


/**
 * Create and send a timestamp
 * challenge message to new_host
 *
 * The host is registered in the timestamps
 * repository with valid=0
 */

int
send_challenge(struct interface *olsr_if, const union olsr_ip_addr *new_host)
{
  struct challengemsg cmsg;
  struct stamp *entry;
  olsr_u32_t challenge, hash;
  struct ipaddr_str buf;

  olsr_printf(1, "[WOT]Building CHALLENGE message\n");

  /* Set the size including OLSR packet size */


  challenge = rand() << 16;
  challenge |= rand();

  /* Fill challengemessage */
  cmsg.olsr_msgtype = TYPE_CHALLENGE;
  cmsg.olsr_vtime = 0;
  cmsg.olsr_msgsize = htons(sizeof(struct challengemsg));
  memcpy(&cmsg.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
  cmsg.ttl = 1;
  cmsg.hopcnt = 0;
  cmsg.seqno = htons(get_msg_seqno());

  /* Fill subheader */
  memcpy(&cmsg.destination, new_host, olsr_cnf->ipsize);
  cmsg.challenge = htonl(challenge);

  olsr_printf(3, "[WOT]Size: %lu\n", (unsigned long)sizeof(struct challengemsg));

  /* gpg-sign the message */
  if(!wotplugin_challenge_sign(&cmsg))
  {
	  olsr_printf(1, "[WOT]Problem signing challenge message\n");
	  return 0;
  }

  olsr_printf(3, "[WOT]Sending timestamp request to %s challenge 0x%x seqno 0x%x\n", 
	      olsr_ip_to_string(&buf, new_host),
	      challenge,
	      cmsg.seqno);

  /* Add to buffer */
  net_outbuffer_push(olsr_if, &cmsg, ntohs(cmsg.olsr_msgsize));

  /* Send the request */
  net_output(olsr_if);

  /* Create new entry */
  entry = malloc(sizeof(struct stamp));
  
  entry->diff = 0;
  entry->validated = 0;
  entry->cmsg_challenge = challenge;
//  entry->cres_challenge = 0;

  memcpy(&entry->addr, new_host, olsr_cnf->ipsize);

  /* update validtime - not validated */
  entry->conftime = GET_TIMESTAMP(EXCHANGE_HOLD_TIME * 1000);

  hash = olsr_ip_hashing(new_host);
  
  /* Queue */
  timestamps[hash].next->prev = entry;
  entry->next = timestamps[hash].next;
  timestamps[hash].next = entry;
  entry->prev = &timestamps[hash];


  return 1;

}

int
parse_cres(struct interface *olsr_if, char *in_msg)
{
  struct c_respmsg *msg;
  olsr_u8_t sha1_hash[SIGNATURE_SIZE];
  struct stamp *entry;
  struct ipaddr_str buf;

  msg = (struct c_respmsg *)in_msg;

  olsr_printf(1, "[WOT]Challenge-response message received. Seq = 0x%x\n", msg->seqno);
  olsr_printf(3, "[WOT]To: %s\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->destination));

  if(if_ifwithaddr((union olsr_ip_addr *)&msg->destination) == NULL)
    {
      olsr_printf(3, "[WOT]Not for us...\n");
      return 0;
    }

  olsr_printf(3, "[WOT]Challenge: 0x%lx\n", (unsigned long)ntohl(msg->challenge)); /* ntohl() returns a unsignedlong onwin32 */


  /* gpg-verify the signature in the message */
 if(wotplugin_cresponse_verify(msg)){
	 olsr_printf(3, "[WOT]Signature verified\n");
 } else {
      olsr_printf(1, "[WOT]Signature missmatch in challenge-response!\n");
      return 0;
 }
 
  /* Now to check the digest from the emitted challenge */
 if((entry = lookup_timestamp_entry((const union olsr_ip_addr *)&msg->originator)) == NULL)
   {
     struct ipaddr_str buf;
     olsr_printf(1, "[WOT]Received challenge-response from non-registered node %s!\n",
	  olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));
     return 0;
   }

 /* Generate the digest */
  olsr_printf(3, "[WOT]Entry-challenge 0x%x\n", entry->cmsg_challenge);

  {
  olsr_u8_t checksum_cache[512];
  /* First the challenge received */
  memcpy(checksum_cache, &entry->cmsg_challenge, 4);
  /* Then the local IP */
  memcpy(&checksum_cache[sizeof(olsr_u32_t)], &msg->originator, olsr_cnf->ipsize);

  /* Create the hash */
  CHECKSUM(checksum_cache, 
	   sizeof(olsr_u32_t) + olsr_cnf->ipsize, 
	   sha1_hash);
  
#ifdef DEBUG
  {
  int i;
  olsr_printf(3, "[WOT]checksumed this:\n");

  for(i = 0; i < sizeof(olsr_u32_t) + olsr_cnf->ipsize; i++)
	  olsr_printf(3, "%x.", checksum_cache[i]);

  olsr_printf(3, "\n");
  printchecksum(sha1_hash, "parse_cres:sha1_hash");
  printchecksum(msg->res_sig, "parse_cres:msg->res_sig");
  }
#endif
  }

  if(memcmp(msg->res_sig, sha1_hash, HASH_SIZE) != 0)
    {
      struct ipaddr_str buf;
      olsr_printf(1, "[WOT]Error in challenge signature from %s!\n",
		  olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));
      
      return 0;
    }

  olsr_printf(3, "[WOT]Challenge-response signature ok\n");

  /* Update entry! */
  entry->cmsg_challenge = 0;
  entry->validated = 1;
  entry->diff = now.tv_sec - msg->timestamp;

  /* update validtime - validated entry */
  entry->valtime = GET_TIMESTAMP(TIMESTAMP_HOLD_TIME * 1000);

  olsr_printf(1, "[WOT]%s registered with diff %d!\n",
	      olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator),
	      entry->diff);

  /* Send response-response */
  send_rres(olsr_if, (union olsr_ip_addr *)&msg->originator, 
	    (union olsr_ip_addr *)&msg->destination, 
	    ntohl(msg->challenge));

  return 1;
}


int
parse_rres(char *in_msg)
{
  struct r_respmsg *msg;
  olsr_u8_t sha1_hash[SIGNATURE_SIZE];
  struct stamp *entry;
  struct ipaddr_str buf;

  msg = (struct r_respmsg *)in_msg;

  olsr_printf(1, "[WOT]Response-response message received. Seq = 0x%x\n", msg->seqno);
  olsr_printf(3, "[WOT]To: %s\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->destination));

  if(if_ifwithaddr((union olsr_ip_addr *)&msg->destination) == NULL)
    {
      olsr_printf(1, "[WOT]Not for us...\n");
      return 0;
    }

  /* gpg-verify the signatures in the message */
 if(wotplugin_rresponse_verify(msg)){
	 olsr_printf(3, "[WOT]Response-response message signature verified\n");
 } else {
      olsr_printf(1, "[WOT]Signature missmatch in response-response!\n");
      return 0;
 }
  
 if((entry = lookup_timestamp_entry((const union olsr_ip_addr *)&msg->originator)) == NULL)
    {
      struct ipaddr_str buf;
      olsr_printf(1, "[WOT]Received response-response from non-registered node %s!\n",
		  olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));
      return 0;
    }

  /* Generate the digest */
  olsr_printf(3, "[WOT]Entry-challenge 0x%x\n", entry->cres_challenge);

  {
  olsr_u8_t checksum_cache[512];
  /* First the challenge received */
  memcpy(checksum_cache, &entry->cres_challenge, 4);
  /* Then the local IP */
  memcpy(&checksum_cache[sizeof(olsr_u32_t)], &msg->originator, olsr_cnf->ipsize);

  /* Create the hash */
  CHECKSUM(checksum_cache, 
	   sizeof(olsr_u32_t) + olsr_cnf->ipsize, 
	   sha1_hash);
#ifdef DEBUG
  {
  int i;
  olsr_printf(3, "[WOT]checksumed this:\n");

  for(i = 0; i < sizeof(olsr_u32_t) + olsr_cnf->ipsize; i++)
	  olsr_printf(3, "%x.", checksum_cache[i]);

  olsr_printf(3, "\n");
  printchecksum(sha1_hash, "parse_rres:sha1_hash");
  printchecksum(msg->res_sig, "parse_rres:msg->res_sig");
  }
#endif
  }

  if(memcmp(msg->res_sig, sha1_hash, HASH_SIZE) != 0)
    {
      struct ipaddr_str buf;
      olsr_printf(1, "[WOT]Error in response-response signature from %s!\n",
		  olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));
      
      return 0;
    }

  olsr_printf(3, "[WOT]response-response signature ok\n");

  /* Update entry! */
  entry->cres_challenge = 0;
  entry->validated = 1;
  entry->diff = now.tv_sec - msg->timestamp;

  /* update validtime - validated entry */
  entry->valtime = GET_TIMESTAMP(TIMESTAMP_HOLD_TIME * 1000);

  olsr_printf(1, "[WOT]%s registered with diff %d!\n",
	      olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator),
	      entry->diff);

  return 1;
}


int
parse_challenge(struct interface *olsr_if, char *in_msg)
{
  struct challengemsg *msg;
  struct stamp *entry;
  olsr_u32_t hash;
  struct ipaddr_str buf;
          
  msg = (struct challengemsg *)in_msg;
  
  olsr_printf(1, "[WOT]Challenge message received. Seq = 0x%x\n", msg->seqno);
  olsr_printf(3, "[WOT]To: %s\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->destination));

  if(if_ifwithaddr((union olsr_ip_addr *)&msg->destination) == NULL)
    {
      olsr_printf(1, "[WOT]Not for us...\n");
      return 0;
    }

  /* Create entry if not registered */
  if((entry = lookup_timestamp_entry((const union olsr_ip_addr *)&msg->originator)) == NULL)
    {
      entry = malloc(sizeof(struct stamp));
      memcpy(&entry->addr, &msg->originator, olsr_cnf->ipsize);

      hash = olsr_ip_hashing((union olsr_ip_addr *)&msg->originator);
  
      /* Queue */
      timestamps[hash].next->prev = entry;
      entry->next = timestamps[hash].next;
      timestamps[hash].next = entry;
      entry->prev = &timestamps[hash];
    }
  else
    {
      /* Check configuration timeout */
      if(!TIMED_OUT(entry->conftime))
	{
	  /* If registered - do not accept! */
	  olsr_printf(1, "[WOT]Challenge from registered node...dropping!\n");
	  return 0;
	}
      else
	{
	  olsr_printf(1, "[WOT]Challenge from registered node...accepted!\n");
	}
    }

  olsr_printf(3, "[WOT]Challenge: 0x%lx\n", (unsigned long)ntohl(msg->challenge)); /* ntohl() returns a unsignedlong onwin32 */

  /* gpg-verify the signature in the message */
  if(wotplugin_challenge_verify(msg)) {
	  olsr_printf(3, "[WOT]Signature verified\n");
  } else {
	  olsr_printf(1, "[WOT]Signature missmatch in challenge!\n");
	  return 0;
  };
  
  entry->diff = 0;
  entry->validated = 0;

  /* update validtime - not validated */
  entry->conftime = GET_TIMESTAMP(EXCHANGE_HOLD_TIME * 1000);

  /* Build and send response */

  send_cres(olsr_if, (union olsr_ip_addr *)&msg->originator, 
	    (union olsr_ip_addr *)&msg->destination, 
	    ntohl(msg->challenge),
	    entry);

  return 1;
}





/**
 * Build and transmit a challenge response
 * message.
 *
 */
int
send_cres(struct interface *olsr_if, union olsr_ip_addr *to, union olsr_ip_addr *from, olsr_u32_t chal_in, struct stamp *entry)
{
  struct c_respmsg crmsg;
  olsr_u32_t challenge;
  struct ipaddr_str buf;

  olsr_printf(1, "[WOT]Building CRESPONSE message\n");

  challenge = rand() << 16;
  challenge |= rand();

  entry->cres_challenge = challenge;
  //entry->cmsg_challenge = 0;

  olsr_printf(3, "[WOT]Challenge-response: 0x%x\n", challenge);

  /* Fill challengemessage */
  crmsg.olsr_msgtype = TYPE_CRESPONSE;
  crmsg.olsr_vtime = 0;
  crmsg.olsr_msgsize = htons(sizeof(struct c_respmsg));
  memcpy(&crmsg.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
  crmsg.ttl = 1;
  crmsg.hopcnt = 0;
  crmsg.seqno = htons(get_msg_seqno());

  /* set timestamp */
  crmsg.timestamp = now.tv_sec;
  olsr_printf(3, "[WOT]Timestamp %ld\n", crmsg.timestamp);

  /* Fill subheader */
  memcpy(&crmsg.destination, to, olsr_cnf->ipsize);
  crmsg.challenge = htonl(challenge);

  /* Create digest of received challenge + IP */

  {
  olsr_u8_t checksum_cache[512];
  /* Create packet + key cache */
  /* First the challenge received */
  memcpy(checksum_cache, &chal_in, 4);
  /* Then the local IP */
  memcpy(&checksum_cache[sizeof(olsr_u32_t)], from, olsr_cnf->ipsize);

  /* Create the hash */
  CHECKSUM(checksum_cache, 
	   sizeof(olsr_u32_t) + olsr_cnf->ipsize, 
	   crmsg.res_sig);

#ifdef DEBUG
  {
  int i;
  olsr_printf(3, "[WOT]checksumed this:\n");

  for(i = 0; i < sizeof(olsr_u32_t) + olsr_cnf->ipsize; i++)
	  olsr_printf(3, "%x.", checksum_cache[i]);

  olsr_printf(3, "\n");

  printchecksum(crmsg.res_sig, "send_cres");

  }
#endif
  }

  /* gpg-sign the message */
  if (wotplugin_cres_sign(&crmsg) == 0)
	  return 0;

  olsr_printf(3, "[WOT]Sending challenge-response to %s challenge 0x%x seqno 0x%x\n", 
	      olsr_ip_to_string(&buf, to),
	      challenge,
	      crmsg.seqno);

  /* Add to buffer */
  net_outbuffer_push(olsr_if, &crmsg, ntohs(crmsg.olsr_msgsize));
  /* Send the request */
  net_output(olsr_if);

  return 1;
}






/**
 * Build and transmit a response response
 * message.
 *
 */
static int
send_rres(struct interface *olsr_if, union olsr_ip_addr *to, union olsr_ip_addr *from, olsr_u32_t chal_in)
{
	struct r_respmsg rrmsg;
	struct ipaddr_str buf;
	
	olsr_printf(1, "[WOT]Building RRESPONSE message\n");
	
	
	/* Fill challengemessage */
	rrmsg.olsr_msgtype = TYPE_RRESPONSE;
	rrmsg.olsr_vtime = 0;
	rrmsg.olsr_msgsize = htons(sizeof(struct r_respmsg));
	memcpy(&rrmsg.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
	rrmsg.ttl = 1;
	rrmsg.hopcnt = 0;
	rrmsg.seqno = htons(get_msg_seqno());
	
	/* set timestamp */
	rrmsg.timestamp = now.tv_sec;
	olsr_printf(3, "[WOT]Timestamp %ld\n", rrmsg.timestamp);
	
	/* Fill subheader */
	memcpy(&rrmsg.destination, to, olsr_cnf->ipsize);
	
	
	{
	olsr_u8_t checksum_cache[512];
	/* Create packet + key cache */
	/* First the challenge received */
	memcpy(checksum_cache, &chal_in, 4);
	/* Then the local IP */
	memcpy(&checksum_cache[sizeof(olsr_u32_t)], from, olsr_cnf->ipsize);
	
	/* Create the hash */
	CHECKSUM(checksum_cache, 
	   sizeof(olsr_u32_t) + olsr_cnf->ipsize, 
	   rrmsg.res_sig);

#ifdef DEBUG
  {
  int i;
  olsr_printf(3, "[WOT]checksumed this:\n");

  for(i = 0; i < sizeof(olsr_u32_t) + olsr_cnf->ipsize; i++)
	  olsr_printf(3, "%x.", checksum_cache[i]);

  olsr_printf(3, "\n");
  printchecksum(rrmsg.res_sig, "send_rres");
  }
#endif
	}
	
	/* gpg-sign the message */
	if (wotplugin_rres_sign(&rrmsg) == 0)
		return 0;
	
	olsr_printf(3, "[WOT]Sending response-response to %s seqno 0x%x\n", 
	      olsr_ip_to_string(&buf, to),
	      rrmsg.seqno);
	
	/* add to buffer */
	net_outbuffer_push(olsr_if, &rrmsg, ntohs(rrmsg.olsr_msgsize));
	
	/* Send the request */
	net_output(olsr_if);
	
	return 1;
}



static struct stamp *
lookup_timestamp_entry(const union olsr_ip_addr *adr)
{
  olsr_u32_t hash;
  struct stamp *entry;
  struct ipaddr_str buf;

  hash = olsr_ip_hashing(adr);

  for(entry = timestamps[hash].next;
      entry != &timestamps[hash];
      entry = entry->next)
    {
      if(memcmp(&entry->addr, adr, olsr_cnf->ipsize) == 0)
	{
	  olsr_printf(3, "[WOT]Match for %s\n", olsr_ip_to_string(&buf, adr));
	  return entry;
	}
    }

  olsr_printf(1, "[WOT]No match for %s\n", olsr_ip_to_string(&buf, adr));

  return NULL;
}



/**
 *Find timed out entries and delete them
 *
 *@return nada
 */
void
timeout_timestamps(void* foo __attribute__((unused)))
{
  struct stamp *tmp_list;
  struct stamp *entry_to_delete;
  int index;

  /* Update our local timestamp */
  gettimeofday(&now, NULL);

  for(index=0;index<HASHSIZE;index++)
    {
      tmp_list = timestamps[index].next;
      /*Traverse MID list*/
      while(tmp_list != &timestamps[index])
	{
	  /*Check if the entry is timed out*/
	  if((TIMED_OUT(tmp_list->valtime)) && (TIMED_OUT(tmp_list->conftime)))
	    {
              struct ipaddr_str buf;
	      entry_to_delete = tmp_list;
	      tmp_list = tmp_list->next;

	      olsr_printf(1, "[WOT]timestamp info for %s timed out.. deleting it\n", 
			  olsr_ip_to_string(&buf, &entry_to_delete->addr));

	      /*Delete it*/
	      entry_to_delete->next->prev = entry_to_delete->prev;
	      entry_to_delete->prev->next = entry_to_delete->next;

	      free(entry_to_delete);
	    }
	  else
	      tmp_list = tmp_list->next;
	}
    }

  return;
}




