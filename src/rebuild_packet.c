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
 * $Id: rebuild_packet.c,v 1.25 2007/11/16 22:56:54 bernd67 Exp $
 */


#include "rebuild_packet.h"
#include "defs.h"
#include "olsr.h"
#include "mid_set.h"
#include "mantissa.h"
#include "net_olsr.h"

/**
 *Process/rebuild HNA message. Converts the OLSR
 *packet to the internal hna_message format.
 *@param hmsg the hna_message struct in wich infomation
 *is to be put.
 *@param m the entire OLSR message revieved.
 *@return negative on error
 */

void
hna_chgestruct(struct hna_message *hmsg, const union olsr_message *m)
{
  struct hna_net_addr *hna_pairs, *tmp_pairs;
  int no_pairs, i;

  /*Check if everyting is ok*/
  if ((!m) || (m->v4.olsr_msgtype != HNA_MESSAGE))
    return;
  

  if(olsr_cnf->ip_version == AF_INET)
    {
      /* IPv4 */
      const struct hnapair *haddr = m->v4.message.hna.hna_net;

      /*
       * How many HNA pairs?
       * nextmsg contains size of
       * the addresses + 12 bytes(nextmessage, from address and the header)
       */
      no_pairs = (ntohs(m->v4.olsr_msgsize) - 12) / 8;
      
      //COPY_IP(&hmsg->originator, &m->v4.originator);
      hmsg->originator.v4.s_addr = m->v4.originator;

      hmsg->packet_seq_number = ntohs(m->v4.seqno);
      hmsg->hop_count =  m->v4.hopcnt;

      //printf("HNA from %s\n\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&hmsg->originator));

      /* Get vtime */
      hmsg->vtime = me_to_double(m->v4.olsr_vtime);

      tmp_pairs = NULL;
      hna_pairs = NULL;

      for(i = 0; i < no_pairs; i++)
	{	  
	  hna_pairs = olsr_malloc(sizeof(struct hna_net_addr), "HNA chgestruct");
	  
	  //COPY_IP(&hna_pairs->net, &haddr->addr);
          hna_pairs->net.v4.s_addr = haddr->addr;
	  //COPY_IP(&hna_pairs->netmask, &haddr->netmask);
          hna_pairs->netmask.v4 = haddr->netmask;

	  hna_pairs->next = tmp_pairs;
	  
	  tmp_pairs = hna_pairs;
	  haddr++;
	}
    }
  else
    {
      /* IPv6 */
      const struct hnapair6 *haddr6 = m->v6.message.hna.hna_net;

      /*
       * How many HNA pairs?
       * nextmsg contains size of
       * the addresses + 12 bytes(nextmessage, from address and the header)
       */
      no_pairs = (ntohs(m->v6.olsr_msgsize) - 24) / 32; /* NB 32 not 8 */
      
      //COPY_IP(&hmsg->originator, &m->v6.originator);
      hmsg->originator.v6 = m->v6.originator;
      hmsg->packet_seq_number = ntohs(m->v6.seqno);
      hmsg->hop_count =  m->v6.hopcnt;
      
      /* Get vtime */
      hmsg->vtime = me_to_double(m->v6.olsr_vtime);
      
      tmp_pairs = NULL;
      hna_pairs = NULL;
      
      for(i = 0; i < no_pairs; i++)
	{
	  
	  hna_pairs = olsr_malloc(sizeof(struct hna_net_addr), "HNA chgestruct 2");	  
	  
	  //COPY_IP(&hna_pairs->net, &haddr6->addr);
	  hna_pairs->net.v6 = haddr6->addr;
	  hna_pairs->netmask.v6 = olsr_netmask_to_prefix((const union olsr_ip_addr *)&haddr6->netmask);

	  hna_pairs->next = tmp_pairs;
	  
	  tmp_pairs = hna_pairs;
	  haddr6++;	  
	}
    }      

  /* 
     tmp_pairs = hna_pairs;
	 
     while(tmp_pairs)
     {
     printf("\t net: %s ", ip_to_string(&tmp_pairs->net));
     printf("\t mask: %s\n", ip_to_string(&tmp_pairs->netmask));
     tmp_pairs = tmp_pairs->next;
     }
     printf("\n");
  */



  hmsg->hna_net = hna_pairs;
 
}


/**
 *Process/rebuild MID message. Converts the OLSR
 *packet to the internal mid_message format.
 *@param mmsg the mid_message struct in wich infomation
 *is to be put.
 *@param m the entire OLSR message revieved.
 *@return negative on error
 */

void
mid_chgestruct(struct mid_message *mmsg, const union olsr_message *m)
{
  int i;
  struct mid_alias *alias, *alias_tmp;
  int no_aliases;

  /* Checking if everything is ok */
  if ((!m) || (m->v4.olsr_msgtype != MID_MESSAGE))
    return;

  alias = NULL;

  if(olsr_cnf->ip_version == AF_INET)
    {
      /* IPv4 */
      const struct midaddr *maddr = m->v4.message.mid.mid_addr;
      /*
       * How many aliases?
       * nextmsg contains size of
       * the addresses + 12 bytes(nextmessage, from address and the header)
       */
      no_aliases =  ((ntohs(m->v4.olsr_msgsize) - 12) / 4);

      //printf("Aliases: %d\n", no_aliases);
      //COPY_IP(&mmsg->mid_origaddr, &m->v4.originator);
      mmsg->mid_origaddr.v4.s_addr = m->v4.originator;
      //COPY_IP(&mmsg->addr, &m->v4.originator);
      mmsg->addr.v4.s_addr = m->v4.originator;
      /*seq number*/
      mmsg->mid_seqno = ntohs(m->v4.seqno);
      mmsg->mid_addr = NULL;

      /* Get vtime */
      mmsg->vtime = me_to_double(m->v4.olsr_vtime);

      //printf("Sequencenuber of MID from %s is %d\n", ip_to_string(&mmsg->addr), mmsg->mid_seqno);


      for(i = 0; i < no_aliases; i++)
	{
	  alias = olsr_malloc(sizeof(struct mid_alias), "MID chgestruct");
	  
	  //COPY_IP(&alias->alias_addr, &maddr->addr);
          alias->alias_addr.v4.s_addr = maddr->addr;
	  alias->next = mmsg->mid_addr;
	  mmsg->mid_addr = alias;
	  maddr++;
	}
      
      
      if(olsr_cnf->debug_level > 1)
	{
#ifndef NODEBUG
          struct ipaddr_str buf;
#endif
	  OLSR_PRINTF(3, "Alias list for %s: ", olsr_ip_to_string(&buf, &mmsg->mid_origaddr));
	  OLSR_PRINTF(3, "%s", olsr_ip_to_string(&buf, &mmsg->addr));
	  alias_tmp = mmsg->mid_addr;
	  while(alias_tmp)
	    {
	      OLSR_PRINTF(3, " - %s", olsr_ip_to_string(&buf, &alias_tmp->alias_addr));
	      alias_tmp = alias_tmp->next;
	    }
	  OLSR_PRINTF(3, "\n");
	}
    }
  else
    {
      /* IPv6 */
      const struct midaddr6 *maddr6 = m->v6.message.mid.mid_addr;
      /*
       * How many aliases?
       * nextmsg contains size of
       * the addresses + 12 bytes(nextmessage, from address and the header)
       */
      no_aliases =  ((ntohs(m->v6.olsr_msgsize) - 12) / 16); /* NB 16 */

      //printf("Aliases: %d\n", no_aliases);
      //COPY_IP(&mmsg->mid_origaddr, &m->v6.originator);
      mmsg->mid_origaddr.v6 = m->v6.originator;
      //COPY_IP(&mmsg->addr, &m->v6.originator);
      mmsg->addr.v6 = m->v6.originator;
      /*seq number*/
      mmsg->mid_seqno = ntohs(m->v6.seqno);
      mmsg->mid_addr = NULL;

      /* Get vtime */
      mmsg->vtime = me_to_double(m->v6.olsr_vtime);

      //printf("Sequencenuber of MID from %s is %d\n", ip_to_string(&mmsg->addr), mmsg->mid_seqno);

      for(i = 0; i < no_aliases; i++)
	{
	  alias = olsr_malloc(sizeof(struct mid_alias), "MID chgestruct 2");
	  
	  //printf("Adding alias: %s\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&maddr6->addr));
	  //COPY_IP(&alias->alias_addr, &maddr6->addr);
	  alias->alias_addr.v6 = maddr6->addr;
	  alias->next = mmsg->mid_addr;
	  mmsg->mid_addr = alias;
	   
	  maddr6++;
	}


      if(olsr_cnf->debug_level > 1)
	{
#ifndef NODEBUG
          struct ipaddr_str buf;
#endif
	  OLSR_PRINTF(3, "Alias list for %s", ip6_to_string(&buf, &mmsg->mid_origaddr.v6));
	  OLSR_PRINTF(3, "%s", ip6_to_string(&buf, &mmsg->addr.v6));

	  alias_tmp = mmsg->mid_addr;
	  while(alias_tmp)
	    {
	      OLSR_PRINTF(3, " - %s", ip6_to_string(&buf, &alias_tmp->alias_addr.v6));
	      alias_tmp = alias_tmp->next;
	    }
	  OLSR_PRINTF(3, "\n");
	}
    }

}




/**
 *Process/rebuild a message of unknown type. Converts the OLSR
 *packet to the internal unknown_message format.
 *@param umsg the unknown_message struct in wich infomation
 *is to be put.
 *@param m the entire OLSR message revieved.
 *@return negative on error
 */

void
unk_chgestruct(struct unknown_message *umsg, const union olsr_message *m)
{

  /* Checking if everything is ok */
  if (!m)
    return;


  if(olsr_cnf->ip_version == AF_INET)
    {
      /* IPv4 */
      /* address */
      //COPY_IP(&umsg->originator, &m->v4.originator);
      umsg->originator.v4.s_addr = m->v4.originator;
      /*seq number*/
      umsg->seqno = ntohs(m->v4.seqno);
      /* type */
      umsg->type = m->v4.olsr_msgtype;
    }
  else
    {
      /* IPv6 */
      /* address */
      //COPY_IP(&umsg->originator, &m->v6.originator);
      umsg->originator.v6 = m->v6.originator;
      /*seq number*/
      umsg->seqno = ntohs(m->v6.seqno);
      /* type */
      umsg->type = m->v4.olsr_msgtype;
    }
  
}



/**
 *Process/rebuild HELLO message. Converts the OLSR
 *packet to the internal hello_message format.
 *@param hmsg the hello_message struct in wich infomation
 *is to be put.
 *@param m the entire OLSR message revieved.
 *@return negative on error
 */

void
hello_chgestruct(struct hello_message *hmsg, const union olsr_message *m)
{
  const union olsr_ip_addr *hadr;
  struct hello_neighbor *nb;
  
  hmsg->neighbors = NULL;

  if ((!m) || (m->v4.olsr_msgtype != HELLO_MESSAGE))
    return;

  if(olsr_cnf->ip_version == AF_INET)
    {
      const struct hellinfo *hinf;

      /* IPv4 */
      //COPY_IP(&hmsg->source_addr, &m->v4.originator);
      hmsg->source_addr.v4.s_addr = m->v4.originator;
      hmsg->packet_seq_number = ntohs(m->v4.seqno);


      /* Get vtime */
      hmsg->vtime = me_to_double(m->v4.olsr_vtime);

      /* Get htime */
      hmsg->htime = me_to_double(m->v4.message.hello.htime);

      /* Willingness */
      hmsg->willingness = m->v4.message.hello.willingness;

      OLSR_PRINTF(3, "Got HELLO vtime: %f htime: %f\n", hmsg->vtime, hmsg->htime);

      for (hinf = m->v4.message.hello.hell_info; 
	   (const char *)hinf < ((const char *)m + (ntohs(m->v4.olsr_msgsize))); 
	   hinf = (const struct hellinfo *)((const char *)hinf + ntohs(hinf->size)))
	{
	  
	  for (hadr = (const union olsr_ip_addr  *)&hinf->neigh_addr; 
	       (const char *)hadr < (const char *)hinf + ntohs(hinf->size); 
	       hadr = (const union olsr_ip_addr *)&hadr->v6.s6_addr[4])
	    {
	      nb = olsr_malloc(sizeof (struct hello_neighbor), "HELLO chgestruct");

	      //COPY_IP(&nb->address, hadr);
	      nb->address = *hadr;

	      /* Fetch link and status */
	      nb->link = EXTRACT_LINK(hinf->link_code);
	      nb->status = EXTRACT_STATUS(hinf->link_code);

	      nb->next = hmsg->neighbors;
	      hmsg->neighbors = nb;
	    }
	}

      
    }
  else
    {
      const struct hellinfo6 *hinf6;

      /* IPv6 */
      //COPY_IP(&hmsg->source_addr, &m->v6.originator);
      hmsg->source_addr.v6 = m->v6.originator;
      //printf("parsing HELLO from %s\n", olsr_ip_to_string(&buf, &hmsg->source_addr));
      hmsg->packet_seq_number = ntohs(m->v6.seqno);

      /* Get vtime */
      hmsg->vtime = me_to_double(m->v6.olsr_vtime);

      /* Get htime */
      hmsg->htime = me_to_double(m->v6.message.hello.htime);

      /* Willingness */
      hmsg->willingness = m->v6.message.hello.willingness;

      OLSR_PRINTF(3, "Got HELLO vtime: %f htime: %f\n", hmsg->vtime, hmsg->htime);


      for (hinf6 = m->v6.message.hello.hell_info; 
	   (const char *)hinf6 < ((const char *)m + (ntohs(m->v6.olsr_msgsize))); 
	   hinf6 = (const struct hellinfo6 *)((const char *)hinf6 + ntohs(hinf6->size)))
	{

	  for (hadr = (const union olsr_ip_addr *)hinf6->neigh_addr; 
	       (const char *)hadr < (const char *)hinf6 + ntohs(hinf6->size); 
	       hadr++)
	    {
	      nb = olsr_malloc(sizeof (struct hello_neighbor), "OLSR chgestruct 2");

	      //COPY_IP(&nb->address, hadr);
	      nb->address = *hadr;

	      /* Fetch link and status */
	      nb->link = EXTRACT_LINK(hinf6->link_code);
	      nb->status = EXTRACT_STATUS(hinf6->link_code);

	      nb->next = hmsg->neighbors;
	      hmsg->neighbors = nb;
	    }
	}

    }

}
