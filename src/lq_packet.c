/*
 * OLSR ad-hoc routing table management protocol
 * Copyright (C) 2003 Andreas T�nnesen (andreto@ifi.uio.no)
 * Copyright (C) 2004 Thomas Lopatic (thomas@lopatic.de)
 *
 * This file is part of the olsr.org OLSR daemon.
 *
 * olsr.org is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * olsr.org is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with olsr.org; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 * 
 * $Id: lq_packet.c,v 1.3 2004/11/05 20:58:10 tlopatic Exp $
 *
 */

#if defined USE_LINK_QUALITY
#include "olsr_protocol.h"
#include "defs.h"
#include "interfaces.h"
#include "link_set.h"
#include "neighbor_table.h"
#include "mpr_selector_set.h"
#include "mid_set.h"
#include "mantissa.h"
#include "process_package.h" // XXX - remove
#include "two_hop_neighbor_table.h"
#include "hysteresis.h"

static unsigned char msg_buffer[MAXMESSAGESIZE - OLSR_HEADERSIZE];

static void
create_lq_hello(struct lq_hello_message *lq_hello, struct interface *outif)
{
  struct lq_hello_neighbor *neigh;
  struct link_entry *walker;

  // initialize the static fields

  lq_hello->comm.type = LQ_HELLO_MESSAGE;
  lq_hello->comm.vtime = me_to_double(outif->valtimes.hello);
  lq_hello->comm.size = 0;

  COPY_IP(&lq_hello->comm.orig, &main_addr);

  lq_hello->comm.ttl = 1;
  lq_hello->comm.hops = 0;
  lq_hello->comm.seqno = get_msg_seqno();

  lq_hello->htime = me_to_double(outif->hello_etime);
  lq_hello->will = olsr_cnf->willingness;

  lq_hello->neigh = NULL;
  
  // loop through the link set

  for (walker = link_set; walker != NULL; walker = walker->next)
    {
      // allocate a neighbour entry

      neigh = olsr_malloc(sizeof (struct lq_hello_neighbor), "Build LQ_HELLO");
      
      // a) this neighbor interface IS NOT visible via the output interface

      if(!COMP_IP(&walker->local_iface_addr, &outif->ip_addr))
        neigh->link_type = UNSPEC_LINK;
      
      // b) this neighbor interface IS visible via the output interface

      else
        neigh->link_type = lookup_link_status(walker);

      // set the entry's link quality

      neigh->link_quality = walker->loss_link_quality;
      neigh->neigh_link_quality = walker->neigh_link_quality;

      // set the entry's neighbour type

      if(walker->neighbor->is_mpr)
        neigh->neigh_type = MPR_NEIGH;

      else if (walker->neighbor->status == SYM)
        neigh->neigh_type = SYM_NEIGH;

      else if (walker->neighbor->status == NOT_SYM)
        neigh->neigh_type = NOT_NEIGH;
  
      // set the entry's neighbour interface address

      COPY_IP(&neigh->addr, &walker->neighbor_iface_addr);
      
      // queue the neighbour entry

      neigh->next = lq_hello->neigh;
      lq_hello->neigh = neigh;
    }
}

static void
destroy_lq_hello(struct lq_hello_message *lq_hello)
{
  struct lq_hello_neighbor *walker, *aux;

  // loop through the queued neighbour entries and free them

  for (walker = lq_hello->neigh; walker != NULL; walker = aux)
    {
      aux = walker->next;
      free(walker);
    }

  lq_hello->neigh = NULL;
}

static void
create_lq_tc(struct lq_tc_message *lq_tc, struct interface *outif)
{
  struct lq_tc_neighbor *neigh;
  int i;
  struct neighbor_entry *walker;

  // initialize the static fields

  lq_tc->comm.type = LQ_TC_MESSAGE;
  lq_tc->comm.vtime = me_to_double(outif->valtimes.tc);
  lq_tc->comm.size = 0;

  COPY_IP(&lq_tc->comm.orig, &main_addr);

  lq_tc->comm.ttl = MAX_TTL;
  lq_tc->comm.hops = 0;
  lq_tc->comm.seqno = get_msg_seqno();

  COPY_IP(&lq_tc->from, &main_addr);

  lq_tc->ansn = ansn;

  lq_tc->neigh = NULL;
 
  // loop through all neighbours
  
  for(i = 0; i < HASHSIZE; i++)
    {
      for(walker = neighbortable[i].next; walker != &neighbortable[i];
          walker = walker->next)
        {
          // only consider symmetric neighbours

          if(walker->status != SYM)
            continue;

          // TC redundancy == 1: only consider MPRs and MPR selectors

          if (olsr_cnf->tc_redundancy == 1 && !walker->is_mpr &&
              olsr_lookup_mprs_set(&walker->neighbor_main_addr) == NULL)
            continue;

          // TC redundancy == 0: only consider MPR selectors

          else if (olsr_cnf->tc_redundancy == 0 &&
                   olsr_lookup_mprs_set(&walker->neighbor_main_addr) == NULL)
            continue;

          // allocate a neighbour entry
          
          neigh = olsr_malloc(sizeof (struct lq_tc_neighbor), "Build LQ_TC");
		
          // set the entry's main address

          COPY_IP(&neigh->main, &walker->neighbor_main_addr);

          // set the entry's link quality

          neigh->link_quality =
            olsr_neighbor_best_link_quality(&neigh->main);

          // queue the neighbour entry

          neigh->next = lq_tc->neigh;
          lq_tc->neigh = neigh;
        }
    }
}

static void
destroy_lq_tc(struct lq_tc_message *lq_tc)
{
  struct lq_tc_neighbor *walker, *aux;

  // loop through the queued neighbour entries and free them

  for (walker = lq_tc->neigh; walker != NULL; walker = aux)
    {
      aux = walker->next;
      free(walker);
    }
}

static int common_size(void)
{
  // return the size of the header shared by all OLSR messages

  return (olsr_cnf->ip_version == AF_INET) ?
    sizeof (struct olsr_header_v4) : sizeof (struct olsr_header_v6);
}

static void serialize_common(struct olsr_common *comm)
{
  struct olsr_header_v4 *olsr_head_v4;
  struct olsr_header_v6 *olsr_head_v6;

  // serialize an IPv4 OLSR message header

  if (olsr_cnf->ip_version == AF_INET)
    {
      olsr_head_v4 = (struct olsr_header_v4 *)msg_buffer;

      olsr_head_v4->type = comm->type;
      olsr_head_v4->vtime = double_to_me(comm->vtime);
      olsr_head_v4->size = htons(comm->size);

      COPY_IP(&olsr_head_v4->orig, &comm->orig);

      olsr_head_v4->ttl = comm->ttl;
      olsr_head_v4->hops = comm->hops;
      olsr_head_v4->seqno = htons(comm->seqno);
    }

  // serialize an IPv6 OLSR message header

  olsr_head_v6 = (struct olsr_header_v6 *)msg_buffer;

  olsr_head_v6->type = comm->type;
  olsr_head_v6->vtime = double_to_me(comm->vtime);
  olsr_head_v6->size = htons(comm->size);

  COPY_IP(&olsr_head_v6->orig, &comm->orig);

  olsr_head_v6->ttl = comm->ttl;
  olsr_head_v6->hops = comm->hops;
  olsr_head_v6->seqno = htons(comm->seqno);
}

static void
serialize_lq_hello(struct lq_hello_message *lq_hello, struct interface *outif)
{
  int off, rem, size, req;
  struct lq_hello_header *head;
  struct lq_hello_info_header *info_head;
  struct lq_hello_neighbor *neigh;
  unsigned char *buff;
  int is_first;
  int i, j;

  if (lq_hello == NULL || outif == NULL)
    return;

  // leave space for the OLSR header

  off = common_size();

  // initialize the LQ_HELLO header

  head = (struct lq_hello_header *)(msg_buffer + off);

  head->reserved = 0;
  head->htime = double_to_me(lq_hello->htime);
  head->will = lq_hello->will; 

  // 'off' is the offset of the byte following the LQ_HELLO header

  off += sizeof (struct lq_hello_header);

  // our work buffer starts at 'off'...

  buff = msg_buffer + off;

  // ... that's why we start with a 'size' of 0 and subtract 'off' from
  // the remaining bytes in the output buffer

  size = 0;
  rem = net_outbuffer_bytes_left(outif) - off;

  // initially, we want to put at least an info header, an IP address,
  // and the corresponding link quality into the message

  if (rem < sizeof (struct lq_hello_info_header) + ipsize + 4)
  {
    net_output(outif);

    rem = net_outbuffer_bytes_left(outif) - off;
  }

  info_head = NULL;

  // iterate through all neighbor types ('i') and all link types ('j')

  for (i = 0; i <= MAX_NEIGH; i++) 
    {
      for(j = 0; j <= MAX_LINK; j++)
        {
          if(j == HIDE_LINK)
            continue;

          is_first = 1;

          // loop through neighbors

          for (neigh = lq_hello->neigh; neigh != NULL; neigh = neigh->next)
            {  
              if (neigh->neigh_type != i || neigh->link_type != j)
                continue;

              // we need space for an IP address plus link quality
              // information

              req = ipsize + 4;

              // no, we also need space for an info header, as this is the
              // first neighbor with the current neighor type and link type

              if (is_first != 0)
                req += sizeof (struct lq_hello_info_header);

              // we do not have enough space left

              if (size + req > rem)
                {
                  // finalize the OLSR header

                  lq_hello->comm.size = size + off;

                  serialize_common((struct olsr_common *)lq_hello);

                  // finalize the info header

                  info_head->size =
                    ntohs(buff + size - (unsigned char *)info_head);
			      
                  // output packet

                  net_outbuffer_push(outif, msg_buffer, size + off);

                  net_output(outif);

                  // move to the beginning of the buffer

                  size = 0;
                  rem = net_outbuffer_bytes_left(outif) - off;

                  // we need a new info header

                  is_first = 1;
                }

              // create a new info header

              if (is_first != 0)
                {
                  info_head = (struct lq_hello_info_header *)(buff + size);
                  size += sizeof (struct lq_hello_info_header);

                  info_head->reserved = 0;
                  info_head->link_code = CREATE_LINK_CODE(i, j);
                }

              // add the current neighbor's IP address

              COPY_IP(buff + size, &neigh->addr);
              size += ipsize;

              // add the corresponding link quality

              buff[size++] = (unsigned char)(neigh->link_quality * 256);
              buff[size++] = (unsigned char)(neigh->neigh_link_quality * 256);

              // pad

              buff[size++] = 0;
              buff[size++] = 0;

              is_first = 0;
            }

          // finalize the info header, if there are any neighbors with the
          // current neighbor type and link type

          if (is_first == 0)
            info_head->size = ntohs(buff + size - (unsigned char *)info_head);
        }
    }

  // finalize the OLSR header

  lq_hello->comm.size = size + off;

  serialize_common((struct olsr_common *)lq_hello);

  // move the message to the output buffer

  net_outbuffer_push(outif, msg_buffer, size + off);
}

static void
serialize_lq_tc(struct lq_tc_message *lq_tc, struct interface *outif)
{
  int off, rem, size;
  struct lq_tc_header *head;
  struct lq_tc_neighbor *neigh;
  unsigned char *buff;

  if (lq_tc == NULL || outif == NULL)
    return;

  // leave space for the OLSR header

  off = common_size();

  // initialize the LQ_TC header

  head = (struct lq_tc_header *)(msg_buffer + off);

  head->ansn = htons(lq_tc->ansn);
  head->reserved = 0;

  // 'off' is the offset of the byte following the LQ_TC header

  off += sizeof (struct lq_tc_header);

  // our work buffer starts at 'off'...

  buff = msg_buffer + off;

  // ... that's why we start with a 'size' of 0 and subtract 'off' from
  // the remaining bytes in the output buffer

  size = 0;
  rem = net_outbuffer_bytes_left(outif) - off;

  // initially, we want to put at least an IP address and the corresponding
  // link quality into the message

  if (rem < ipsize + 4)
  {
    net_output(outif);

    rem = net_outbuffer_bytes_left(outif) - off;
  }

  // loop through neighbors

  for (neigh = lq_tc->neigh; neigh != NULL; neigh = neigh->next)
    {  
      // we need space for an IP address plus link quality
      // information

      if (size + ipsize + 4 > rem)
        {
          // finalize the OLSR header

          lq_tc->comm.size = size + off;

          serialize_common((struct olsr_common *)lq_tc);

          // output packet

          net_outbuffer_push(outif, msg_buffer, size + off);

          net_output(outif);

          // move to the beginning of the buffer

          size = 0;
          rem = net_outbuffer_bytes_left(outif) - off;
        }

      // add the current neighbor's IP address

      COPY_IP(buff + size, &neigh->main);
      size += ipsize;

      // add the corresponding link quality

      buff[size++] = (unsigned char)(neigh->link_quality * 256);

      // pad

      buff[size++] = 0;
      buff[size++] = 0;
      buff[size++] = 0;
    }

  // finalize the OLSR header

  lq_tc->comm.size = size + off;

  serialize_common((struct olsr_common *)lq_tc);

  net_outbuffer_push(outif, msg_buffer, size + off);
}

static void *deserialize_common(struct olsr_common *comm, void *ser)
{
  struct olsr_header_v4 *olsr_head_v4;
  struct olsr_header_v6 *olsr_head_v6;

  // deserialize an IPv4 OLSR message header

  if (olsr_cnf->ip_version == AF_INET)
    {
      olsr_head_v4 = (struct olsr_header_v4 *)ser;

      comm->type = olsr_head_v4->type;
      comm->vtime = me_to_double(olsr_head_v4->vtime);
      comm->size = ntohs(olsr_head_v4->size);

      COPY_IP(&comm->orig, &olsr_head_v4->orig);

      comm->ttl = olsr_head_v4->ttl;
      comm->hops = olsr_head_v4->hops;
      comm->seqno = ntohs(olsr_head_v4->seqno);

      return (void *)(olsr_head_v4 + 1);
    }

  // deserialize an IPv6 OLSR message header

  olsr_head_v6 = (struct olsr_header_v6 *)ser;

  comm->type = olsr_head_v6->type;
  comm->vtime = me_to_double(olsr_head_v6->vtime);
  comm->size = ntohs(olsr_head_v6->size);

  COPY_IP(&comm->orig, &olsr_head_v6->orig);

  comm->ttl = olsr_head_v6->ttl;
  comm->hops = olsr_head_v6->hops;
  comm->seqno = ntohs(olsr_head_v6->seqno);

  return (void *)(olsr_head_v6 + 1);
}

static void
deserialize_lq_hello(struct lq_hello_message *lq_hello, void *ser)
{
  struct lq_hello_header *head;
  struct lq_hello_info_header *info_head;
  unsigned char *curr, *limit, *limit2;
  struct lq_hello_neighbor *neigh;
  
  lq_hello->neigh = NULL;

  if (ser == NULL)
    return;

  head = (struct lq_hello_header *)
    deserialize_common((struct olsr_common *)lq_hello, ser);

  if (lq_hello->comm.type != LQ_HELLO_MESSAGE)
    return;

  limit = ((unsigned char *)ser) + lq_hello->comm.size;

  lq_hello->htime = me_to_double(head->htime);
  lq_hello->will = head->will;

  curr = (unsigned char *)(head + 1);

  while (curr < limit)
    {
      info_head = (struct lq_hello_info_header *)curr;

      limit2 = curr + ntohs(info_head->size);

      curr = (unsigned char *)(info_head + 1);
      
      while (curr < limit2)
        {
          neigh = olsr_malloc(sizeof (struct lq_tc_neighbor),
                              "LQ_HELLO deserialization");

          COPY_IP(&neigh->addr, curr);
          curr += ipsize;

          neigh->link_quality = (double)*curr++ / 256.0;
          neigh->neigh_link_quality = (double)*curr++ / 256.0;

          curr += 2;

          neigh->link_type = EXTRACT_LINK(info_head->link_code);
          neigh->neigh_type = EXTRACT_STATUS(info_head->link_code);

          neigh->next = lq_hello->neigh;
          lq_hello->neigh = neigh;
        }
    }
}

static void
deserialize_lq_tc(struct lq_tc_message *lq_tc, void *ser,
                  union olsr_ip_addr *from)
{
  struct lq_tc_header *head;
  union olsr_ip_addr *addr;
  unsigned char *curr, *limit;
  struct lq_tc_neighbor *neigh;

  lq_tc->neigh = NULL;

  if (ser == NULL)
    return;

  head = (struct lq_tc_header *)
    deserialize_common((struct olsr_common *)lq_tc, ser);

  if (lq_tc->comm.type != LQ_TC_MESSAGE)
    return;

  limit = ((unsigned char *)ser) + lq_tc->comm.size;

  addr = mid_lookup_main_addr(from);

  if (addr == 0)
    COPY_IP(&lq_tc->from, from);

  else
    COPY_IP(&lq_tc->from, addr);

  lq_tc->ansn =  ntohs(head->ansn);

  curr = (unsigned char *)(head + 1);

  while (curr < limit)
    {
      neigh = olsr_malloc(sizeof (struct lq_tc_neighbor),
                          "LQ_TC deserialization");

      COPY_IP(&neigh->main, curr);
      curr += ipsize;

      neigh->link_quality = (double)*curr / 256.0;
      curr += 4;

      neigh->next = lq_tc->neigh;
      lq_tc->neigh = neigh;
    }
}

void
olsr_output_lq_hello(void *para)
{
  struct lq_hello_message lq_hello;
  struct interface *outif = (struct interface *)para;

  // create LQ_HELLO in internal format

  create_lq_hello(&lq_hello, outif);

  // convert internal format into transmission format, send it

  serialize_lq_hello(&lq_hello, outif);

  // destroy internal format

  destroy_lq_hello(&lq_hello);

  if(net_output_pending(outif))
    net_output(outif);
}

void
olsr_output_lq_tc(void *para)
{
  static int prev_empty = 1;
  struct lq_tc_message lq_tc;
  struct interface *outif = (struct interface *)para;
  struct timeval timer;

  // create LQ_TC in internal format

  create_lq_tc(&lq_tc, outif);

  // a) the message is not empty

  if (lq_tc.neigh != NULL)
    {
      prev_empty = 0;

      // convert internal format into transmission format, send it

      serialize_lq_tc(&lq_tc, outif);
    }

  // b) this is the first empty message

  else if (prev_empty == 0)
    {
      // initialize timer

      olsr_init_timer((olsr_u32_t)(max_tc_vtime * 3) * 1000, &timer);
      timeradd(&now, &timer, &send_empty_tc);

      prev_empty = 1;

      // convert internal format into transmission format, send it

      serialize_lq_tc(&lq_tc, outif);
    }

  // c) this is not the first empty message, send if timer hasn't fired

  else if (!TIMED_OUT(&send_empty_tc))
    serialize_lq_tc(&lq_tc, outif);

  // destroy internal format

  destroy_lq_tc(&lq_tc);

  if(net_output_pending(outif) && TIMED_OUT(&fwdtimer[outif->if_nr]))
    set_buffer_timer(outif);
}

static void
process_lq_hello(struct lq_hello_message *lq_hello, struct interface *inif,
                 union olsr_ip_addr *from)
{
  struct hello_message hello;
  struct lq_hello_neighbor *neigh;
  struct hello_neighbor *new_neigh;

  // XXX - translation is ugly; everybody should use lq_hello_message :-)

  // move the static fields from LQ_HELLO to HELLO

  hello.vtime = lq_hello->comm.vtime;
  hello.htime = lq_hello->htime;

  COPY_IP(&hello.source_addr, &lq_hello->comm.orig);

  hello.packet_seq_number = lq_hello->comm.seqno;
  hello.hop_count = lq_hello->comm.hops;
  hello.ttl = lq_hello->comm.ttl;
  hello.willingness = lq_hello->will;

  // move all LQ_HELLO neighbours to HELLO

  for (neigh = lq_hello->neigh; neigh != NULL; neigh = neigh->next)
    {
      // allocate HELLO neighbour

      new_neigh = olsr_malloc(sizeof (struct hello_neighbor),
                              "LQ_HELLO translation");

      // copy fields

      new_neigh->status = neigh->neigh_type;
      new_neigh->link = neigh->link_type;
      new_neigh->link_quality = neigh->link_quality;

      COPY_IP(&new_neigh->address, &neigh->addr);

      // queue HELLO neighbour

      new_neigh->next = hello.neighbors;
      hello.neighbors = new_neigh;
    }

  olsr_hello_tap(&hello, inif, from);
}

static void
process_lq_tc(struct lq_tc_message *lq_tc, struct interface *inif,
              union olsr_ip_addr *from, union olsr_message *ser)
{
  struct tc_message tc;
  struct lq_tc_neighbor *neigh;
  struct tc_mpr_addr *new_neigh;

  // XXX - translation is ugly; everybody should use lq_tc_message :-)

  // move the static fields from LQ_TC to TC

  tc.vtime = lq_tc->comm.vtime;

  COPY_IP(&tc.source_addr, &lq_tc->from);
  COPY_IP(&tc.originator, &lq_tc->comm.orig);

  tc.packet_seq_number = lq_tc->comm.seqno;
  tc.hop_count = lq_tc->comm.hops;
  tc.ttl = lq_tc->comm.ttl;
  tc.ansn = lq_tc->ansn;

  // move all LQ_TC neighbours to TC

  for (neigh = lq_tc->neigh; neigh != NULL; neigh = neigh->next)
    {
      // allocate TC neighbour

      new_neigh = olsr_malloc(sizeof (struct tc_mpr_addr),
                              "LQ_TC translation");

      // copy fields

      new_neigh->link_quality = neigh->link_quality;

      COPY_IP(&new_neigh->address, &neigh->main);

      // queue TC neighbour

      new_neigh->next = tc.multipoint_relay_selector_address;
      tc.multipoint_relay_selector_address = new_neigh;
    }

  olsr_tc_tap(&tc, inif, from, ser);
}

void
olsr_input_lq_hello(union olsr_message *ser,
                    struct interface *inif,
                    union olsr_ip_addr *from)
{
  struct lq_hello_message lq_hello;

  // convert received packet from transmission format into internal format

  deserialize_lq_hello(&lq_hello, ser);

  // process internal format

  process_lq_hello(&lq_hello, inif, from);

  // destroy internal format

  destroy_lq_hello(&lq_hello);
}

void
olsr_input_lq_tc(union olsr_message *ser, struct interface *inif,
                 union olsr_ip_addr *from)
{
  struct lq_tc_message lq_tc;
  
  // convert received packet from transmission format into internal format

  deserialize_lq_tc(&lq_tc, ser, from);

  // process internal format

  process_lq_tc(&lq_tc, inif, from, ser);

  // destroy internal format

  destroy_lq_tc(&lq_tc);
}
#endif