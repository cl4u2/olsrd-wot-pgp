/*
 * OLSR ad-hoc routing table management protocol
 * Copyright (C) 2004 Andreas T�nnesen (andreto@ifi.uio.no)
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
 * $Id: tc_set.c,v 1.10 2004/11/10 12:35:30 tlopatic Exp $
 *
 */


#include "tc_set.h"
#include "olsr.h"
#include "scheduler.h"

/**
 * Initialize the topology set
 *
 */

int
olsr_init_tc()
{
  int index;
  
  /* Set timer to zero */
  send_empty_tc.tv_sec = 0;
  send_empty_tc.tv_usec = 0;

  changes = OLSR_FALSE;

  olsr_printf(5, "TC: init topo\n");

  olsr_register_timeout_function(&olsr_time_out_tc_set);

  for(index=0;index<HASHSIZE;index++)
    {
      tc_table[index].next = &tc_table[index];
      tc_table[index].prev = &tc_table[index];
    }

  return 1;
}


/**
 *Delete a TC entry if it has no associated
 *destinations
 *
 *@param entry the TC entry to check and possibly delete
 *
 *@return 1 if entry deleted 0 if not
 */

int
olsr_tc_delete_entry_if_empty(struct tc_entry *entry)
{

  //olsr_printf(1, "TC: del entry if empty\n");

  if(entry->destinations.next == &entry->destinations)
    {
      /* dequeue */
      DEQUEUE_ELEM(entry);
      //entry->prev->next = entry->next;
      //entry->next->prev = entry->prev;
      olsr_printf(1, "TC-SET: Deleting empty entry %s ->\n", olsr_ip_to_string(&entry->T_last_addr));
      free(entry);
      return 1;
    }
  return 0;
}



/**
 * Look up a entry from the TC tabe based
 * on address
 *
 *@param adr the address to look for
 *
 *@return the entry found or NULL
 */

struct tc_entry *
olsr_lookup_tc_entry(union olsr_ip_addr *adr)
{
  struct tc_entry *entries;
  olsr_u32_t hash;

  //olsr_printf(1, "TC: lookup entry\n");

  hash = olsr_hashing(adr);

  for(entries = tc_table[hash].next; 
      entries != &tc_table[hash]; 
      entries = entries->next)
    {
      //printf("TC lookup checking: %s\n", olsr_ip_to_string(&entries->T_last_addr));
      if(COMP_IP(adr, &entries->T_last_addr))
	return entries;
    }

  return NULL;
}


/**
 *Add a new tc_entry to the tc set
 *
 *@param (last)adr address of the entry
 *
 *@return a pointer to the created entry
 */

struct tc_entry *
olsr_add_tc_entry(union olsr_ip_addr *adr)
{
  struct tc_entry *new_entry;
  olsr_u32_t hash;

  olsr_printf(1, "TC: adding entry %s\n", olsr_ip_to_string(adr));

  hash = olsr_hashing(adr);

  new_entry = olsr_malloc(sizeof(struct tc_entry), "New TC entry");

  /* Fill entry */
  COPY_IP(&new_entry->T_last_addr, adr);
  new_entry->destinations.next = &new_entry->destinations;
  new_entry->destinations.prev = &new_entry->destinations;

  /* Queue entry */
  QUEUE_ELEM(tc_table[hash], new_entry);
  /*
  new_entry->next = tc_table[hash].next;
  new_entry->prev = tc_table[hash].next->prev;
  tc_table[hash].next->prev = new_entry;
  tc_table[hash].next = new_entry;
  */

  return new_entry;
}


/**
 *Delete all destinations that have a
 *lower ANSN than the one in the message
 *
 *@param entry the entry to delete destenations from
 *@param msg the message to fetch the ANSN from
 *
 *@return 1 if any destinations were deleted 0 if not
 */

int
olsr_tc_delete_mprs(struct tc_entry *entry, struct tc_message *msg)
{
  struct topo_dst *tmp_dsts, *dst_to_del;
  int retval;

  //olsr_printf(5, "TC: deleting MPRS\n");

  tmp_dsts = entry->destinations.next;
  retval = 0;

  while(tmp_dsts != &entry->destinations)
    {
      if(SEQNO_GREATER_THAN(msg->ansn, tmp_dsts->T_seq))
	{
	  /* Delete entry */
	  dst_to_del = tmp_dsts;
	  tmp_dsts = tmp_dsts->next;

	  /* dequeue */
	  DEQUEUE_ELEM(dst_to_del);

	  free(dst_to_del);
	  retval = 1;
	}
      else
	tmp_dsts = tmp_dsts->next;

    }

  return retval;
}


/**
 *Update the destinations registered on an entry.
 *Creates new dest-entries if not registered.
 *Bases update on a receivied TC message
 *
 *@param entry the TC entry to check
 *@msg the TC message to update by
 *
 *@return 1 if entries are added 0 if not
 */

int
olsr_tc_update_mprs(struct tc_entry *entry, struct tc_message *msg)
{
  struct tc_mpr_addr *mprs;
  struct topo_dst *new_topo_dst, *existing_dst;
  int retval;

  //olsr_printf(1, "TC: update MPRS\n");

  retval = 0;


  mprs = msg->multipoint_relay_selector_address;
  
  /* Add all the MPRs */

  while(mprs != NULL)
    {
      existing_dst = olsr_tc_lookup_dst(entry, &mprs->address);

      if(existing_dst == NULL)
	{
	  /* New entry */
	  new_topo_dst = olsr_malloc(sizeof(struct topo_dst), "add TC destination");

	  COPY_IP(&new_topo_dst->T_dest_addr, &mprs->address);
	  olsr_get_timestamp((olsr_u32_t) msg->vtime*1000, &new_topo_dst->T_time);
	  new_topo_dst->T_seq = msg->ansn;

#if defined USE_LINK_QUALITY
    if (olsr_cnf->lq_level > 0)
      {
        new_topo_dst->link_quality = mprs->neigh_link_quality;
        new_topo_dst->inverse_link_quality = mprs->link_quality;
      }
#endif

	  /* Add to queue */
	  new_topo_dst->prev = &entry->destinations;
	  new_topo_dst->next = entry->destinations.next;
	  entry->destinations.next->prev = new_topo_dst;
	  entry->destinations.next = new_topo_dst;

	  retval = 1;
	}
      else
	{
	  /* Update entry */
	  olsr_get_timestamp((olsr_u32_t) msg->vtime*1000, &existing_dst->T_time);
	  existing_dst->T_seq = msg->ansn;

#if defined USE_LINK_QUALITY
          if (olsr_cnf->lq_level > 0)
            {
              double saved_lq, rel_lq;

              saved_lq = existing_dst->link_quality;

              if (saved_lq == 0.0)
                saved_lq = -1.0;

              existing_dst->link_quality = mprs->neigh_link_quality;

              rel_lq = existing_dst->link_quality / saved_lq;

              if (rel_lq > 1.1 || rel_lq < 0.9)
                retval = 1;

              saved_lq = existing_dst->inverse_link_quality;

              if (saved_lq == 0.0)
                saved_lq = -1.0;

              existing_dst->inverse_link_quality = mprs->link_quality;

              rel_lq = existing_dst->inverse_link_quality / saved_lq;

              if (rel_lq > 1.1 || rel_lq < 0.9)
                retval = 1;
            }
#endif
	}

      mprs = mprs->next;
    }

  return retval;
}



/**
 *Lookup a destination in a TC entry
 *
 *@param entry the entry to check
 *@param dst_addr the destination address to check for
 *
 *@return a pointer to the topo_dst found - or NULL
 */
struct topo_dst *
olsr_tc_lookup_dst(struct tc_entry *entry, union olsr_ip_addr *dst_addr)
{
  struct topo_dst *dsts;
  
  //olsr_printf(1, "TC: lookup dst\n");

  for(dsts = entry->destinations.next; 
      dsts != &entry->destinations; 
      dsts = dsts->next)
    {
      if(COMP_IP(dst_addr, &dsts->T_dest_addr))
	return dsts;
    }
  return NULL;
}






/**
 * Time out entries
 *
 *@return nada
 */

void
olsr_time_out_tc_set()
{
  int index, deleted;
  struct tc_entry *entry, *entry2;
  struct topo_dst *dst_entry, *dst_to_delete;


  for(index=0;index<HASHSIZE;index++)
    {
      /* For all TC entries */
      entry = tc_table[index].next;
      while(entry != &tc_table[index])
	{
	  //printf("INDEX: %d\n", index);
	  /* For all destination entries of that TC entry */
	  deleted = 0;
	  dst_entry = entry->destinations.next;
	  while(dst_entry != &entry->destinations)
	    {
	      /* If timed out - delete */
	      if(TIMED_OUT(&dst_entry->T_time))
		{
		  deleted = 1;
		  /* Dequeue */
		  DEQUEUE_ELEM(dst_entry);
		  //dst_entry->prev->next = dst_entry->next;
		  //dst_entry->next->prev = dst_entry->prev;

		  dst_to_delete = dst_entry;

		  dst_entry = dst_entry->next;

		  /* Delete */
		  free(dst_to_delete);

		}
	      else
		dst_entry = dst_entry->next;
	    }
	  /* Delete entry if no destinations */
	  entry2 = entry;
	  entry = entry->next;
	  if(deleted)
	    olsr_tc_delete_entry_if_empty(entry2);
	}
    }

  return;
}


/**
 *Print the topology table to stdout
 */
int
olsr_print_tc_table()
{
  int index;
  struct tc_entry *entry;
  struct topo_dst *dst_entry;
  
  olsr_printf(1, "topology table: %02d:%02d:%02d.%06lu\n",nowtm->tm_hour, nowtm->tm_min, nowtm->tm_sec, now.tv_usec);

  for(index=0;index<HASHSIZE;index++)
    {
      /* For all TC entries */
      entry = tc_table[index].next;
      while(entry != &tc_table[index])
	{
	  /* For all destination entries of that TC entry */
	  dst_entry = entry->destinations.next;
	  while(dst_entry != &entry->destinations)
	    {
	      olsr_printf(1, "%s", olsr_ip_to_string(&entry->T_last_addr));
	      olsr_printf(1, " -> %s\n", olsr_ip_to_string(&dst_entry->T_dest_addr));
	      dst_entry = dst_entry->next;
	    }
	  entry = entry->next;
	}
      
    }

  olsr_printf(1, "\n");
  
  return 1;
}
