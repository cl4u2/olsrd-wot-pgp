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
 * $Id: link_set.c,v 1.47 2005/02/12 22:42:34 kattemat Exp $
 */


/*
 * Link sensing database for the OLSR routing daemon
 */

#include "link_set.h"
#include "hysteresis.h"
#include "mid_set.h"
#include "mpr.h"
#include "olsr.h"
#include "scheduler.h"
#include "link_layer.h"
#include "lq_route.h"


static int
check_link_status(struct hello_message *message, struct interface *in_if);

static void
olsr_time_out_hysteresis(void);

static void olsr_time_out_packet_loss(void);

static struct link_entry *
add_new_entry(union olsr_ip_addr *, union olsr_ip_addr *, union olsr_ip_addr *, double, double);

static void
olsr_time_out_link_set(void);

static int
get_neighbor_status(union olsr_ip_addr *);

static inline struct link_entry *
find_best_link(union olsr_ip_addr *);



void
olsr_init_link_set()
{

  /* Timers */
  hold_time_neighbor = (NEIGHB_HOLD_TIME*1000) / system_tick_divider;

  olsr_register_timeout_function(&olsr_time_out_link_set);
  if(olsr_cnf->use_hysteresis)
    {
      olsr_register_timeout_function(&olsr_time_out_hysteresis);
    }

  if (olsr_cnf->lq_level > 0)
    {
      olsr_register_timeout_function(&olsr_time_out_packet_loss);
    }
}



/**
 * Get the status of a link. The status is based upon different
 * timeouts in the link entry.
 *
 *@param remote address of the remote interface
 *
 *@return the link status of the link
 */
int
lookup_link_status(struct link_entry *entry)
{

  if(entry == NULL || link_set == NULL)
    return UNSPEC_LINK;

  /*
   * Hysteresis
   */
  if(olsr_cnf->use_hysteresis)
    {
      /*
	if L_LOST_LINK_time is not expired, the link is advertised
	with a link type of LOST_LINK.
      */

      if(!TIMED_OUT(entry->L_LOST_LINK_time))
	return LOST_LINK;
      /*
	otherwise, if L_LOST_LINK_time is expired and L_link_pending
	is set to "true", the link SHOULD NOT be advertised at all;
      */
      if(entry->L_link_pending == 1)
	{
#ifdef DEBUG
	  olsr_printf(3, "HYST[%s]: Setting to HIDE\n", olsr_ip_to_string(&entry->neighbor_iface_addr));
#endif
	  return HIDE_LINK;
	}
      /*
	otherwise, if L_LOST_LINK_time is expired and L_link_pending
	is set to "false", the link is advertised as described
	previously in section 6.
      */
    }

  if(!TIMED_OUT(entry->SYM_time))
    return SYM_LINK;

  if(!TIMED_OUT(entry->ASYM_time))
    return ASYM_LINK;

  return LOST_LINK;


}






/**
 *Find the "best" link status to a
 *neighbor
 *
 *@param address the address to check for
 *
 *@return SYM_LINK if a symmetric link exists 0 if not
 */
static int
get_neighbor_status(union olsr_ip_addr *address)
{
  union olsr_ip_addr *main_addr;
  struct interface   *ifs;

  //printf("GET_NEIGHBOR_STATUS\n");

  /* Find main address */
  if(!(main_addr = mid_lookup_main_addr(address)))
    main_addr = address;

  //printf("\tmain: %s\n", olsr_ip_to_string(main_addr));

  /* Loop trough local interfaces to check all possebilities */
  for(ifs = ifnet; ifs != NULL; ifs = ifs->int_next)
    {
      struct mid_address   *aliases;
      struct link_entry  *link;

      //printf("\tChecking %s->", olsr_ip_to_string(&ifs->ip_addr));
      //printf("%s : ", olsr_ip_to_string(main_addr)); 
      if((link = lookup_link_entry(main_addr, &ifs->ip_addr)) != NULL)
	{
	  //printf("%d\n", lookup_link_status(link));
	  if(lookup_link_status(link) == SYM_LINK)
	    return SYM_LINK;
	}
      /* Get aliases */
      for(aliases = mid_lookup_aliases(main_addr);
	  aliases != NULL;
	  aliases = aliases->next_alias)
	{
	  //printf("\tChecking %s->", olsr_ip_to_string(&ifs->ip_addr));
	  //printf("%s : ", olsr_ip_to_string(&aliases->address)); 
	  if((link = lookup_link_entry(&aliases->alias, &ifs->ip_addr)) != NULL)
	    {
	      //printf("%d\n", lookup_link_status(link));

	      if(lookup_link_status(link) == SYM_LINK)
		return SYM_LINK;
	    }
	}
    }
  
  return 0;
}


/**
 *Find the best link to a neighbor interface 
 *
 */

static inline struct link_entry *
find_best_link(union olsr_ip_addr *remote)
{
  struct link_entry *tmp_link_set, *entry;
  int curr_metric = MAX_IF_METRIC;
  float curr_lq = -1.0;

  tmp_link_set = link_set;
  entry = NULL;

  while(tmp_link_set)
    {
      if(COMP_IP(remote, &tmp_link_set->neighbor_iface_addr))
	{
	  struct interface *tmp_if = if_ifwithaddr(&tmp_link_set->local_iface_addr);

	  if (olsr_cnf->lq_level == 0)
	    {
	      if(tmp_if->int_metric < curr_metric)
		{
		  entry = tmp_link_set;
		  curr_metric = tmp_if->int_metric;
		}
	    }
	  else
	    {
	      float tmp_lq = tmp_link_set->loss_link_quality *
		tmp_link_set->neigh_link_quality;

	      if (tmp_lq > curr_lq)
		{
		  entry = tmp_link_set;
		  curr_lq = tmp_lq;
		}
	    }
	}
	  tmp_link_set = tmp_link_set->next;
    }
  
  return entry;
}


/**
 * Find best link to a neighbor
 */

struct link_entry *
get_best_link_to_neighbor(union olsr_ip_addr *remote)
{
  struct link_entry *good_link = NULL, *backup_link = NULL;
  int curr_metric = MAX_IF_METRIC;
  float curr_lq = -1.0;
  union olsr_ip_addr *main_addr;
  struct mid_address *aliases, main_alias;
  
  /* Find main address */
  if(!(main_addr = mid_lookup_main_addr(remote)))
    main_addr = remote;

  COPY_IP(&main_alias.alias, main_addr);
  main_alias.next_alias = mid_lookup_aliases(main_addr);

  for(aliases = &main_alias;
      aliases != NULL;
      aliases = aliases->next_alias)
    {
      struct link_entry *link;

      if((link = find_best_link(&aliases->alias)) != NULL)
	{
	  if (olsr_cnf->lq_level == 0)
	    {
	      struct interface *tmp_if = if_ifwithaddr(&link->local_iface_addr);
	      if((tmp_if->int_metric < curr_metric) ||
		 /* Prefer the requested link */
		 ((tmp_if->int_metric == curr_metric) && 
		  COMP_IP(&link->local_iface_addr, remote)))
		{
		  curr_metric = tmp_if->int_metric;
		  if(lookup_link_status(link) == SYM_LINK)
		    good_link = link;
		  else
		    backup_link = link;
		}
	    }
	  else
	    {
	      float tmp_lq = link->loss_link_quality *
		link->neigh_link_quality;
	      
	      if((tmp_lq > curr_lq) ||
		 /* Prefer the requested link */
		 ((tmp_lq == curr_lq) && 
		  COMP_IP(&link->local_iface_addr, remote)))		  
		{
		  curr_lq = tmp_lq;
		  if(lookup_link_status(link) == SYM_LINK)
		    good_link = link;
		  else
		    backup_link = link;
		}
	    } 
	}
    }

  return good_link ? good_link : backup_link;
}




/**
 *Nothing mysterious here.
 *Adding a new link entry to the link set.
 *
 *@param local the local IP address
 *@param remote the remote IP address
 *@param remote_main teh remote nodes main address
 *@param vtime the validity time of the entry
 *@param htime the HELLO interval of the remote node
 */

static struct link_entry *
add_new_entry(union olsr_ip_addr *local, union olsr_ip_addr *remote, union olsr_ip_addr *remote_main, double vtime, double htime)
{
  struct link_entry *tmp_link_set, *new_link;
  struct neighbor_entry *neighbor;
#ifdef linux
  struct interface *local_if;
#endif

  tmp_link_set = link_set;

  while(tmp_link_set)
    {
      if(COMP_IP(remote, &tmp_link_set->neighbor_iface_addr) &&
	 COMP_IP(local, &tmp_link_set->local_iface_addr))
	return tmp_link_set;
      tmp_link_set = tmp_link_set->next;
    }

  /*
   * if there exists no link tuple with
   * L_neighbor_iface_addr == Source Address
   */

#ifdef DEBUG
  olsr_printf(3, "Adding %s to link set\n", olsr_ip_to_string(remote));
#endif

  /* a new tuple is created with... */

  new_link = olsr_malloc(sizeof(struct link_entry), "new link entry");

  memset(new_link, 0 , sizeof(struct link_entry));
  /*
   * L_local_iface_addr = Address of the interface
   * which received the HELLO message
   */
  //printf("\tLocal IF: %s\n", olsr_ip_to_string(local));
  COPY_IP(&new_link->local_iface_addr, local);
  /* L_neighbor_iface_addr = Source Address */
  COPY_IP(&new_link->neighbor_iface_addr, remote);

  /* L_SYM_time            = current time - 1 (expired) */
  new_link->SYM_time = now_times - 1;

  /* L_time = current time + validity time */
  new_link->time = GET_TIMESTAMP(vtime*1000);


  /* HYSTERESIS */
  if(olsr_cnf->use_hysteresis)
    {
      new_link->L_link_pending = 1;
      new_link->L_LOST_LINK_time = GET_TIMESTAMP(vtime*1000);
      new_link->hello_timeout = GET_TIMESTAMP(htime*1500);
      new_link->last_htime = htime;
      new_link->olsr_seqno = 0;
      new_link->olsr_seqno_valid = OLSR_FALSE;
    }

  new_link->L_link_quality = 0.0;

  if (olsr_cnf->lq_level > 0)
    {
      new_link->loss_hello_int = htime;

      new_link->loss_timeout = GET_TIMESTAMP(htime * 1500.0);

      new_link->loss_seqno = 0;
      new_link->loss_seqno_valid = 0;
      new_link->loss_missed_hellos = 0;

      new_link->lost_packets = 0;
      new_link->total_packets = 0;

      new_link->loss_window_size = olsr_cnf->lq_wsize;
      new_link->loss_index = 0;

      memset(new_link->loss_bitmap, 0, sizeof (new_link->loss_bitmap));
    }

  new_link->loss_link_quality = 0.0;
  new_link->neigh_link_quality = 0.0;

  new_link->saved_loss_link_quality = 0.0;
  new_link->saved_neigh_link_quality = 0.0;

  /* Add to queue */
  new_link->next = link_set;
  link_set = new_link;


  /*
   * Create the neighbor entry
   */

  /* Neighbor MUST exist! */
  if(NULL == (neighbor = olsr_lookup_neighbor_table(remote_main)))
    {
      neighbor = olsr_insert_neighbor_table(remote_main);
#ifdef DEBUG
      olsr_printf(3, "ADDING NEW NEIGHBOR ENTRY %s FROM LINK SET\n", olsr_ip_to_string(remote_main));
#endif
    }

  /* Copy the main address - make sure this is done every time
   * as neighbors might change main address */
  COPY_IP(&neighbor->neighbor_main_addr, remote_main);

  neighbor->linkcount++;


  new_link->neighbor = neighbor;

  if(!COMP_IP(remote, remote_main))
    {
      /* Add MID alias if not already registered */
      /* This is kind of sketchy... and not specified
       * in the RFC. We can only guess a vtime.
       * We'll go for one that is hopefully long
       * enough in most cases. 20 seconds
       */
      olsr_printf(1, "Adding MID alias main %s ", olsr_ip_to_string(remote_main));
      olsr_printf(1, "-> %s based on HELLO\n\n", olsr_ip_to_string(remote));
      insert_mid_alias(remote_main, remote, 20.0);
    }

  /* Add to link-layer spy list */
#ifdef linux
  if(llinfo)
    {
      local_if = if_ifwithaddr(local);
      
      olsr_printf(1, "Adding %s to spylist of interface %s\n", olsr_ip_to_string(remote), local_if->int_name);

      if((local_if != NULL) && (add_spy_node(remote, local_if->int_name)))
	new_link->spy_activated = 1;
    }
#endif

  return link_set;
}


/**
 *Lookup the status of a link.
 *
 *@param int_addr address of the remote interface
 *
 *@return 1 of the link is symmertic 0 if not
 */

int
check_neighbor_link(union olsr_ip_addr *int_addr)
{
  struct link_entry *tmp_link_set;

  tmp_link_set = link_set;

  while(tmp_link_set)
    {
      if(COMP_IP(int_addr, &tmp_link_set->neighbor_iface_addr))
	return lookup_link_status(tmp_link_set);
      tmp_link_set = tmp_link_set->next;
    }
  return UNSPEC_LINK;
}


/**
 *Lookup a link entry
 *
 *@param remote the remote interface address
 *@param local the local interface address
 *
 *@return the link entry if found, NULL if not
 */
struct link_entry *
lookup_link_entry(union olsr_ip_addr *remote, union olsr_ip_addr *local)
{
  struct link_entry *tmp_link_set;

  tmp_link_set = link_set;

  while(tmp_link_set)
    {
      if(COMP_IP(remote, &tmp_link_set->neighbor_iface_addr) &&
	 COMP_IP(local, &tmp_link_set->local_iface_addr))
	return tmp_link_set;
      tmp_link_set = tmp_link_set->next;
    }
  return NULL;

}







/**
 *Update a link entry. This is the "main entrypoint" in
 *the link-sensing. This function is calles from the HELLO
 *parser function.
 *It makes sure a entry is updated or created.
 *
 *@param local the local IP address
 *@param remote the remote IP address
 *@param message the HELLO message
 *@param in_if the interface on which this HELLO was received
 *
 *@return the link_entry struct describing this link entry
 */
struct link_entry *
update_link_entry(union olsr_ip_addr *local, union olsr_ip_addr *remote, struct hello_message *message, struct interface *in_if)
{
  int status;
  struct link_entry *entry;
#ifdef linux
  struct interface *local_if;
#endif

  /* Add if not registered */
  entry = add_new_entry(local, remote, &message->source_addr, message->vtime, message->htime);

  /* Update link layer info */
  /* Add to link-layer spy list */
#ifdef linux
  if(llinfo && !entry->spy_activated)
    {
      local_if = if_ifwithaddr(local);
      
      olsr_printf(1, "Adding %s to spylist of interface %s\n", olsr_ip_to_string(remote), local_if->int_name);

      if((local_if != NULL) && (add_spy_node(remote, local_if->int_name)))
	entry->spy_activated = 1;
    }
#endif

  /* Update ASYM_time */
  //printf("Vtime is %f\n", message->vtime);
  /* L_ASYM_time = current time + validity time */
  entry->ASYM_time = GET_TIMESTAMP(message->vtime*1000);
  
  status = check_link_status(message, in_if);
  
  //printf("Status %d\n", status);
  
  switch(status)
    {
    case(LOST_LINK):
      /* L_SYM_time = current time - 1 (i.e., expired) */
      entry->SYM_time = now_times - 1;

      break;
    case(SYM_LINK):
    case(ASYM_LINK):
      /* L_SYM_time = current time + validity time */
      //printf("updating SYM time for %s\n", olsr_ip_to_string(remote));
      entry->SYM_time = GET_TIMESTAMP(message->vtime*1000);

      /* L_time = L_SYM_time + NEIGHB_HOLD_TIME */
      entry->time = entry->SYM_time + hold_time_neighbor;

      break;
    default:;
    }

  /* L_time = max(L_time, L_ASYM_time) */
  if(entry->time < entry->ASYM_time)
    entry->time = entry->ASYM_time;


  /*
  printf("Updating link LOCAL: %s ", olsr_ip_to_string(local));
  printf("REMOTE: %s\n", olsr_ip_to_string(remote));
  printf("VTIME: %f ", message->vtime);
  printf("STATUS: %d\n", status);
  */

  /* Update hysteresis values */
  if(olsr_cnf->use_hysteresis)
    olsr_process_hysteresis(entry);

  /* update neighbor status */
  status = get_neighbor_status(remote);

  /* Update neighbor */
  update_neighbor_status(entry->neighbor, status);

  return entry;  
}


/**
 * Fuction that updates all registered pointers to
 * one neighbor entry with another pointer
 * Used by MID updates.
 *
 *@old the pointer to replace
 *@new the pointer to use instead of "old"
 *
 *@return the number of entries updated
 */
int
replace_neighbor_link_set(struct neighbor_entry *old,
			  struct neighbor_entry *new)
{
  struct link_entry *tmp_link_set;
  int retval;

  retval = 0;

  if(link_set == NULL)
    return retval;
      
  tmp_link_set = link_set;

  while(tmp_link_set)
    {

      if(tmp_link_set->neighbor == old)
	{
	  tmp_link_set->neighbor = new;
	  retval++;
	}
      tmp_link_set = tmp_link_set->next;
    }

  return retval;

}


/**
 *Checks the link status to a neighbor by
 *looking in a received HELLO message.
 *
 *@param message the HELLO message to check
 *
 *@return the link status
 */
static int
check_link_status(struct hello_message *message, struct interface *in_if)
{
  struct hello_neighbor  *neighbors;

  neighbors = message->neighbors;
  
  while(neighbors!=NULL)
    {
      if(COMP_IP(&neighbors->address, &in_if->ip_addr))
        {
	  //printf("ok");
	  return neighbors->link;
	}

      neighbors = neighbors->next; 
    }


  return UNSPEC_LINK;
}


/**
 *Time out the link set. In other words, the link
 *set is traversed and all non-valid entries are
 *deleted.
 *
 */
static void
olsr_time_out_link_set()
{

  struct link_entry *tmp_link_set, *last_link_entry;

  if(link_set == NULL)
    return;
      
  tmp_link_set = link_set;
  last_link_entry = NULL;

  while(tmp_link_set)
    {

      if(TIMED_OUT(tmp_link_set->time))
	{
	  if(last_link_entry != NULL)
	    {
	      last_link_entry->next = tmp_link_set->next;

	      /* Delete neighbor entry */
	      if(tmp_link_set->neighbor->linkcount == 1)
		olsr_delete_neighbor_table(&tmp_link_set->neighbor->neighbor_main_addr);
	      else
		tmp_link_set->neighbor->linkcount--;

	      //olsr_delete_neighbor_if_no_link(&tmp_link_set->neighbor->neighbor_main_addr);
	      changes_neighborhood = OLSR_TRUE;

	      free(tmp_link_set);
	      tmp_link_set = last_link_entry;
	    }
	  else
	    {
	      link_set = tmp_link_set->next; /* CHANGED */

	      /* Delete neighbor entry */
	      if(tmp_link_set->neighbor->linkcount == 1)
		olsr_delete_neighbor_table(&tmp_link_set->neighbor->neighbor_main_addr);
	      else
		tmp_link_set->neighbor->linkcount--;

	      changes_neighborhood = OLSR_TRUE;

	      free(tmp_link_set);
	      tmp_link_set = link_set;
	      continue;
	    }	    
	}
      
      last_link_entry = tmp_link_set;
      tmp_link_set = tmp_link_set->next;
    }

  return;
}




/**
 *Updates links that we have not received
 *HELLO from in expected time according to 
 *hysteresis.
 *
 *@return nada
 */
static void
olsr_time_out_hysteresis()
{

  struct link_entry *tmp_link_set;

  if(link_set == NULL)
    return;

  tmp_link_set = link_set;

  while(tmp_link_set)
    {
      if(TIMED_OUT(tmp_link_set->hello_timeout))
	{
	  int status;

	  tmp_link_set->L_link_quality = olsr_hyst_calc_instability(tmp_link_set->L_link_quality);
	  olsr_printf(1, "HYST[%s] HELLO timeout %0.3f\n", olsr_ip_to_string(&tmp_link_set->neighbor_iface_addr), tmp_link_set->L_link_quality);
	  /* Update hello_timeout - NO SLACK THIS TIME */
	  tmp_link_set->hello_timeout = GET_TIMESTAMP(tmp_link_set->last_htime*1000);
	  /* Recalculate status */
	  /* Update hysteresis values */
	  olsr_process_hysteresis(tmp_link_set);
	  
	  /* update neighbor status */
	  status = get_neighbor_status(&tmp_link_set->neighbor_iface_addr);


	  /* Update neighbor */
	  update_neighbor_status(tmp_link_set->neighbor, status);

	  /* Update seqno - not mentioned in the RFC... kind of a hack.. */
	  tmp_link_set->olsr_seqno++;
	}
      tmp_link_set = tmp_link_set->next;
    }

  return;
}

void olsr_print_link_set(void)
{
  struct link_entry *walker;
  char *fstr;

  olsr_printf(1, "\n--- %02d:%02d:%02d.%02d ---------------------------------------------------- LINKS\n\n",
              nowtm->tm_hour,
              nowtm->tm_min,
              nowtm->tm_sec,
              now.tv_usec/10000);

  if (olsr_cnf->ip_version == AF_INET)
  {
    olsr_printf(1, "IP address       hyst   LQ     lost   total  NLQ    ETX\n");
    fstr = "%-15s  %5.3f  %5.3f  %-3d    %-3d    %5.3f  %.2f\n";
  }

  else
  {
    olsr_printf(1, "IP address                               hyst   LQ     lost   total  NLQ    ETX\n");
    fstr = "%-39s  %5.3f  %5.3f  %-3d    %-3d    %5.3f  %.2f\n";
  }

  for (walker = link_set; walker != NULL; walker = walker->next)
  {
    float etx;

    if (walker->loss_link_quality < MIN_LINK_QUALITY ||
        walker->neigh_link_quality < MIN_LINK_QUALITY)
      etx = 0.0;

    else
      etx = 1.0 / (walker->loss_link_quality * walker->neigh_link_quality);

    olsr_printf(1, fstr, olsr_ip_to_string(&walker->neighbor_iface_addr),
                walker->L_link_quality, walker->loss_link_quality,
		walker->lost_packets, walker->total_packets,
		walker->neigh_link_quality, etx);
  }
}

static void update_packet_loss_worker(struct link_entry *entry, int lost)
{
  unsigned char mask = 1 << (entry->loss_index & 7);
  int index = entry->loss_index >> 3;
  double rel_lq, saved_lq;

  if (lost == 0)
    {
      // packet not lost

      if ((entry->loss_bitmap[index] & mask) != 0)
        {
          // but the packet that we replace was lost
          // => decrement packet loss

          entry->loss_bitmap[index] &= ~mask;
          entry->lost_packets--;
        }
    }

  else
    {
      // packet lost

      if ((entry->loss_bitmap[index] & mask) == 0)
        {
          // but the packet that we replace was not lost
          // => increment packet loss

          entry->loss_bitmap[index] |= mask;
          entry->lost_packets++;
        }
    }

  // move to the next packet

  entry->loss_index++;

  // wrap around at the end of the packet loss window

  if (entry->loss_index >= entry->loss_window_size)
    entry->loss_index = 0;

  // count the total number of handled packets up to the window size

  if (entry->total_packets < entry->loss_window_size)
    entry->total_packets++;

  // the current reference link quality

  saved_lq = entry->saved_loss_link_quality;

  if (saved_lq == 0.0)
    saved_lq = -1.0;

  // calculate the new link quality
  //
  // start slowly: receive the first packet => link quality = 1 / n
  //               (n = window size)

  entry->loss_link_quality =
    (float)(entry->total_packets - entry->lost_packets) /
    (float)(entry->loss_window_size);

  // if the link quality has changed by more than 10 percent,
  // print the new link quality table

  rel_lq = entry->loss_link_quality / saved_lq;

  if (rel_lq > 1.1 || rel_lq < 0.9)
    {
      entry->saved_loss_link_quality = entry->loss_link_quality;

      changes_neighborhood = OLSR_TRUE;
      changes_topology = OLSR_TRUE;

      // create a new ANSN

      // XXX - we should check whether we actually
      // announce this neighbour

      changes = OLSR_TRUE;
    }
}

void olsr_update_packet_loss_hello_int(struct link_entry *entry,
                                       double loss_hello_int)
{
  // called for every LQ HELLO message - update the timeout
  // with the htime value from the message

  entry->loss_hello_int = loss_hello_int;
}

void olsr_update_packet_loss(union olsr_ip_addr *rem, union olsr_ip_addr *loc,
                             olsr_u16_t seqno)
{
  struct link_entry *entry;

  // called for every OLSR packet

  entry = lookup_link_entry(rem, loc);

  // it's the very first LQ HELLO message - we do not yet have a link

  if (entry == NULL)
    return;
    
  // a) have we seen a packet before, i.e. is the sequence number valid?

  // b) heuristically detect a restart (= sequence number reset)
  //    of our neighbor

  if (entry->loss_seqno_valid != 0 && 
      (unsigned short)(seqno - entry->loss_seqno) < 100)
    {
      // loop through all lost packets

      while (entry->loss_seqno != seqno)
        {
          // have we already considered all lost LQ HELLO messages?

          if (entry->loss_missed_hellos == 0)
            update_packet_loss_worker(entry, 1);

          // if not, then decrement the number of lost LQ HELLOs

          else
            entry->loss_missed_hellos--;

          entry->loss_seqno++;
        }
    }

  // we have received a packet, otherwise this function would not
  // have been called

  update_packet_loss_worker(entry, 0);

  // (re-)initialize

  entry->loss_missed_hellos = 0;
  entry->loss_seqno = seqno + 1;

  // we now have a valid serial number for sure

  entry->loss_seqno_valid = 1;

  // timeout for the first lost packet is 1.5 x htime

  entry->loss_timeout = GET_TIMESTAMP(entry->loss_hello_int * 1500.0);
}

static void olsr_time_out_packet_loss()
{
  struct link_entry *walker;

  // loop through all links

  for (walker = link_set; walker != NULL; walker = walker->next)
    {
      // find a link that has not seen any packets for a very long
      // time (first time: 1.5 x htime, subsequently: 1.0 x htime)

      if (!TIMED_OUT(walker->loss_timeout))
        continue;
      
      // count the lost packet

      update_packet_loss_worker(walker, 1);

      // memorize that we've counted the packet, so that we do not
      // count it a second time later

      walker->loss_missed_hellos++;

      // next timeout in 1.0 x htime

      walker->loss_timeout = GET_TIMESTAMP(walker->loss_hello_int * 1000.0);
    }
}

struct link_entry *olsr_neighbor_best_link(union olsr_ip_addr *main)
{
  struct link_entry *walker;
  double best = 0.0;
  double curr;
  struct link_entry *res = NULL;

  // loop through all links

  for (walker = link_set; walker != NULL; walker = walker->next)
  {
    // check whether it's a link to the requested neighbor and
    // whether the link's quality is better than what we have

    if(COMP_IP(main, &walker->neighbor->neighbor_main_addr))
    {
      curr = walker->loss_link_quality * walker->neigh_link_quality;

      if (curr >= best)
      {
        best = curr;
        res = walker;
      }
    }
  }

  return res;
}
