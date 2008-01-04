/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Andreas Tønnesen(andreto@olsr.org)
 * RIB implementation (c) 2007, Hannes Gredler (hannes@gredler.at)
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

#include "routing_table.h"
#include "ipcalc.h"
#include "defs.h"
#include "two_hop_neighbor_table.h"
#include "tc_set.h"
#include "mid_set.h"
#include "neighbor_table.h"
#include "olsr.h"
#include "link_set.h"
#include "lq_avl.h"
#include "lq_route.h"
#include "net_olsr.h"

#include <assert.h>

/*
 * Sven-Ola: if the current internet gateway is switched, the
 * NAT connection info is lost for any active TCP/UDP session.
 * For this reason, we do not want to switch if the advantage
 * is only minimal (cost of loosing all NATs is too high).
 * The following rt_path keeps track of the current inet gw.
 */
static struct rt_path *current_inetgw = NULL;

/* Root of our RIB */
struct avl_tree routingtree;

/*
 * Keep a version number for detecting outdated elements
 * in the per rt_entry rt_path subtree.
 */
unsigned int routingtree_version;

/**
 * Bump the version number of the routing tree.
 *
 * After route-insertion compare the version number of the routes
 * against the version number of the table.
 * This is a lightweight detection if a node or prefix went away,
 * rather than brute force old vs. new rt_entry comparision.
 */
unsigned int
olsr_bump_routingtree_version(void)
{
  return routingtree_version++;
}

/**
 * avl_comp_ipv4_prefix
 *
 * compare two ipv4 prefixes.
 * first compare the prefixes, then
 *  then compare the prefix lengths.
 *
 * return 0 if there is an exact match and
 * -1 / +1 depending on being smaller or bigger.
 */
int
avl_comp_ipv4_prefix (const void *prefix1, const void *prefix2)
{       
  const struct olsr_ip_prefix *pfx1 = prefix1;
  const struct olsr_ip_prefix *pfx2 = prefix2;
  const olsr_u32_t addr1 = ntohl(pfx1->prefix.v4.s_addr);
  const olsr_u32_t addr2 = ntohl(pfx2->prefix.v4.s_addr);

  /* prefix */
  if (addr1 < addr2) {
    return -1;
  }
  if (addr1 > addr2) {
    return +1;
  }

  /* prefix length */
  if (pfx1->prefix_len < pfx2->prefix_len) {
    return -1;
  }
  if (pfx1->prefix_len > pfx2->prefix_len) {
    return +1;
  }

  return 0;
}

/**
 * avl_comp_ipv6_prefix
 *
 * compare two ipv6 prefixes.
 * first compare the prefixes, then
 *  then compare the prefix lengths.
 *
 * return 0 if there is an exact match and
 * -1 / +1 depending on being smaller or bigger.
 */
int
avl_comp_ipv6_prefix (const void *prefix1, const void *prefix2)
{       
  int res;
  const struct olsr_ip_prefix *pfx1 = prefix1;
  const struct olsr_ip_prefix *pfx2 = prefix2;

  /* prefix */
  res = memcmp(&pfx1->prefix.v6, &pfx2->prefix.v6, 16);
  if (res != 0) {
    return res;
  } 
  /* prefix length */
  if (pfx1->prefix_len < pfx2->prefix_len) {
    return -1;
  }
  if (pfx1->prefix_len > pfx2->prefix_len) {
    return +1;
  }

  return 0;
}

/**
 * Initialize the routingtree and kernel change queues.
 */
void
olsr_init_routing_table(void)
{
  /* the routing tree */
  avl_init(&routingtree, avl_comp_prefix_default);
  routingtree_version = 0;
}

/**
 * Look up a maxplen entry (= /32 or /128) in the routing table.
 *
 * @param dst the address of the entry
 *
 * @return a pointer to a rt_entry struct 
 * representing the route entry.
 */
struct rt_entry *
olsr_lookup_routing_table(const union olsr_ip_addr *dst)
{
  struct avl_node *rt_tree_node;
  struct olsr_ip_prefix prefix;

  prefix.prefix = *dst;
  prefix.prefix_len = olsr_cnf->maxplen;

  rt_tree_node = avl_find(&routingtree, &prefix);

  return rt_tree_node ? rt_tree_node->data : NULL;
}

/**
 * Update gateway/interface/etx/hopcount and the version for a route path.
 */
void
olsr_update_rt_path(struct rt_path *rtp, struct tc_entry *tc,
                    struct link_entry *link)
{

  rtp->rtp_version = routingtree_version;

  /* gateway */
  rtp->rtp_nexthop.gateway = link->neighbor_iface_addr;

  /* interface */
  rtp->rtp_nexthop.iif_index = link->inter->if_index;

  /* metric/etx */
  rtp->rtp_metric.hops = tc->hops;
  rtp->rtp_metric.etx = tc->path_etx;
}

/**
 * Alloc and key a new rt_entry.
 */
static struct rt_entry *
olsr_alloc_rt_entry(struct olsr_ip_prefix *prefix)
{
  struct rt_entry *rt = olsr_malloc(sizeof(struct rt_entry), __FUNCTION__);
  if (!rt) {
    return NULL;
  }

  memset(rt, 0, sizeof(*rt));
  
  /* Mark this entry as fresh (see process_routes.c:512) */
  rt->rt_nexthop.iif_index = -1;

  /* set key and backpointer prior to tree insertion */
  rt->rt_dst = *prefix;

  rt->rt_tree_node.key = &rt->rt_dst;
  rt->rt_tree_node.data = rt;
  avl_insert(&routingtree, &rt->rt_tree_node, AVL_DUP_NO);

  /* init the originator subtree */
  avl_init(&rt->rt_path_tree, avl_comp_default);

  return rt;
}

/**
 * Alloc and key a new rt_path.
 */
static struct rt_path *
olsr_alloc_rt_path(struct tc_entry *tc,
                   struct olsr_ip_prefix *prefix, olsr_u8_t origin)
{
  struct rt_path *rtp = olsr_malloc(sizeof(struct rt_path), __FUNCTION__);

  if (!rtp) {
    return NULL;
  }

  memset(rtp, 0, sizeof(*rtp));

  rtp->rtp_dst = *prefix;

  /* set key and backpointer prior to tree insertion */
  rtp->rtp_prefix_tree_node.key = &rtp->rtp_dst;
  rtp->rtp_prefix_tree_node.data = rtp;

  /* insert to the tc prefix tree */
  avl_insert(&tc->prefix_tree, &rtp->rtp_prefix_tree_node, AVL_DUP_NO);

  /* backlink to the owning tc entry */
  rtp->rtp_tc = tc;

  /* store the origin of the route */
  rtp->rtp_origin = origin;

  return rtp;
}

/**
 * Create a route entry for a given rt_path and
 * insert it into the global RIB tree.
 */
void
olsr_insert_rt_path(struct rt_path *rtp, struct tc_entry *tc,
                    struct link_entry *link)
{
  struct rt_entry *rt;
  struct avl_node *node;

  /*
   * no unreachable routes please.
   */
  if (tc->path_etx >= INFINITE_ETX) {
    return;
  }

  /*
   * No bogus prefix lengths.
   */
  if (rtp->rtp_dst.prefix_len > olsr_cnf->maxplen) {
    return;
  }

  /*
   * first check if there is a route_entry for the prefix.
   */
  node = avl_find(&routingtree, &rtp->rtp_dst);

  if (!node) {

    /* no route entry yet */
    rt = olsr_alloc_rt_entry(&rtp->rtp_dst);

    if (!rt) {
      return;
    }

  } else {
    rt = node->data;
  }


  /* Now insert the rt_path to the owning rt_entry tree */
  rtp->rtp_originator = tc->addr;

  /* set key and backpointer prior to tree insertion */
  rtp->rtp_tree_node.key = &rtp->rtp_originator;
  rtp->rtp_tree_node.data = rtp;

  /* insert to the route entry originator tree */
  avl_insert(&rt->rt_path_tree, &rtp->rtp_tree_node, AVL_DUP_NO);

  /* backlink to the owning route entry */
  rtp->rtp_rt = rt;

  /* update the version field and relevant parameters */
  olsr_update_rt_path(rtp, tc, link);
}

/**
 * Unlink and free a rt_path.
 */
static void
olsr_free_rt_path(struct rt_path *rtp)
{

  /* remove from the originator tree */
  if (rtp->rtp_rt) {
    avl_delete(&rtp->rtp_rt->rt_path_tree, &rtp->rtp_tree_node);
    rtp->rtp_rt = NULL;
  }

  /* remove from the tc prefix tree */
  if (rtp->rtp_tc) {
    avl_delete(&rtp->rtp_tc->prefix_tree, &rtp->rtp_prefix_tree_node);
    rtp->rtp_tc = NULL;
  }

  /* no current inet gw if the rt_path is removed */
  if (current_inetgw == rtp) {
    current_inetgw = NULL;
  }

  free(rtp);
}


/**
 * Check if there is an interface or gateway change.
 */
olsr_bool
olsr_nh_change(const struct rt_nexthop *nh1, const struct rt_nexthop *nh2)
{
  if (!ipequal(&nh1->gateway, &nh2->gateway) ||
      (nh1->iif_index != nh2->iif_index)) {
    return OLSR_TRUE;
  }
  return OLSR_FALSE;
}

/**
 * Check if there is a hopcount change.
 */
olsr_bool
olsr_hopcount_change(const struct rt_metric *met1, const struct rt_metric *met2)
{
  return (met1->hops != met2->hops);
}

/**
 * Depending if flat_metric is configured and the kernel fib operation
 * return the hopcount metric of a route.
 * For adds this is the metric of best rour after olsr_rt_best() election,
 * for deletes this is the metric of the route that got stored in the rt_entry,
 * during route installation.
 */
olsr_u8_t
olsr_fib_metric(const struct rt_metric *met)
{
  if (FIBM_CORRECT == olsr_cnf->fib_metric) {
    return met->hops;
  }
  return RT_METRIC_DEFAULT;
}

/**
 * depending on the operation (add/chg/del) the nexthop
 * field from the route entry or best route path shall be used.
 */
const struct rt_nexthop *
olsr_get_nh(const struct rt_entry *rt)
{

  if(rt->rt_best) {

    /* this is a route add/chg - grab nexthop from the best route. */
    return &rt->rt_best->rtp_nexthop;
  } 
  
  /* this is a route deletion - all routes are gone. */
  return &rt->rt_nexthop;
}

/**
 * compare two route paths.
 *
 * returns TRUE if the first path is better
 * than the second one, FALSE otherwise.
 */
static olsr_bool
olsr_cmp_rtp(const struct rt_path *rtp1, const struct rt_path *rtp2, const struct rt_path *inetgw)
{
    float etx1 = rtp1->rtp_metric.etx;
    float etx2 = rtp2->rtp_metric.etx;
    if (inetgw == rtp1) etx1 *= olsr_cnf->lq_nat_thresh;
    if (inetgw == rtp2) etx2 *= olsr_cnf->lq_nat_thresh;

    /* etx comes first */
    if (etx1 < etx2) {
      return OLSR_TRUE;
    }

    /* hopcount is next tie breaker */
    if ((etx1 == etx2) &&
        (rtp1->rtp_metric.hops < rtp2->rtp_metric.hops)) {
      return OLSR_TRUE;
    }

    /* originator (which is guaranteed to be unique) is final tie breaker */
    if ((rtp1->rtp_metric.hops == rtp2->rtp_metric.hops) &&
        (memcmp(&rtp1->rtp_originator, &rtp2->rtp_originator,
                olsr_cnf->ipsize) == -1)) {
      return OLSR_TRUE;
    }

    return OLSR_FALSE;
}

/**
 * compare the best path of two route entries.
 *
 * returns TRUE if the first entry is better
 * than the second one, FALSE otherwise.
 */
olsr_bool
olsr_cmp_rt(const struct rt_entry *rt1, const struct rt_entry *rt2)
{
  return olsr_cmp_rtp(rt1->rt_best, rt2->rt_best, NULL);
}

/**
 * run best route selection among a
 * set of identical prefixes.
 */
void
olsr_rt_best(struct rt_entry *rt)
{
  /* grab the first entry */
  struct avl_node *node = avl_walk_first(&rt->rt_path_tree);

  assert(node != 0); /* should not happen */

  rt->rt_best = node->data;

  /* walk all remaining originator entries */
  while ((node = avl_walk_next(node))) {
    struct rt_path *rtp = node->data;

    if (olsr_cmp_rtp(rtp, rt->rt_best, current_inetgw)) {
      rt->rt_best = rtp;
    }
  }

  if (0 == rt->rt_dst.prefix_len) {
    current_inetgw = rt->rt_best;
  }
}

/**
 * Insert a prefix into the prefix tree hanging off a lsdb (tc) entry.
 *
 * Check if the candidate route (we call this a rt_path) is known,
 * if not create it.
 * Upon post-SPF processing (if the node is reachable) the prefix
 * will be finally inserted into the global RIB.
 *
 *@param dst the destination
 *@param plen the prefix length
 *@param originator the originating router
 *
 *@return the new rt_path struct
 */
struct rt_path *
olsr_insert_routing_table(union olsr_ip_addr *dst, int plen,
                          union olsr_ip_addr *originator, int origin)
{
#if !defined(NODEBUG) && defined(DEBUG)
  struct ipaddr_str dstbuf, origbuf;
#endif
  struct tc_entry *tc;
  struct rt_path *rtp;
  struct avl_node *node;
  struct olsr_ip_prefix prefix;

  /*
   * No bogus prefix lengths.
   */
  if (plen > olsr_cnf->maxplen) {
    return NULL;
  }

#ifdef DEBUG
  OLSR_PRINTF(1, "RIB: add prefix %s/%u from %s\n",
              olsr_ip_to_string(&dstbuf, dst), plen,
              olsr_ip_to_string(&origbuf, originator));
#endif

  /*
   * For internal routes the tc_entry must already exist.
   * For all other routes we may create it as an edgeless
   * hookup point. If so he tc_entry has no edges it will not
   * be explored during SPF run.
   */
  tc = olsr_locate_tc_entry(originator);
  
  /*
   * first check if there is a rt_path for the prefix.
   */
  prefix.prefix = *dst;
  prefix.prefix_len = plen;

  node = avl_find(&tc->prefix_tree, &prefix);

  if (!node) {

    /* no rt_path for this prefix yet */
    rtp = olsr_alloc_rt_path(tc, &prefix, origin);

    if (!rtp) {
      return NULL;
    }

    /* overload the hna change bit for flagging a prefix change */
    changes_hna = OLSR_TRUE;

  } else {
    rtp = node->data;
  }

  return rtp;
}

/**
 * Delete a prefix from the prefix tree hanging off a lsdb (tc) entry.
 */
void
olsr_delete_routing_table(union olsr_ip_addr *dst, int plen,
                          union olsr_ip_addr *originator)
{
#if !defined(NODEBUG) && defined(DEBUG)
  struct ipaddr_str buf;
#endif

  struct tc_entry *tc;
  struct rt_path *rtp;
  struct avl_node *node;
  struct olsr_ip_prefix prefix;

  /*
   * No bogus prefix lengths.
   */
  if (plen > olsr_cnf->maxplen) {
    return;
  }

#ifdef DEBUG
  OLSR_PRINTF(1, "RIB: del prefix %s/%u from %s\n",
              olsr_ip_to_string(&buf, dst), plen,
              olsr_ip_to_string(&buf, originator));
#endif

  tc = olsr_lookup_tc_entry(originator);
  if (!tc) {
    return;
  }

  /*
   * Grab the rt_path for the prefix.
   */
  prefix.prefix = *dst;
  prefix.prefix_len = plen;

  node = avl_find(&tc->prefix_tree, &prefix);

  if (node) {
    rtp = node->data;
    olsr_free_rt_path(rtp);

    /* overload the hna change bit for flagging a prefix change */
    changes_hna = OLSR_TRUE;
  }
}

/**
 * format a route entry into a buffer
 */
char *
olsr_rt_to_string(const struct rt_entry *rt)
{
  static char buff[128];
  struct ipaddr_str prefixstr, gwstr;

  snprintf(buff, sizeof(buff),
           "%s/%u via %s",
           olsr_ip_to_string(&prefixstr, &rt->rt_dst.prefix),
           rt->rt_dst.prefix_len,
           olsr_ip_to_string(&gwstr, &rt->rt_nexthop.gateway));

  return buff;
}

/**
 * format a route path into a buffer
 */
char *
olsr_rtp_to_string(const struct rt_path *rtp)
{
  static char buff[128];
  struct ipaddr_str prefixstr, origstr, gwstr;
  struct rt_entry *rt = rtp->rtp_rt;

  snprintf(buff, sizeof(buff),
           "%s/%u from %s via %s, "
           "etx %.3f, metric %u, v %u",
           olsr_ip_to_string(&prefixstr, &rt->rt_dst.prefix),
           rt->rt_dst.prefix_len,
           olsr_ip_to_string(&origstr, &rtp->rtp_originator),
           olsr_ip_to_string(&gwstr, &rtp->rtp_nexthop.gateway),
           rtp->rtp_metric.etx,
           rtp->rtp_metric.hops,
           rtp->rtp_version);

  return buff;
}

/**
 * Print the routingtree to STDOUT
 *
 */
void
olsr_print_routing_table(const struct avl_tree *tree)
{
  const struct avl_node *rt_tree_node;

#ifdef DEBUG
  printf("ROUTING TABLE\n");
#endif

  for (rt_tree_node = avl_walk_first_c(tree);
       rt_tree_node != NULL;
       rt_tree_node = avl_walk_next_c(rt_tree_node)) {
    const struct avl_node *rtp_tree_node;
    struct ipaddr_str prefixstr, origstr, gwstr;
    const struct rt_entry * const rt = rt_tree_node->data;

    /* first the route entry */
    printf("%s/%u, via %s, best-originator %s\n",
           olsr_ip_to_string(&prefixstr, &rt->rt_dst.prefix),
           rt->rt_dst.prefix_len,
           olsr_ip_to_string(&origstr, &rt->rt_nexthop.gateway),
           olsr_ip_to_string(&gwstr, &rt->rt_best->rtp_originator));

    /* walk the per-originator path tree of routes */
    for (rtp_tree_node = avl_walk_first_c(&rt->rt_path_tree);
         rtp_tree_node != NULL;
         rtp_tree_node = avl_walk_next_c(rtp_tree_node)) {
      const struct rt_path * const rtp = rtp_tree_node->data;
      printf("\tfrom %s, etx %.3f, metric %u, via %s, %s, v %u\n",
             olsr_ip_to_string(&origstr, &rtp->rtp_originator),
             rtp->rtp_metric.etx,
             rtp->rtp_metric.hops,
             olsr_ip_to_string(&gwstr, &rtp->rtp_nexthop.gateway),
             if_ifwithindex_name(rt->rt_nexthop.iif_index),
             rtp->rtp_version);    
    }
  }
}

/*
 * Local Variables:
 * c-basic-offset: 2
 * End:
 */
