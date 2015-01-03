/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Andreas Tønnesen(andreto@olsr.org)
 * Copyright (c) 2007, Sven-Ola for the policy routing stuff
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

#include "kernel_policy_routes.h"
#include "ipc_frontend.h"
#include <linux/types.h>
#include <linux/rtnetlink.h>

struct olsr_rtreq
{
  struct nlmsghdr n;
  struct rtmsg    r;
  char            buf[512];
};

static void olsr_netlink_addreq(struct olsr_rtreq *req, int type, const void *data, int len)
{
  struct rtattr *rta = (struct rtattr*)(((char*)req) + NLMSG_ALIGN(req->n.nlmsg_len));
  req->n.nlmsg_len = NLMSG_ALIGN(req->n.nlmsg_len) + RTA_LENGTH(len);
  rta->rta_type = type;
  rta->rta_len = RTA_LENGTH(len);
  memcpy(RTA_DATA(rta), data, len);
}

int olsr_netlink_pol_route(const struct rt_entry *rt, olsr_u8_t family, olsr_u8_t rttable, __u16 cmd)
{
  int ret = 0;
  struct olsr_rtreq req;
  struct iovec iov;
  struct sockaddr_nl nladdr;
  struct msghdr msg =
  {
    &nladdr,
    sizeof(nladdr),
    &iov,
    1,
    NULL,
    0,
    0
  };
  olsr_u32_t metric = FIBM_FLAT != olsr_cnf->fib_metric ? (RTM_NEWROUTE == cmd ?
    rt->rt_best->rtp_metric.hops : rt->rt_metric.hops): RT_METRIC_DEFAULT;
  const struct rt_nexthop* nexthop = (RTM_NEWROUTE == cmd) ?
    &rt->rt_best->rtp_nexthop : &rt->rt_nexthop;

  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = family;
  req.r.rtm_table = rttable;
  req.r.rtm_protocol = RTPROT_BOOT;
  req.r.rtm_scope = RT_SCOPE_LINK;
  req.r.rtm_type = RTN_UNICAST;
  req.r.rtm_dst_len = rt->rt_dst.prefix_len;

  if (AF_INET == family)
  {
    if (rt->rt_dst.prefix.v4.s_addr != nexthop->gateway.v4.s_addr)
    {
      olsr_netlink_addreq(&req, RTA_GATEWAY, &nexthop->gateway.v4, sizeof(nexthop->gateway.v4));
      req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    }
    olsr_netlink_addreq(&req, RTA_DST, &rt->rt_dst.prefix.v4, sizeof(rt->rt_dst.prefix.v4));
  }
  else
  {
    if (0 != memcmp(&rt->rt_dst.prefix.v6, &nexthop->gateway.v6, sizeof(nexthop->gateway.v6)))
    {
      olsr_netlink_addreq(&req, RTA_GATEWAY, &nexthop->gateway.v6, sizeof(nexthop->gateway.v6));
      req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    }
    olsr_netlink_addreq(&req, RTA_DST, &rt->rt_dst.prefix.v6, sizeof(rt->rt_dst.prefix.v6));
  }
  if (FIBM_APPROX != olsr_cnf->fib_metric || RTM_NEWROUTE == cmd)
  {
    olsr_netlink_addreq(&req, RTA_PRIORITY, &metric, sizeof(metric));
  }
  olsr_netlink_addreq(&req, RTA_OIF, &nexthop->iif_index, sizeof(nexthop->iif_index));
  iov.iov_base = &req.n;
  iov.iov_len = req.n.nlmsg_len;
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  if (0 <= (ret = sendmsg(olsr_cnf->rtnl_s, &msg, 0)))
  {
    iov.iov_base = req.buf;
    iov.iov_len = sizeof(req.buf);
    if (0 < (ret = recvmsg(olsr_cnf->rtnl_s, &msg, 0)))
    {
      struct nlmsghdr* h = (struct nlmsghdr*)req.buf;
      while (NLMSG_OK(h, (unsigned int)ret)) {
        if (NLMSG_DONE == h->nlmsg_type) break;
        if (NLMSG_ERROR == h->nlmsg_type)
        {
          if (NLMSG_LENGTH(sizeof(struct nlmsgerr) <= h->nlmsg_len))
          {
            struct nlmsgerr *l_err = (struct nlmsgerr*)NLMSG_DATA(h);
            errno = -l_err->error;
            if (0 != errno) ret = -1;
          }
          break;
        }
        h = NLMSG_NEXT(h, ret);
      }
    }
    if (0 <= ret && olsr_cnf->ipc_connections > 0)
    {
      ipc_route_send_rtentry(
        &rt->rt_dst.prefix,
        &nexthop->gateway,
        metric,
        RTM_NEWROUTE == cmd,
        if_ifwithindex_name(nexthop->iif_index));
    }
  }
  return ret;
}


