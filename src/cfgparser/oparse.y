%{

/*
 * OLSR ad-hoc routing table management protocol config parser
 * Copyright (C) 2004 Andreas T�nnesen (andreto@olsr.org)
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
 * $Id: oparse.y,v 1.17 2004/11/20 18:46:03 kattemat Exp $
 *
 */


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "olsrd_conf.h"

#define PARSER_DEBUG 0

#define YYSTYPE struct conf_token *

void yyerror(char *);
int yylex(void);





%}

%token TOK_OPEN
%token TOK_CLOSE
%token TOK_SEMI

%token TOK_STRING
%token TOK_INTEGER
%token TOK_FLOAT
%token TOK_BOOLEAN

%token TOK_IP6TYPE

%token TOK_DEBUGLEVEL
%token TOK_IPVERSION
%token TOK_HNA4
%token TOK_HNA6
%token TOK_PLUGIN
%token TOK_INTERFACE
%token TOK_NOINT
%token TOK_TOS
%token TOK_WILLINGNESS
%token TOK_IPCCON
%token TOK_USEHYST
%token TOK_HYSTSCALE
%token TOK_HYSTUPPER
%token TOK_HYSTLOWER
%token TOK_POLLRATE
%token TOK_TCREDUNDANCY
%token TOK_MPRCOVERAGE
%token TOK_LQ_LEVEL
%token TOK_LQ_WSIZE
%token TOK_CLEAR_SCREEN
%token TOK_PLNAME
%token TOK_PLPARAM

%token TOK_HOSTLABEL
%token TOK_NETLABEL
%token TOK_MAXIPC

%token TOK_IP4BROADCAST
%token TOK_IP6ADDRTYPE
%token TOK_IP6MULTISITE
%token TOK_IP6MULTIGLOBAL
%token TOK_HELLOINT
%token TOK_HELLOVAL
%token TOK_TCINT
%token TOK_TCVAL
%token TOK_MIDINT
%token TOK_MIDVAL
%token TOK_HNAINT
%token TOK_HNAVAL

%token TOK_IP4_ADDR
%token TOK_IP6_ADDR

%token TOK_COMMENT

%%

conf:
          | conf block
          | conf stmt
;

stmt:       idebug
          | iipversion
          | bnoint
          | atos
          | awillingness
          | busehyst
          | fhystscale
          | fhystupper
          | fhystlower
          | fpollrate
          | atcredundancy
          | amprcoverage
          | alq_level
          | alq_wsize
          | bclear_screen
          | vcomment
;

block:      TOK_HNA4 hna4body
          | TOK_HNA6 hna6body
          | TOK_IPCCON ipcbody
          | ifblock ifbody
          | plblock plbody
;

hna4body:       TOK_OPEN hna4stmts TOK_CLOSE
;

hna4stmts: | hna4stmts hna4stmt
;

hna4stmt:  vcomment
         | ihna4entry
;

hna6body:       TOK_OPEN hna6stmts TOK_CLOSE
;

hna6stmts: | hna6stmts hna6stmt
;

hna6stmt:  vcomment
         | ihna6entry
;

ipcbody:    TOK_OPEN ipcstmts TOK_CLOSE
;

ipcstmts: | ipcstmts ipcstmt
;

ipcstmt:  vcomment
          | imaxipc
          | ipchost
          | ipcnet
;

ifbody:     TOK_OPEN ifstmts TOK_CLOSE
;

ifstmts:   | ifstmts ifstmt
;

ifstmt:      vcomment
             | isetip4br
             | isetip6addrt
             | isetip6mults
             | isetip6multg
             | isethelloint
             | isethelloval
             | isettcint
             | isettcval
             | isetmidint
             | isetmidval
             | isethnaint
             | isethnaval
;

plbody:     TOK_OPEN plstmts TOK_CLOSE
;

plstmts:   | plstmts plstmt
;

plstmt:     plparam
          | vcomment
;


imaxipc: TOK_MAXIPC TOK_INTEGER
{
  cnf->ipc_connections = $2->integer;

  cnf->open_ipc = cnf->ipc_connections ? OLSR_TRUE : OLSR_FALSE;

  free($2);
}
;


ipchost: TOK_HOSTLABEL TOK_IP4_ADDR
{
  struct in_addr in;
  struct ipc_host *ipch;

  if(PARSER_DEBUG) printf("\tIPC host: %s\n", $2->string);
  
  if(inet_aton($2->string, &in) == 0)
    {
      fprintf(stderr, "Failed converting IP address IPC %s\n", $2->string);
      exit(EXIT_FAILURE);
    }

  ipch = malloc(sizeof(struct ipc_host));
  ipch->host.v4 = in.s_addr;

  ipch->next = cnf->ipc_hosts;
  cnf->ipc_hosts = ipch;

  free($2->string);
  free($2);

}
;

ipcnet: TOK_NETLABEL TOK_IP4_ADDR TOK_IP4_ADDR
{
  struct in_addr in1, in2;
  struct ipc_net *ipcn;

  if(PARSER_DEBUG) printf("\tIPC net: %s/%s\n", $2->string, $3->string);
  
  if(inet_aton($2->string, &in1) == 0)
    {
      fprintf(stderr, "Failed converting IP net IPC %s\n", $2->string);
      exit(EXIT_FAILURE);
    }

  if(inet_aton($3->string, &in2) == 0)
    {
      fprintf(stderr, "Failed converting IP mask IPC %s\n", $3->string);
      exit(EXIT_FAILURE);
    }

  ipcn = malloc(sizeof(struct ipc_net));
  ipcn->net.v4 = in1.s_addr;
  ipcn->mask.v4 = in2.s_addr;

  ipcn->next = cnf->ipc_nets;
  cnf->ipc_nets = ipcn;

  free($2->string);
  free($2);
  free($3->string);
  free($3);

}
;

isetip4br: TOK_IP4BROADCAST TOK_IP4_ADDR
{
  struct in_addr in;

  if(PARSER_DEBUG) printf("\tIPv4 broadcast: %s\n", $2->string);

  if(inet_aton($2->string, &in) == 0)
    {
      fprintf(stderr, "Failed converting IP address %s\n", $2->string);
      exit(EXIT_FAILURE);
    }

  cnf->interfaces->cnf->ipv4_broadcast.v4 = in.s_addr;

  free($2->string);
  free($2);
}
;

isetip6addrt: TOK_IP6ADDRTYPE TOK_IP6TYPE
{
  if($2->boolean)
    cnf->interfaces->cnf->ipv6_addrtype = IPV6_ADDR_SITELOCAL;
  else
    cnf->interfaces->cnf->ipv6_addrtype = 0;

  free($2);
}
;

isetip6mults: TOK_IP6MULTISITE TOK_IP6_ADDR
{
  struct in6_addr in6;

  if(PARSER_DEBUG) printf("\tIPv6 site-local multicast: %s\n", $2->string);

  if(inet_pton(AF_INET6, $2->string, &in6) < 0)
    {
      fprintf(stderr, "Failed converting IP address %s\n", $2->string);
      exit(EXIT_FAILURE);
    }
  memcpy(&cnf->interfaces->cnf->ipv6_multi_site.v6, &in6, sizeof(struct in6_addr));


  free($2->string);
  free($2);
}
;


isetip6multg: TOK_IP6MULTIGLOBAL TOK_IP6_ADDR
{
  struct in6_addr in6;

  if(PARSER_DEBUG) printf("\tIPv6 global multicast: %s\n", $2->string);

  if(inet_pton(AF_INET6, $2->string, &in6) < 0)
    {
      fprintf(stderr, "Failed converting IP address %s\n", $2->string);
      exit(EXIT_FAILURE);
    }
  memcpy(&cnf->interfaces->cnf->ipv6_multi_glbl.v6, &in6, sizeof(struct in6_addr));


  free($2->string);
  free($2);
}
;
isethelloint: TOK_HELLOINT TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tHELLO interval: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->hello_params.emission_interval = $2->floating;
    free($2);
}
;
isethelloval: TOK_HELLOVAL TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tHELLO validity: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->hello_params.validity_time = $2->floating;
    free($2);
}
;
isettcint: TOK_TCINT TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tTC interval: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->tc_params.emission_interval = $2->floating;
    free($2);
}
;
isettcval: TOK_TCVAL TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tTC validity: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->tc_params.validity_time = $2->floating;
    free($2);
}
;
isetmidint: TOK_MIDINT TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tMID interval: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->mid_params.emission_interval = $2->floating;
    free($2);
}
;
isetmidval: TOK_MIDVAL TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tMID validity: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->mid_params.validity_time = $2->floating;
    free($2);
}
;
isethnaint: TOK_HNAINT TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tHNA interval: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->hna_params.emission_interval = $2->floating;
    free($2);
}
;
isethnaval: TOK_HNAVAL TOK_FLOAT
{
    if(PARSER_DEBUG) printf("\tHNA validity: %0.2f\n", $2->floating);
    if($2->floating < MIN_INTERVAL)
      {
	fprintf(stderr, "%0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
    cnf->interfaces->cnf->hna_params.validity_time = $2->floating;
    free($2);
}
;


idebug:       TOK_DEBUGLEVEL TOK_INTEGER
{

  cnf->debug_level = $2->integer;
  if(PARSER_DEBUG) printf("Debug level: %d\n", cnf->debug_level);
    if($2->integer < MIN_DEBUGLVL ||
       $2->integer > MAX_DEBUGLVL)
      {
	fprintf(stderr, "Debuglevel %d is not allowed\n", $2->integer);
	exit(EXIT_FAILURE);
      }

  free($2);
}
;


iipversion:    TOK_IPVERSION TOK_INTEGER
{
  if($2->integer == 4)
    cnf->ip_version = AF_INET;
  else if($2->integer == 6)
    cnf->ip_version = AF_INET6;
  else
    {
      fprintf(stderr, "IPversion must be 4 or 6!\n");
      YYABORT;
    }

  if(PARSER_DEBUG) printf("IpVersion: %d\n", $2->integer);
  free($2);
}
;


ihna4entry:     TOK_IP4_ADDR TOK_IP4_ADDR
{
  struct hna4_entry *h = malloc(sizeof(struct hna4_entry));
  struct in_addr in;

  if(PARSER_DEBUG) printf("HNA IPv4 entry: %s/%s\n", $1->string, $2->string);

  if(h == NULL)
    {
      fprintf(stderr, "Out of memory(HNA4)\n");
      YYABORT;
    }

  if(inet_aton($1->string, &in) == 0)
    {
      fprintf(stderr, "Failed converting IP address %s\n", $1->string);
      exit(EXIT_FAILURE);
    }
  h->net.v4 = in.s_addr;
  if(inet_aton($2->string, &in) == 0)
    {
      fprintf(stderr, "Failed converting IP address %s\n", $1->string);
      exit(EXIT_FAILURE);
    }
  h->netmask.v4 = in.s_addr;
  /* Queue */
  h->next = cnf->hna4_entries;
  cnf->hna4_entries = h;

  free($1->string);
  free($1);
  free($2->string);
  free($2);

}

ihna6entry:     TOK_IP6_ADDR TOK_INTEGER
{
  struct hna6_entry *h = malloc(sizeof(struct hna6_entry));
  struct in6_addr in6;

  if(PARSER_DEBUG) printf("HNA IPv6 entry: %s/%d\n", $1->string, $2->integer);

  if(h == NULL)
    {
      fprintf(stderr, "Out of memory(HNA6)\n");
      YYABORT;
    }

  if(inet_pton(AF_INET6, $1->string, &in6) < 0)
    {
      fprintf(stderr, "Failed converting IP address %s\n", $1->string);
      exit(EXIT_FAILURE);
    }
  memcpy(&h->net, &in6, sizeof(struct in6_addr));

  if(($2->integer < 0) || ($2->integer > 128))
    {
      fprintf(stderr, "Illegal IPv6 prefix length %d\n", $2->integer);
      exit(EXIT_FAILURE);
    }

  h->prefix_len = $2->integer;
  /* Queue */
  h->next = cnf->hna6_entries;
  cnf->hna6_entries = h;

  free($1->string);
  free($1);
  free($2);

}

ifblock: TOK_INTERFACE TOK_STRING
{
  struct olsr_if *in = malloc(sizeof(struct olsr_if));
  
  if(in == NULL)
    {
      fprintf(stderr, "Out of memory(ADD IF)\n");
      YYABORT;
    }

  in->cnf = get_default_if_config();

  if(in->cnf == NULL)
    {
      fprintf(stderr, "Out of memory(ADD IFRULE)\n");
      YYABORT;
    }

  in->name = $2->string;

  /* Queue */
  in->next = cnf->interfaces;
  cnf->interfaces = in;

  free($2);
}

bnoint: TOK_NOINT TOK_BOOLEAN
{
  if(PARSER_DEBUG) printf("Noint set to %d\n", $2->boolean);

  cnf->allow_no_interfaces = $2->boolean;

  free($2);
}
;

atos: TOK_TOS TOK_INTEGER
{
  if(PARSER_DEBUG) printf("TOS: %d\n", $2->integer);
    if($2->integer < MIN_TOS ||
       $2->integer > MAX_TOS)
      {
	fprintf(stderr, "%d is not allowed\n", $2->integer);
	exit(EXIT_FAILURE);
      }

  cnf->tos = $2->integer;

  free($2);

}
;

awillingness: TOK_WILLINGNESS TOK_INTEGER
{
  cnf->willingness_auto = OLSR_FALSE;

  if(PARSER_DEBUG) printf("Willingness: %d\n", $2->integer);
    if($2->integer < MIN_WILLINGNESS ||
       $2->integer > MAX_WILLINGNESS)
      {
	fprintf(stderr, "willingness %d is not allowed\n", $2->integer);
	exit(EXIT_FAILURE);
      }
  cnf->willingness = $2->integer;

  free($2);

}
;



busehyst: TOK_USEHYST TOK_BOOLEAN
{
  cnf->use_hysteresis = $2->boolean;
  if(cnf->use_hysteresis)
    {
      if(PARSER_DEBUG) printf("Hysteresis enabled\n");
    }
  else
    {
      if(PARSER_DEBUG) printf("Hysteresis disabled\n");
    }
  free($2);

}
;


fhystscale: TOK_HYSTSCALE TOK_FLOAT
{
  cnf->hysteresis_param.scaling = $2->floating;
  if(PARSER_DEBUG) printf("Hysteresis Scaling: %0.2f\n", $2->floating);
    if($2->floating < MIN_HYST_PARAM ||
       $2->floating > MAX_HYST_PARAM)
      {
	fprintf(stderr, "Hyst scaling %0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }

  free($2);
}
;


fhystupper: TOK_HYSTUPPER TOK_FLOAT
{
  cnf->hysteresis_param.thr_high = $2->floating;
  if(PARSER_DEBUG) printf("Hysteresis UpperThr: %0.2f\n", $2->floating);
    if($2->floating < MIN_HYST_PARAM ||
       $2->floating > MAX_HYST_PARAM)
      {
	fprintf(stderr, "Hyst upper thr %0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
  free($2);
}
;


fhystlower: TOK_HYSTLOWER TOK_FLOAT
{
  cnf->hysteresis_param.thr_low = $2->floating;
  if(PARSER_DEBUG) printf("Hysteresis LowerThr: %0.2f\n", $2->floating);
    if($2->floating < MIN_HYST_PARAM ||
       $2->floating > MAX_HYST_PARAM)
      {
	fprintf(stderr, "Hyst lower thr %0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
  free($2);
}
;

fpollrate: TOK_POLLRATE TOK_FLOAT
{
  if(PARSER_DEBUG) printf("Pollrate %0.2f\n", $2->floating);
    if($2->floating < MIN_POLLRATE ||
       $2->floating > MAX_POLLRATE)
      {
	fprintf(stderr, "Pollrate %0.2f is not allowed\n", $2->floating);
	exit(EXIT_FAILURE);
      }
  cnf->pollrate = $2->floating;

  free($2);
}
;


atcredundancy: TOK_TCREDUNDANCY TOK_INTEGER
{
  if(PARSER_DEBUG) printf("TC redundancy %d\n", $2->integer);
  if($2->integer < MIN_TC_REDUNDANCY ||
     $2->integer > MAX_TC_REDUNDANCY)
    {
      fprintf(stderr, "TC redundancy %d is not allowed\n", $2->integer);
      exit(EXIT_FAILURE);
    }

  cnf->tc_redundancy = $2->integer;

  free($2);

}
;

amprcoverage: TOK_MPRCOVERAGE TOK_INTEGER
{
  if(PARSER_DEBUG) printf("MPR coverage %d\n", $2->integer);
    if($2->integer < MIN_MPR_COVERAGE ||
       $2->integer > MAX_MPR_COVERAGE)
      {
	fprintf(stderr, "MPR coverage %d is not allowed\n", $2->integer);
	exit(EXIT_FAILURE);
      }

  cnf->mpr_coverage = $2->integer;

  free($2);
}
;

alq_level: TOK_LQ_LEVEL TOK_INTEGER
{
  if(PARSER_DEBUG) printf("Link quality level %d\n", $2->integer);
  cnf->lq_level = $2->integer;

  free($2);
}
;

alq_wsize: TOK_LQ_WSIZE TOK_INTEGER
{
  if(PARSER_DEBUG) printf("Link quality window size %d\n", $2->integer);
  cnf->lq_wsize = $2->integer;

  free($2);
}
;

bclear_screen: TOK_CLEAR_SCREEN TOK_BOOLEAN
{
  cnf->clear_screen = $2->boolean;

  if (PARSER_DEBUG)
    printf("Clear screen %s\n", cnf->clear_screen ? "enabled" : "disabled");

  free($2);
}
;

plblock: TOK_PLUGIN TOK_STRING
{
  struct plugin_entry *pe = malloc(sizeof(struct plugin_entry));
  
  if(pe == NULL)
    {
      fprintf(stderr, "Out of memory(ADD PL)\n");
      YYABORT;
    }

  pe->name = $2->string;

  pe->params = NULL;
  
  if(PARSER_DEBUG) printf("Plugin: %s\n", $2->string);

  /* Queue */
  pe->next = cnf->plugins;
  cnf->plugins = pe;

  free($2);
}
;

plparam: TOK_PLPARAM TOK_STRING TOK_STRING
{
  struct plugin_param *pp = malloc(sizeof(struct plugin_param));
  
  if(pp == NULL)
    {
      fprintf(stderr, "Out of memory(ADD PP)\n");
      YYABORT;
    }
  
  if(PARSER_DEBUG) printf("Plugin param key:\"%s\" val: \"%s\"\n", $2->string, $3->string);
  
  pp->key = $2->string;
  pp->value = $3->string;

  /* Queue */
  pp->next = cnf->plugins->params;
  cnf->plugins->params = pp;

  free($2);
  free($3);
}
;

vcomment:       TOK_COMMENT
{
    //if(PARSER_DEBUG) printf("Comment\n");
}
;



%%

void yyerror (char *string)
{
  fprintf(stderr, "Config line %d: %s\n", current_line, string);
}
