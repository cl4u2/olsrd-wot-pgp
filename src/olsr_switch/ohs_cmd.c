
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2005, Andreas T�nnesen(andreto@olsr.org)
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
 * $Id: ohs_cmd.c,v 1.16 2005/08/04 18:57:11 kattemat Exp $
 */

#include "olsr_host_switch.h"
#include "olsr_types.h"
#include "commands.h"
#include "link_rules.h"
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


#define ARG_BUF_SIZE 500
static char arg_buf[ARG_BUF_SIZE];

#define TOK_BUF_SIZE 500
static char tok_buf[TOK_BUF_SIZE];

#define MAX_OLSRD_ARGS 10
static char olsrd_path[FILENAME_MAX];

static void
get_arg_buf(FILE *handle, char *buf, size_t size)
{
  char c = 0;
  int pos = 0;

  while(((c = fgetc(handle)) != '\n') &&
	pos < ((int)size - 2))
    {
      buf[pos] = c;
      pos++;
    }

  buf[pos] = 0;
}

static int
get_next_token(char *src, char *dst, size_t buflen)
{
  int i = 0, j = 0;

  dst[0] = 0;
  /* Skip leading spaces */
  while(src[j] == ' ' && src[j] != 0)
    {
      j++;
    }

  src += j;
  i = 0;
  while((src[i] != ' ') && (src[i] != 0) && (i < ((int)buflen - 1)))
    {
      dst[i] = src[i];
      i++;
    }
  dst[i] = 0;

  //if(strlen(dst))
  //printf("Extracted token: %s\n", dst);
  return i + j;
}

int
ohs_set_olsrd_path(char *path)
{
  strncpy(olsrd_path, path, FILENAME_MAX);
  return 0;
}

int
ohs_cmd_olsrd(FILE *handle, char *args)
{
#ifdef WIN32
  printf("olsrd command not available in windows version\nStart instances manually\n");
  return 0;
#else
  char *olsrd_args[MAX_OLSRD_ARGS];
  struct in_addr iaddr;

  args += get_next_token(args, tok_buf, TOK_BUF_SIZE);

  if(!strlen(tok_buf))
    goto print_usage;

  /* Start olsrd instance */
  if(!strncmp(tok_buf, "start", strlen("start")))
    {
      int argc = 0, i = 0;

      args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
      
      if(!strlen(tok_buf))
	goto print_usage;

      if(!inet_aton(tok_buf, &iaddr))
	{
	  printf("Invalid IP %s\n", tok_buf);
	  goto print_usage;
	}

      olsrd_args[argc++] = olsrd_path;

      if(1) /* config file is set */
	{
	  olsrd_args[argc++] = "-f";
	  olsrd_args[argc++] = "/etc/olsrd-emu.conf";
	}
      olsrd_args[argc++] = "-hemu";
      olsrd_args[argc++] = tok_buf;

      olsrd_args[argc++] = "-d";
      olsrd_args[argc++] = "0";
      olsrd_args[argc++] = "-nofork";
      olsrd_args[argc] = NULL;

      printf("Executing: %s", olsrd_path);
      for(i = 0; i < argc; i++)
	printf(" %s", olsrd_args[i]);
      printf("\n");

      if(fork())
	return 1;

      if(execve(olsrd_path, olsrd_args, NULL) < 0)
	{
	  printf("Error executing olsrd: %s\n", strerror(errno));
	  exit(1);
	}
    }
  /* Stop olsrd instance */
  else if(!strncmp(tok_buf, "stop", strlen("stop")))
    {
      struct ohs_connection *oc;

      args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
      
      if(!strlen(tok_buf))
	goto print_usage;

      if(!inet_aton(tok_buf, &iaddr))
	{
	  printf("Invalid IP %s\n", tok_buf);
	  goto print_usage;
	}

      oc = get_client_by_addr((union olsr_ip_addr *)&iaddr.s_addr);

      if(!oc)
	{
	  printf("No such client: %s\n", tok_buf);
	  return -1;
	}
      ohs_delete_connection(oc);
      
      return 1;
    }
  /* Set olsrd binary path */
  else if(!strncmp(tok_buf, "setb", strlen("setb")))
    {
      struct stat sbuf;

      args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
      
      if(!strlen(tok_buf))
	goto print_usage;

      if(stat(tok_buf, &sbuf) < 0)
	{
	  printf("Error setting binary \"%s\": %s\n",
		 tok_buf, strerror(errno));
	  return -1;
	}

      if((sbuf.st_mode & S_IFDIR) || !(sbuf.st_mode & S_IXUSR))
	{
	  printf("Error setting binary \"%s\": Not a regular execuatble file!\n",
		 tok_buf);
	  return -1;
	}

      printf("New olsrd binary path:\"%s\"\n", tok_buf);
      ohs_set_olsrd_path(tok_buf);

      return 1;

    }
  /* Set arguments */
  else if(!strncmp(tok_buf, "seta", strlen("seta")))
    {

    }
  /* Show settings */
  else if(!strncmp(tok_buf, "show", strlen("show")))
    {
      printf("olsrd command settings:\n\tBinary path: %s\n\tArguments  : \n",
	     olsrd_path);
      return 1;
    }

 print_usage:
  printf("Usage: olsrd [start|stop|show|setb|seta] [IP|path|args]\n");
  return 0;
#endif
}

int
ohs_cmd_link(FILE *handle, char *args)
{
  olsr_u8_t bi = 0, wildc_src = 0, wildc_dst = 0;
  struct ohs_connection *src, *dst;
  struct in_addr iaddr;
  int qual;
  struct ohs_ip_link *link, *inv_link;

  args += get_next_token(args, tok_buf, TOK_BUF_SIZE);

  if(!strlen(tok_buf))
    goto print_usage;

  if(!strncmp(tok_buf, "bi", strlen("bi")))
    {
      bi = 1;
      args += get_next_token(args, tok_buf, TOK_BUF_SIZE);

      if(!strlen(tok_buf))
	goto print_usage;
    }

  if(tok_buf[0] == '*')
    {
      wildc_src = 1;
      src = ohs_conns;
    }
  else
    {
      if(!inet_aton(tok_buf, &iaddr))
	{
	  printf("Invalid src IP %s\n", tok_buf);
	  return -1;
	}

      src = get_client_by_addr((union olsr_ip_addr *)&iaddr.s_addr);

      if(!src)
	{
	  printf("No such client: %s!\n", tok_buf);
	  return -1;
	}
    }

  args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
  
  if(!strlen(tok_buf))
    goto print_usage;

  if(tok_buf[0] == '*')
    {
      wildc_dst = 1;
      dst = ohs_conns;
    }
  else
    {
      
      if(!inet_aton(tok_buf, &iaddr))
	{
	  printf("Invalid src IP %s\n", tok_buf);
	  return -1;
	}
      
      dst = get_client_by_addr((union olsr_ip_addr *)&iaddr.s_addr);
      if(!dst)
	{
	  printf("No such client: %s!\n", tok_buf);
	  return -1;
	}
    }

  args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
  
  if(!strlen(tok_buf))
    goto print_usage;

  /* No use for bi if both src and dst are widcards */
  if(wildc_src && wildc_dst)
    {
      bi = 0;
    }

  qual = atoi(tok_buf);

  if(qual < 0 || qual > 100)
    {
      printf("Link quality out of range(0-100)\n");
      return -1;
    }

  while(src)
    {

      while(dst)
	{

	  if(src == dst)
	    goto next_iteration;

	  link = get_link(src, &dst->ip_addr);
	  
	  inv_link = bi ? get_link(dst, &src->ip_addr) : NULL;
	  
	  if(qual == 100)
	    {
	      /* Remove link entry */
	      if(link)
		remove_link(src, link);
	      if(inv_link)
		remove_link(dst, inv_link);
	    }
	  else 
	    {
	      if(!link)
		{
		  /* Create new link */
		  link = add_link(src, dst);
		}
	      
	      link->quality = qual;
	      
	      if(bi)
		{
		  if(!inv_link)
		    {
		      /* Create new link */
		      inv_link = add_link(dst, src);
		    }
		  inv_link->quality = qual;
		}
	    }

	  printf("%s %sdirectional link(s) %s %c=> %s quality %d\n", 
		 (qual == 100) ? "Removing" : "Setting", bi ? "bi" : "uni",
		 olsr_ip_to_string(&src->ip_addr), bi ? '<' : '=', 
		 olsr_ip_to_string(&dst->ip_addr), qual);

	next_iteration:
	  if(wildc_dst)
	    dst = dst->next;
	  else
	    break;
	}
      dst = wildc_dst ? ohs_conns : dst;
      src = wildc_src ? src->next : NULL;
    }

  return 1;
 print_usage:
  printf("link <bi> srcIP dstIP [0-100]");
  return -1;
}

int
ohs_cmd_list(FILE *handle, char *args)
{
  struct ohs_connection *oc = ohs_conns;

  args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
  
  if(!strlen(tok_buf) || 
     !strncmp(tok_buf, "clients", strlen("clients")))
    {
      printf("All connected clients:\n");
      
      while(oc)
	{
	  printf("\t%s - Rx: %d Tx: %d LinkCnt: %d\n", olsr_ip_to_string(&oc->ip_addr), 
		 oc->rx, oc->tx, oc->linkcnt);
	  oc = oc->next;
	}
    }
  else if(!strncmp(tok_buf, "links", strlen("links")))
    {
      printf("All configured links:\n");
      
      while(oc)
	{
	  struct ohs_ip_link *links = oc->links;

	  while(links)
	    {
	      printf("\t%s => %s Quality: %d\n", 
		     olsr_ip_to_string(&oc->ip_addr),
		     olsr_ip_to_string(&links->dst),
		     links->quality);

	      links = links->next;
	    }
	  oc = oc->next;
	}
    }
  else
    {

      printf("list [clients|links]");
      return -1;
    }

  return 1;
}

int
ohs_cmd_help(FILE *handle, char *args)
{
  int i;

  args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
  
  if(!strlen(tok_buf))
    {
      printf("Olsrd host switch version %s\n", OHS_VERSION);
      printf("Available commands:\n");
      
      for(i = 0; ohs_commands[i].cmd; i++)
	{
	  if(ohs_commands[i].helptext_brief)
	    printf("\t%s - %s\n", 
		   ohs_commands[i].cmd,
		   ohs_commands[i].helptext_brief);
	}
      printf("\nType 'help cmd' for help on a specific command\n");
    }
  else
    {
      for(i = 0; ohs_commands[i].cmd; i++)
	{
	  if(!strncmp(tok_buf, ohs_commands[i].cmd, strlen(ohs_commands[i].cmd)))
	    {
	      printf("Usage: %s\nDescription:\n%s\n", 
		     ohs_commands[i].syntax,
		     ohs_commands[i].helptext_long);
	      return 1;
	    }
	}

      printf("Usage: help <command>\n");
    }

  return i;
}

int
ohs_cmd_log(FILE *handle, char *args)
{
  olsr_u8_t set = 0;

  args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
  
  if(strlen(tok_buf) &&
     ((set = !strncmp(tok_buf, "set", strlen("set"))) || 
      !strncmp(tok_buf, "unset", strlen("unset"))))
    {
        olsr_u32_t new_bit = 0;
        
        args += get_next_token(args, tok_buf, TOK_BUF_SIZE);
  
        if(!strlen(tok_buf))
            goto print_usage;
        
        
        if(!strncmp(tok_buf, "CON", strlen("CON")))
	    new_bit = LOG_CONNECT;
        else if(!strncmp(tok_buf, "FOR", strlen("FOR")))
	    new_bit = LOG_FORWARD;
        else if(!strncmp(tok_buf, "LIN", strlen("LIN")))
	    new_bit = LOG_LINK;
	  
        if(!new_bit)
	    goto print_usage;

        if(set)
	    logbits |= new_bit;
        else
	    logbits &= ~new_bit;

        printf("%s log bit: 0x%08x, new log: 0x%08x\n", set ? "Setting" : "Removing",
               new_bit, logbits);

    }
  else
    {
      if(strlen(tok_buf))
	goto print_usage;

      printf("Log: (0x%08x) ", logbits);
      if(logbits & LOG_CONNECT)
	printf("CONNECT ");
      if(logbits & LOG_FORWARD)
	printf("FORWARD ");
      if(logbits & LOG_LINK)
	printf("LINK ");

      printf("\n");
    }
  return 1;

 print_usage:
  printf("Usage: log <[set|unset] [CONNECT|FORWARD|LINK]>\n");
  return 0;

}

int
ohs_cmd_exit(FILE *handle, char *args)
{

  printf("Exitting... bye-bye!\n");

  ohs_close(0);
  return 0;
}

int
ohs_parse_command(FILE *handle)
{
  char input_data[100];
  int i;

  fscanf(handle, "%s", input_data);

  get_arg_buf(handle, arg_buf, ARG_BUF_SIZE);

  for(i = 0; ohs_commands[i].cmd; i++)
    {
      if(!strcmp(input_data, ohs_commands[i].cmd))
	{
	  if(ohs_commands[i].cmd_cb)
	    {
	      ohs_commands[i].cmd_cb(handle, arg_buf);
	    }
	  else
	    {
	      printf("No action registered on cmd %s!\n", input_data);
	    }
	  break;
	}
    }
  
  if(!ohs_commands[i].cmd)
    {
      printf("%s: no such cmd!\n", input_data);
    }


  return 0;
}
