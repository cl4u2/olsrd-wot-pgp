
/*
 * HTTP Info plugin for the olsr.org OLSR daemon
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
 * $Id: admin_interface.c,v 1.1 2005/02/08 23:29:40 kattemat Exp $
 */

/*
 * Dynamic linked library for the olsr.org olsr daemon
 */


#include "olsrd_httpinfo.h"
#include "olsr_cfg.h"
#include "admin_html.h"
#include "admin_interface.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>



#ifdef INCLUDE_SETTINGS

int
build_admin_body(char *buf, olsr_u32_t bufsize)
{
  int size = 0, i = 0;

  while(admin_frame[i] && strcmp(admin_frame[i], "<!-- BASICSETTINGS -->\n"))
    {
      size += sprintf(&buf[size], admin_frame[i]);
      i++;
    }
  
  if(!admin_frame[i])
    return size;


  size += sprintf(&buf[size], "<tr>\n");

  size += sprintf(&buf[size], admin_basic_setting_int,
		  "Debug level:", "debug_level", 2, cfg->debug_level);
  size += sprintf(&buf[size], admin_basic_setting_float,
		  "Pollrate:", "pollrate", 4, cfg->pollrate);
  size += sprintf(&buf[size], admin_basic_setting_string,
		  "TOS:", "tos", 6, "TBD");

  size += sprintf(&buf[size], "</tr>\n");
  size += sprintf(&buf[size], "<tr>\n");

  size += sprintf(&buf[size], admin_basic_setting_int,
		  "TC redundancy:", "tc_redundancy", 1, cfg->tc_redundancy);
  size += sprintf(&buf[size], admin_basic_setting_int,
		  "MPR coverage:", "mpr_coverage", 1, cfg->mpr_coverage);
  size += sprintf(&buf[size], admin_basic_setting_int,
		  "Willingness:", "willingness", 1, cfg->willingness);

  size += sprintf(&buf[size], "</tr>\n");
  size += sprintf(&buf[size], "<tr>\n");

  if(cfg->use_hysteresis)
    {
      size += sprintf(&buf[size], admin_basic_setting_float,
		      "Hyst scaling:", "hyst_scaling", 4, cfg->hysteresis_param.scaling);

      size += sprintf(&buf[size], admin_basic_setting_float,
		      "Lower thr:", "hyst_lower", 4, cfg->hysteresis_param.thr_low);
      size += sprintf(&buf[size], admin_basic_setting_float,
		      "Upper thr:", "hyst_upper", 4, cfg->hysteresis_param.thr_high);
    }
  else
    {
      size += sprintf(&buf[size], "<td>Hysteresis disabled</td>\n");
    }

  size += sprintf(&buf[size], "</tr>\n");
  size += sprintf(&buf[size], "<tr>\n");
  
  if(cfg->lq_level)
    {
      size += sprintf(&buf[size], admin_basic_setting_int,
		      "LQ level:", "lq_level", 1, cfg->lq_level);
      size += sprintf(&buf[size], admin_basic_setting_int,
		      "LQ winsize:", "lq_wsize", 1, cfg->lq_wsize);
    }
  else
    {
      size += sprintf(&buf[size], "<td>LQ disabled</td>\n");
    }


  size += sprintf(&buf[size], "</tr>\n");
  size += sprintf(&buf[size], "<tr>\n");

  size += sprintf(&buf[size], "</tr>\n");
  
  i++;

  while(admin_frame[i] && strcmp(admin_frame[i], "<!-- HNAENTRIES -->\n"))
    {
      size += sprintf(&buf[size], admin_frame[i]);
      i++;
    }

  if(!admin_frame[i] || !admin_frame[i+1])
    return size;

  i++;

  if((cfg->ip_version == AF_INET) && (cfg->hna4_entries))
    {
      struct hna4_entry *hna4;
      
      for(hna4 = cfg->hna4_entries; hna4; hna4 = hna4->next)
	{
	  size += sprintf(&buf[size], admin_frame[i], 
			  olsr_ip_to_string((union olsr_ip_addr *)&hna4->net),
			  olsr_ip_to_string((union olsr_ip_addr *)&hna4->netmask));
	}
    }
  else if((cfg->ip_version == AF_INET6) && (cfg->hna6_entries))
    {
      struct hna6_entry *hna6;
	
      for(hna6 = cfg->hna6_entries; hna6; hna6 = hna6->next)
	{
	  size += sprintf(&buf[size], admin_frame[i], 
			  olsr_ip_to_string((union olsr_ip_addr *)&hna6->net),
			  "TBD"/*hna6->prefix_len*/);
	}
    }
  
  i++;

  while(admin_frame[i])
    {
      size += sprintf(&buf[size], admin_frame[i]);
      i++;
    }
  
  return size;
}


int
process_param(char *key, char *value)
{

  if(!strcmp(key, "debug_level"))
    {
      int dl = atoi(value);
      if((dl < 0) || (dl > 9))
	return -1;

      cfg->debug_level = dl;
    }

  return 0;
#if 0
  { 1, admin_basic_setting_float, "Pollrate:", "pollrate", 4, &cfg->pollrate },
  { 1, admin_basic_setting_string, "TOS:", "tos", 6, "TBD" },

  { 1, admin_basic_setting_int, "TC redundancy:", "tc_redundancy", 1, &cfg->tc_redundancy},
  { 1, admin_basic_setting_int, "MPR coverage:", "mpr_coverage", 1, &cfg->mpr_coverage },
  { 1, admin_basic_setting_int, "Willingness:", "willingness", 1, &cfg->willingness },

  { cfg->use_hysteresis, admin_basic_setting_float, "Hyst scaling:", "hyst_scaling", 4, &cfg->hysteresis_param.scaling },
  { cfg->use_hysteresis, admin_basic_setting_float, "Lower thr:", "hyst_lower", 4, &cfg->hysteresis_param.thr_low },
  { cfg->use_hysteresis, admin_basic_setting_float, "Upper thr:", "hyst_upper", 4, &cfg->hysteresis_param.thr_high },

  { cfg->lq_level, admin_basic_setting_int, "LQ level:", "lq_level", 1, &cfg->lq_level},
  { cfg->lq_level, admin_basic_setting_int, "LQ winsize:", "lq_wsize", 1, &cfg->lq_wsize},

#endif
}

int
process_set_values(char *data, olsr_u32_t data_size, char *buf, olsr_u32_t bufsize)
{
  int size = 0;
  int i, val_start, key_start;

  size += sprintf(buf, "<html>\n<head></head>\n<body>\nDATA:<br>\n%s\n", data);

  key_start = 0;
  val_start = 0;

  for(i = 0; i < data_size; i++)
    {
      if(data[i] == '=')
	{
	  data[i] = '\0';
	  val_start = i + 1;
	}

      if(data[i] == '&')
	{
	  data[i] = '\0';
	  size += sprintf(&buf[size], "<b>Key:</b>%s<br>\n<b>Value:</b>%s<br>\n", 
			  &data[key_start], &data[val_start]);
	  process_param(&data[key_start], &data[val_start]);
	  printf("Key: %s\nValue: %s\n", 
		 &data[key_start], &data[val_start]);
	  key_start = i + 1;
	}
    }  

  size += sprintf(&buf[size], "\n</body>\n</html>\n");

  printf("Dynamic Data: %s\n", data);
  return size;
}
#endif
