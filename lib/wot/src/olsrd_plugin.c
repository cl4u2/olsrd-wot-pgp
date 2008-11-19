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



#include "olsrd_plugin.h"
#include "olsrd_secure.h"
#include <stdio.h>
#include <string.h>
#include "wot_olsrd.h"
#include "defs.h"


#define PLUGIN_NAME    "OLSRD web of trust plugin"
#define PLUGIN_VERSION "0.1"
#define PLUGIN_AUTHOR   "Claudio Pisa, Andreas Tonnesen"
#define MOD_DESC PLUGIN_NAME " " PLUGIN_VERSION " by " PLUGIN_AUTHOR
#define PLUGIN_INTERFACE_VERSION 5

static void my_init(void) __attribute__ ((constructor));
static void my_fini(void) __attribute__ ((destructor));

/*
 * Defines the version of the plugin interface that is used
 * THIS IS NOT THE VERSION OF YOUR PLUGIN!
 * Do not alter unless you know what you are doing!
 */
int olsrd_plugin_interface_version(void)
{
  return PLUGIN_INTERFACE_VERSION;
}


/**
 *Constructor
 */
static void my_init(void)
{
  /* Print plugin info to stdout */
  /* We cannot use olsr_printf yet! */
  printf("%s\n", MOD_DESC);
  printf("[WOT]Accepted parameter pairs: (\"Keyname\" <GPG_KEY_PATTERN>)\n"); 
  printf("[WOT]Accepted parameter pairs: (\"Passphrase\" <GPG_KEY_PASSPHRASE>)\n"); 
  printf("[WOT]Accepted parameter pairs: (\"gpgfilename\" <GPG_EXECUTABLE_FILENAME>)\n"); 
  printf("[WOT]Accepted parameter pairs: (\"gpghomedir\" <GPG_HOME_DIR>)\n"); 
  printf("[WOT]Accepted parameter pairs: (\"passphrasehelper\" <GPG_PASSPHRASE_HELPER_EXECUTABLE>)\n"); 
  printf("[WOT]Accepted parameter pairs: (\"ipowner\" <IP_ADDRESS IP_OWNER>)\n"); 
  passphrasehelper[0] = '\0';
}

/**
 *Destructor
 */
static void my_fini(void)
{

  /* Calls the destruction function
   * olsr_plugin_exit()
   * This function should be present in your
   * sourcefile and all data destruction
   * should happen there - NOT HERE!
   */
  secure_plugin_exit();
}

static int store_string(const char *value, void *data, set_plugin_parameter_addon addon __attribute__((unused)))
{
  char *str = data;
  snprintf(str, FILENAME_MAX+1, "%s", value);
  return 0;
}

static int store_owner(const char *value, void *data __attribute__((unused)), set_plugin_parameter_addon addon __attribute__((unused)))
{
  /* split value into ip_address, ip_owner pairs and populate the ip2emailmap map */
  char * ip_address;
  char * ip_owner;
  int i;

  if(ip2emailmap == NULL) 
		  ip2emailmap = ip2email_map_new();

  ip_address = (char *)malloc(sizeof(char)*128 + 1);
  ip_owner = (char *)malloc(sizeof(char)*500 + 1);
  i = sscanf(value, "%128s %500s", ip_address, ip_owner);
  if (i != 2) 
  {
		  OLSR_PRINTF(0, "Cannot get IP address and owner from \"%s\"", value);
		  return 1;
  }

  wotplugin_update_ip2emailmap(ip_address, ip_owner);
  return 0;
}

static const struct olsrd_plugin_parameters plugin_parameters[] = {
    { .name = "keyname", .set_plugin_parameter = &store_string, .data = keyname },
    { .name = "passphrase", .set_plugin_parameter = &store_string, .data = passphrase },
    { .name = "gpgfilename", .set_plugin_parameter = &store_string, .data = gpgfilename },
    { .name = "gpghomedir", .set_plugin_parameter = &store_string, .data = gpghomedir },
    { .name = "passphrasehelper", .set_plugin_parameter = &store_string, .data = passphrasehelper },
    { .name = "ipowner", .set_plugin_parameter = &store_owner, .data = NULL},
};

void olsrd_get_plugin_parameters(const struct olsrd_plugin_parameters **params, int *size)
{
    *params = plugin_parameters;
    *size = sizeof(plugin_parameters)/sizeof(*plugin_parameters);
}

int olsrd_plugin_init(void) {
  /* Calls the initialization function
   * olsr_plugin_init()
   * This function should be present in your
   * sourcefile and all data initialization
   * should happen there - NOT HERE!
   */
  if(!secure_plugin_init())
    {
      fprintf(stderr, "Could not initialize plugin!\n");
      return 0;
    }

  if(!plugin_ipc_init())
    {
      fprintf(stderr, "Could not initialize plugin IPC!\n");
      return 0;
    }
  return 1;

}
