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
 *POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Dynamic linked library example for UniK OLSRd
 */

#ifndef _OLSRD_PLUGIN_WOT
#define _OLSRD_PLUGIN_WOT

#include "wot_messages.h"

#include "hashing.h"


/* Schemes */
#define ONE_CHECKSUM          1

/* Algorithm definitions */
#define SHA1_INCLUDING_KEY   1
#define MD5_INCLUDING_KEY   2
#define PGP_SIG		3

#define SIGNATURE_SIZE 1024 
#define MAX_KEY_NAME_SIZE 255
#define MAX_PASSPHRASE_SIZE 1024
extern char keyname[MAX_KEY_NAME_SIZE+1];
extern char passphrase[MAX_PASSPHRASE_SIZE+1];
extern char gpgfilename[FILENAME_MAX+1];
extern char gpghomedir[FILENAME_MAX+1];
extern char passphrasehelper[FILENAME_MAX+1];

#define UPPER_DIFF 20
#define LOWER_DIFF -20

/* Seconds of slack allowed */
#define SLACK 3

int secure_plugin_init(void);

void secure_plugin_exit(void);

int plugin_ipc_init(void);

#endif
