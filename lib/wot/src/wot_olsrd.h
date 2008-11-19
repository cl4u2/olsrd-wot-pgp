/*
 * Web of Trust OLSR plugin
 *
 * Copyright (c) 2008 by Claudio Pisa (clauz at ninux dot org)
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
 * * The name of the author may not be used to endorse or promote 
 *   products derived from this software without specific prior written 
 *   permission. 
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

#ifndef _OLSRD_WOT
#define _OLSRD_WOT

#include <gpgme.h>
#include <unistd.h>
#include <sys/time.h>
#include "olsr_types.h"
#include "wot_messages.h"
#include "kernel_policy_routes.h"
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include "ip_to_email_map.h"
#include <string.h>
#include "prefix_to_trust_map.h"

#define WOT_FULL_TABLE 210
#define WOT_MARGINAL_TABLE 220
#define WOT_UNKNOWN_TABLE (olsr_cnf->rttable != 0 ? olsr_cnf->rttable : 254)

/* context used for signing and verifying packet signatures */
extern gpgme_ctx_t signcontext, verifycontext, keylistcontext; 

/* the key we will use to sign packets */
extern gpgme_key_t signingkey; 

/* the map that holds ip-address -> e-mail associations */
extern struct ip2email_map_node * ip2emailmap;

/* the map that holds prefix -> trust level associations */
extern struct pfx2trust_map_node * pfx2trustmap;

int wotplugin_init(void);
int wotplugin_finish(void);
/* verify signature and timestamp return 1 if OK */
int wotplugin_verify(const olsr_u8_t *pck, int *size, const struct s_olsrmsg *msg); 

/* put signature in msg->sig.signature */
int wotplugin_sign(olsr_u8_t *pck, int *size, struct s_olsrmsg *msg); 

/* sign a challenge message */
int wotplugin_challenge_sign(struct challengemsg *cmsg);

/* Sign a challenge-response message */
int wotplugin_cres_sign(struct c_respmsg *msg);

/* Signa a response-response message */
int wotplugin_rres_sign(struct r_respmsg *msg);

/* Verify signature and digest of a timestamp exchange challenge-response message. */
int wotplugin_cresponse_verify(struct c_respmsg *msg);

/* Verify signature and digest of a timestamp exchange response-response message. */
int wotplugin_rresponse_verify(struct r_respmsg *msg);

/* Verify signature and digest of a timestamp exchange challenge message. */
int wotplugin_challenge_verify(struct challengemsg *msg);

int wotplugin_add_policy_route(struct rt_entry *r); 

int wotplugin_del_policy_route(struct rt_entry *r);

/* check that the originator corresponds to the author of the signature */
int wotplugin_check_author(gpgme_signature_t signature, olsr_u32_t originator, gpgme_validity_t *owner_trust);

void wotplugin_update_ip2emailmap(char * key_ip, char * value_email);
#endif

