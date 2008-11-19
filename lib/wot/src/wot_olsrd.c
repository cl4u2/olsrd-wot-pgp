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


#include "wot_olsrd.h"
#include <gpgme.h>
#include <stdlib.h>
#include "olsr.h"
#include "olsrd_secure.h"
#include <linux/rtnetlink.h>
#include "kernel_policy_routes.h"
#include <pthread.h>

/* contexts used for signing and verifying packet signatures and key listing operations */
gpgme_ctx_t signcontext, verifycontext, keylistcontext; 

/* the key we will use to sign packets */
gpgme_key_t signingkey; 

/* the map that holds ip-address -> e-mail associations */
struct ip2email_map_node * ip2emailmap = NULL;

/* the map that holds prefix -> trust level associations */
struct pfx2trust_map_node * pfx2trustmap = NULL;

/* the variable that holds the actual trust state */
gpgme_validity_t state_of_the_trust;
/* and its mutex */
pthread_mutex_t trust_state_mutex = PTHREAD_MUTEX_INITIALIZER;

int errorcheck(gpgme_error_t err, const char *message); 
gpgme_validity_t get_trust_state(void);
int set_trust_state(gpgme_validity_t trustvalue);
gpgme_error_t wot_passphrase_callback(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd);
gpgme_error_t wot_passphrase_helper_callback(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd);
float tdiff(struct timeval *end, struct timeval *start);
gpgme_validity_t max_trust(gpgme_validity_t a, gpgme_validity_t b);
gpgme_validity_t wotplugin_get_max_trust_from_ip(olsr_u32_t ip_address);
olsr_u8_t wotplugin_validity2table(gpgme_validity_t validity);

#ifdef DEBUG
void printpacket(const olsr_u8_t *pck, int *size, const struct s_olsrmsg *msg);
int testz();

int 
testz()
{
	/* perform some sanity tests */
	struct pfx2trust_map_node * tmpmap = NULL;
	gpgme_validity_t tmptrust = GPGME_VALIDITY_ULTIMATE;
	gpgme_validity_t tmptrust2 = GPGME_VALIDITY_UNDEFINED;
	struct olsr_ip_prefix tmpprefix; 
	tmpprefix.prefix.v4.s_addr = 0x0a00000a;
	tmpprefix.prefix_len = 0x0b;

	tmpmap = pfx2trust_map_new();
	pfx2trust_map_update(tmpmap, &tmpprefix, tmptrust);
	tmptrust2 = pfx2trust_map_lookup(tmpmap, &tmpprefix);
	printf("Retrieved trust: %d\n", tmptrust2);
	printf("false: %d true: %d\n", 1==0, 0==0);
	if(tmptrust != tmptrust2)
		exit(1);
	return 1;

}

void
printpacket(const olsr_u8_t *pck, int *size, const struct s_olsrmsg *msg)
{
	int i;
	olsr_u8_t *msgsignature;

	msgsignature = (olsr_u8_t *)&msg[sizeof(msg)];

	olsr_printf(8, "[WOT]Packet size: %d", *size);
	for(i = 0; i < *size; i++){
		if(i % 10 == 0)
			olsr_printf(8, "\n  ");
		olsr_printf(8, "%2x.", pck[i]);
	}
	olsr_printf(8, "\n");

	olsr_printf(8, "[WOT]Solsr message:\n  type:%x\n  vtime:%x\n  size:%d\n  originator:%x\n  ttl:%d\n  hops:%d\n  seq:%x\n",
			msg->olsr_msgtype, msg->olsr_vtime, ntohs(msg->olsr_msgsize), msg->originator, msg->ttl, msg->hopcnt, msg->seqno);
	olsr_printf(8, "[WOT]Solsr submessage:\n  type:%x\n  algo:%x\n  timestamp:%d\n",
			msg->sig.type, msg->sig.algorithm, (int)msg->sig.timestamp);

/*	olsr_printf(8, "[WOT]Signature:");
	for(i=0; i< msg->olsr_msgsize-sizeof(msg); i++)
	{
		if(i % 10 == 0)
			olsr_printf(8, "\n  ");
		olsr_printf(8, "%2x.", msgsignature[i]);
	}
	olsr_printf(8, "\n"); 
	
	*/
}

#endif

void wotplugin_update_ip2emailmap(char * key_ip, char * value_email)
{
		olsr_u32_t new_ip_address;

		if(inet_pton(AF_INET, key_ip, &new_ip_address) <= 0) { ;
        	OLSR_PRINTF(0, "Illegal IP address \"%s\"", key_ip);
	        return;
		}
		
		ip2email_map_update(ip2emailmap, new_ip_address, value_email);
}

int 
errorcheck(gpgme_error_t err, const char *message) 
{
	if(!err)
	{
		olsr_printf(5,"[WOT]OK - %s\n", message);
		return 1;
	}
	else
	{
		olsr_printf(1, "[WOT]ERRROR!!!! - %s\n", message);
		olsr_printf(1, "[WOT]%s: %s\n", gpgme_strsource(err), gpgme_strerror(err));
		return 0;
	}
}

gpgme_error_t 
wot_passphrase_callback(void *hook __attribute__((unused)), const char *uid_hint __attribute__((unused)), const char *passphrase_info __attribute__((unused)), int prev_was_bad __attribute__((unused)), int fd)
{
	strncat(passphrase, "\n", 1);
	write(fd, passphrase, strlen(passphrase));
	return 0;
}

gpgme_error_t 
wot_passphrase_helper_callback(void *hook __attribute__((unused)), const char *uid_hint __attribute__((unused)), const char *passphrase_info __attribute__((unused)), int prev_was_bad __attribute__((unused)), int fd)
{
	char passphrasehelperoutput[MAX_PASSPHRASE_SIZE];
	FILE *phstream;

	olsr_printf(3,"[WOT]Executing passphrase helper\n");

	if(!(phstream = popen(passphrasehelper, "r")))
		return 1;

	fread(passphrasehelperoutput, sizeof(char), MAX_PASSPHRASE_SIZE-1, phstream);

	if(pclose(phstream) == -1)
		return 1;

	write(fd, passphrasehelperoutput, strlen(passphrasehelperoutput));

	return 0;
}

float 
tdiff(struct timeval *end, struct timeval *start)
{ /* Returns time difference in milliseconds between end and start */
	float ret;
	ret = 1000 * (end->tv_sec - start->tv_sec);
	ret += (end->tv_usec - start->tv_usec)/1000.0;
	return ret;
}

int 
wotplugin_init(void) 
{
	gpgme_error_t err; 
	const char *vers; 

	olsr_printf(3, "[WOT]Initializing plugin\n");

	/* TODO: IPv6 support is not yet implemented */
	if(olsr_cnf->ip_version != AF_INET)
	{
			olsr_printf(0, "[WOT]Only IPv4 is supported\n");
			return 0;
	}

#ifdef DEBUG
	testz();
#endif

	/* Initialize ip2emailmap map structure */
	if(ip2emailmap == NULL)
		ip2emailmap = ip2email_map_new();

	/* Initialize pfx2trustmap map structure */
	pfx2trustmap = pfx2trust_map_new();

	/* Initialize gpgme stuff */
	vers = gpgme_check_version(NULL);
	
	/* set the config file parameters for OpenPGP protocol */
	if(strlen(gpgfilename) == 0 && strlen(gpghomedir) > 0)
	{
		err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, NULL, gpghomedir);
		if(!errorcheck(err, "Changing engine defaults")) return 0;
	}
	if(strlen(gpghomedir) == 0 && strlen(gpgfilename) > 0)
	{
		err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, gpgfilename, NULL);
		if(!errorcheck(err, "Changing engine defaults")) return 0;
	}
	if(strlen(gpghomedir) > 0 && strlen(gpgfilename) > 0)
	{
		err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, gpgfilename, gpghomedir);
		if(!errorcheck(err, "Changing engine defaults")) return 0;
	}

	/* create a new context for signatures */
	err = gpgme_new(&signcontext);
	if(!errorcheck(err, "New signing context")) return 0;

	/* context settings */
	err = gpgme_set_protocol(signcontext,GPGME_PROTOCOL_OpenPGP);
	if(!errorcheck(err, "Set protocol OpenPGP")) return 0;

	gpgme_set_armor(signcontext,0);
	gpgme_set_textmode(signcontext,0);

	err = gpgme_set_keylist_mode(signcontext, GPGME_KEYLIST_MODE_LOCAL);
	if(!errorcheck(err, "Keylist mode")) return 0;

	/* Set the callback function for the passphrase */
	if(strlen(passphrasehelper))
		gpgme_set_passphrase_cb(signcontext, wot_passphrase_helper_callback, NULL);
	else
		gpgme_set_passphrase_cb(signcontext, wot_passphrase_callback, NULL);

	/* select the key that will be used to sign */
	if(!strlen(keyname))
		strcpy(keyname, "");

	err = gpgme_op_keylist_start(signcontext, keyname, 0); 
	if(!errorcheck(err, "Keylisting")) return 0;					

	err = gpgme_op_keylist_next(signcontext, &signingkey);
	if(!errorcheck(err, "Choosing signing key")) return 0;

	if(!signingkey->can_sign)
	{
		olsr_printf(1, "[WOT]Error: key %s corresponding to fingerprint %s cannot sign\n", keyname, signingkey->subkeys->fpr); 
		exit(2);
	}
	else
	{
		olsr_printf(3, "[WOT]Signing with key pattern %s -> fingerprint %s\n", keyname, signingkey->subkeys->fpr);
	}
	
	err = gpgme_signers_add(signcontext,signingkey);
	if(!errorcheck(err, "Add signer")) return 0;

	/* create a new context for signature verification */
	err = gpgme_new(&verifycontext);
	if(!errorcheck(err, "New verifying context")) return 0;

	/* context settings */
	err = gpgme_set_protocol(verifycontext,GPGME_PROTOCOL_OpenPGP);
	if(!errorcheck(err, "Set protocol OpenPGP")) return 0;

	gpgme_set_armor(verifycontext,0);
	gpgme_set_textmode(verifycontext,0);

	err = gpgme_set_keylist_mode(verifycontext, GPGME_KEYLIST_MODE_LOCAL);
	if(!errorcheck(err, "Set keylist mode")) return 0;

	/* create a new context for key listing*/
	err = gpgme_new(&keylistcontext);
	if(!errorcheck(err, "New key listing context")) return 0;

	/* context settings */
	err = gpgme_set_protocol(keylistcontext,GPGME_PROTOCOL_OpenPGP);
	if(!errorcheck(err, "Set protocol OpenPGP")) return 0;

	gpgme_set_armor(keylistcontext,0);
	gpgme_set_textmode(keylistcontext,0);

	err = gpgme_set_keylist_mode(keylistcontext, GPGME_KEYLIST_MODE_LOCAL);
	if(!errorcheck(err, "Set keylist mode")) return 0;

	olsr_printf(3, "[WOT]Plugin initialized\n");
	return 1;

}

int 
wotplugin_finish(void) 
{
	olsr_printf(3, "[WOT]Finalizing plugin\n");
	gpgme_release(signcontext);
	gpgme_release(verifycontext);
	gpgme_release(keylistcontext);
	gpgme_key_unref(signingkey);

	ip2email_map_destroy(ip2emailmap);
	pfx2trust_map_destroy(pfx2trustmap);
	pthread_mutex_destroy(&trust_state_mutex);

	return 1;

}

gpgme_validity_t 
max_trust(gpgme_validity_t a, gpgme_validity_t b)
{ /* Returns the 'biggest' between a and b */
  /* The ordering we need is NEVER < UNKNOWN < UNDEFINED < MARGINAL < FULL < ULTIMATE */
  /* In gpgme.h the ordering is UNKNOWN < UNDEFINED < NEVER < MARGINAL < FULL < ULTIMATE */
		if(a == b) return a;
		if(a == GPGME_VALIDITY_NEVER) return b;
		if(b == GPGME_VALIDITY_NEVER) return a;
		if(a > b) return a; else return b;
}

gpgme_validity_t
wotplugin_get_max_trust_from_ip(olsr_u32_t ip_address)
{   /* Returns the maximum level of trust associated to an IP address */
	char * stored_email = (char *) ip2email_map_lookup(ip2emailmap, ip_address);
	gpgme_error_t err; 
	gpgme_key_t key;
	gpgme_validity_t maxtrust = GPGME_VALIDITY_NEVER;

	if(stored_email == NULL)
	{
		olsr_printf(1, "[WOT] Unknown IP address (not present in olsrd.conf)\n");
		return GPGME_VALIDITY_UNKNOWN;
	}

	err = gpgme_op_keylist_start(keylistcontext, stored_email, 0);
	if(!errorcheck(err, "starting key listing")) return GPGME_VALIDITY_UNKNOWN;

	while (!err)
    {
			err = gpgme_op_keylist_next(keylistcontext, &key);
			if(err) break;
			olsr_printf(8, "[WOT] key 1st e-mail: %s validity: %d\n", key->uids->email, key->uids->validity);
			maxtrust = max_trust(key->uids->validity, maxtrust);
			gpgme_key_release(key);
	}

	if(gpg_err_code(err) != GPG_ERR_EOF) return GPGME_VALIDITY_UNKNOWN;
	err = gpgme_op_keylist_end(keylistcontext);
	//if(!errorcheck(err, "ending key listing")) return GPGME_VALIDITY_UNKNOWN;
	olsr_printf(8, "[WOT]Max trust for IP address %x is %d\n", ip_address, maxtrust);
	return maxtrust;
}

int 
wotplugin_check_author(gpgme_signature_t signature, olsr_u32_t originator, gpgme_validity_t *key_validity) 
{ /*check that the originator corresponds to the author of the signature
	and store the trust level associated to the signature in key_validity.
	Returns 0 on failure, 1 on success. 
	*/
	gpgme_key_t retrieved_key;
	gpgme_error_t err; 
	gpgme_user_id_t cur_uid;
	char * stored_email = (char *) ip2email_map_lookup(ip2emailmap, originator);

	olsr_printf(5, "[WOT] Beginning author check\n");

	*key_validity = GPGME_VALIDITY_NEVER;

	if(stored_email == NULL)
	{
		olsr_printf(2, "[WOT] Unknown message originator\n");
		return 0;
	}
	
	olsr_printf(8, "[WOT] Originator known: %s\n", stored_email);
	olsr_printf(8, "[WOT] Fingerprint: %s\n", signature->fpr);

	/* now retrieve the fields of the key */
	err = gpgme_get_key(keylistcontext, signature->fpr, &retrieved_key, 0); 
	if(!errorcheck(err, "signature author verification key retrieving")) return 0;

	/* unknown originator */
	if(retrieved_key == NULL)
			return 1;

	*key_validity = retrieved_key->uids->validity;
	
	/* invalid key */
	if(retrieved_key->uids->invalid)
			return 1;

	/* check that the signature comes from the originator */
	cur_uid = retrieved_key->uids;
	while(cur_uid != NULL)
	{
			olsr_printf(8, "[WOT] User ID: %s\n", cur_uid->uid);
			olsr_printf(8, "[WOT] e-mail: %s\n", cur_uid->email);

			if(cur_uid->email != NULL && !strcmp(cur_uid->email, stored_email))
					return 1;
			/*
			if(cur_uid->name != NULL && !strcmp(cur_uid->name, stored_email))
					return 1;
			if(cur_uid->comment != NULL && !strcmp(cur_uid->comment, stored_email))
					return 1;
			*/

			cur_uid = cur_uid->next;
	}
	return 0;
}

int 
wotplugin_verify(const olsr_u8_t *pck, int *size, const struct s_olsrmsg *msg) 
{	/* verify signature and timestamp return 1 if OK */
	/* the signature is in msg->sig.signature */
	gpgme_verify_result_t verifyresult;
	gpgme_error_t err; 
	gpgme_data_t signature, packet;
	olsr_u16_t padding, packetlen, messagelen;
	gpgme_validity_t keytrust;
//	olsr_u8_t *msgsignature;
	struct timeval tvstart, tvend;
	
	olsr_printf(3, "[WOT]Verifying solsr message seq %x\n", msg->seqno);
	
	gettimeofday(&tvstart, NULL);

	/* check that the recieved message is of the expected type */
	olsr_printf(5, "[WOT]Message type: %d\n", msg->olsr_msgtype);
	if(msg->olsr_msgtype != MESSAGE_TYPE)
		return 0;

	/* check the maximum trust level associated with the originator */	
	/* if is not high enough don't even check the signature */
	switch(wotplugin_get_max_trust_from_ip(msg->originator))
	{
			case GPGME_VALIDITY_NEVER:
					olsr_printf(5, "[WOT] Untrusted message originator! Dropping...\n");
					return 0;
			case GPGME_VALIDITY_UNKNOWN:
					olsr_printf(7, "[WOT] Unknown message originator. Going on...\n");
					set_trust_state(GPGME_VALIDITY_UNKNOWN);
					return 1;
			default:
					;
	};

	olsr_printf(7, "[WOT] Now checking signature...\n");
	
	/* Pad the packet */
	memmove(&padding, &(msg->sig.timestamp), sizeof(padding));
	memmove(&packetlen, &(((struct olsr*)pck)->olsr_packlen), sizeof(packetlen));
	memmove(&messagelen, &(msg->olsr_msgsize), sizeof(messagelen));
	memmove(&(((struct olsr*)pck)->olsr_packlen), &padding, sizeof(packetlen));
	memmove(&(msg->olsr_msgsize), &padding, sizeof(messagelen));
	
	olsr_printf(7, "[WOT]Message length: %d\n", ntohs(messagelen));
	olsr_printf(7, "[WOT]Packet padded using padding %x\n", padding);

	/* make a new data object from the packet without the signature */
	err = gpgme_data_new_from_mem(&packet, (const char *)pck, (long)msg->sig.signature - (long)pck, 1);
	if(!errorcheck(err, "verify: New data object from packet")) return 0;

	olsr_printf(7, "[WOT]Packet size: %d Original packet size: %d\n", (int) gpgme_data_seek(packet, 0, SEEK_END), *size);

	/* and a new data object from the signature */ //TODO: change 20 with something better!
	err = gpgme_data_new_from_mem(&signature, (const char *)msg->sig.signature, ntohs(messagelen) - 20, 1);
	if(!errorcheck(err, "verify: New data object from signature")) return 0;

	olsr_printf(7, "[WOT]Signature size: %d\n", (int) gpgme_data_seek(signature, 0, SEEK_END));

	/* verify */
	gpgme_data_seek(packet, 0, SEEK_SET);
	gpgme_data_seek(signature, 0, SEEK_SET);
	err = gpgme_op_verify(verifycontext, signature, packet, NULL);
	if(!errorcheck(err, "verify: Signature verification")) return 0;

	verifyresult = gpgme_op_verify_result(verifycontext);
	
	/* Release resources */
	gpgme_data_release(packet);
	gpgme_data_release(signature);
	
	/* Bring back the length fields that were padded */
	memcpy(&(((struct olsr*)pck)->olsr_packlen), &packetlen, sizeof(packetlen));
	memcpy(&(msg->olsr_msgsize), &messagelen, sizeof(messagelen));
	
	olsr_printf(7, "[WOT]Verify: packet unpadded\n");

	olsr_printf(8, "[WOT]Signature status: %s\n", gpgme_strerror(verifyresult->signatures->status));
	olsr_printf(8, "[WOT]Signature fingerprint: %s\n", verifyresult->signatures->fpr);
	if(verifyresult->signatures->next != NULL)
		olsr_printf(2, "[WOT]There's another signature!!!!!!!!?\n");
	
	if(
		verifyresult->signatures->summary & GPGME_SIGSUM_VALID ||
		verifyresult->signatures->summary & GPGME_SIGSUM_GREEN ||
		verifyresult->signatures->summary == 0 
	  )
	{
		olsr_printf(3, "[WOT]Signature is valid. Msg seqno=%xi, originator=%x \n", msg->seqno, msg->originator);
	}
	else
	{
		errorcheck(verifyresult->signatures->status, "signature verification");
		olsr_printf(1, "[WOT]Basic signature is NOT valid! seqno=%x, originator=%x \n", msg->seqno, msg->originator);
		return 0; /* signature not ok */
	}

	/* Check that the author of the signature is the originator */
	if(wotplugin_check_author(verifyresult->signatures, msg->originator, &keytrust))
	{
		olsr_printf(3, "[WOT]Signature author is valid. Msg seqno=%xi, originator=%x \n", msg->seqno, msg->originator);
	}
	else
	{
		olsr_printf(1, "[WOT]Basic signature author is NOT valid or not trusted! seqno=%x, originator=%x \n", msg->seqno, msg->originator);
		return 0; /* signature not ok */
	}
	
	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Basic signature verification total time: %f milliseconds\n", tdiff(&tvend, &tvstart));

	set_trust_state(keytrust);

	return 1;
}

int 
wotplugin_sign(olsr_u8_t *pck, int *size, struct s_olsrmsg *msg) 
{	/* sign a secure-wot olsr message */
	/* put signature in msg->sig.signature */
	gpgme_error_t err; 
	gpgme_data_t signature, packet;
	gpgme_sign_result_t sigres;
	ssize_t bytesread;
	olsr_u16_t padding, packetlen, messagelen;
#ifdef DEBUG
	gpgme_verify_result_t verifyresult;
#endif
	olsr_u8_t singlebytebuffer;
	struct timeval tvstart, tvend;
	int i;
	
	olsr_printf(3, "[WOT]Signing olsr packet with a secure-olsr message\n");

	gettimeofday(&tvstart, NULL);


	/* We don't know what will be the real size of the signature, 
	 * so we pad packet and message lengths.    
	 * We use the timestamp as the padding
	 * */
	memmove(&padding, &(msg->sig.timestamp), sizeof(padding));
	packetlen = ntohs(((struct olsr*)pck)->olsr_packlen);
	messagelen = ntohs(msg->olsr_msgsize);
	memmove(&(((struct olsr*)pck)->olsr_packlen), &padding, sizeof(packetlen));
	memmove(&(msg->olsr_msgsize), &padding, sizeof(messagelen));

	olsr_printf(7, "[WOT]Packet padded using %x\n", padding);

	/* make a new data object from the message without the signature */
	err = gpgme_data_new_from_mem(&packet, (char *)pck, (long)msg->sig.signature - (long)pck, 1);
	if(!errorcheck(err, "New data object from message")) return 0;

	/* and a new data object for the signature */
	err = gpgme_data_new(&signature);
	if(!errorcheck(err, "New data object for signature")) return 0;

	err = gpgme_op_sign(signcontext, packet, signature, GPGME_SIG_MODE_DETACH);
	if(!errorcheck(err, "Creating new signature")) return 0;

	sigres = gpgme_op_sign_result(signcontext);

	if(sigres == NULL) 
	{ 
		olsr_printf(1, "[WOT]Signature failed\n");
		return 0; /* signature failed */
	}

	if(sigres->invalid_signers != NULL) 
	{
		olsr_printf(1, "[WOT]Invalid signature\n");
		return 0; /* invalid signature */
	}

	if(sigres->signatures == NULL) 
	{
		olsr_printf(1, "[WOT]Error creating signature\n");
		return 0; /* something went wrong */
	}

	olsr_printf(7,"[WOT]Signature size: %d\n", (int)gpgme_data_seek(signature, 0, SEEK_END));
	olsr_printf(7, "[WOT]Signer fingerprint: %s\n", sigres->signatures->fpr);

#ifdef DEBUG
	//check the correctness of the signature we just made
	olsr_printf(8, "[WOT]Signature test...\n");
	gpgme_data_seek(signature, 0, SEEK_SET);
	gpgme_data_seek(packet, 0, SEEK_SET);
	err = gpgme_op_verify(verifycontext, signature, packet, NULL);
	if(!errorcheck(err, "Signature test: Signature verification")) return 0;
	verifyresult = gpgme_op_verify_result(verifycontext);
	if(
		verifyresult->signatures->summary & GPGME_SIGSUM_VALID ||
		verifyresult->signatures->summary & GPGME_SIGSUM_GREEN ||
		verifyresult->signatures->summary == 0 
	  )
		olsr_printf(8, "[WOT]Signature test passed.\n");
	else
		olsr_printf(1, "[WOT]Signature test NOT PASSED!!!!!.\n");
#endif

	/* Write the signature in the message */
	/* rewind */
	if(gpgme_data_seek(signature, 0, SEEK_SET) == -1) 
	{
		olsr_printf(1, "[WOT]Error changing read-write position\n");
		return 0; /* error while changing the current read/write position */ 
	}

	/* update length fields */
	msg->olsr_msgsize = htons(20 + gpgme_data_seek(signature, 0, SEEK_END));
	*size = packetlen - SIGSIZE + gpgme_data_seek(signature, 0, SEEK_END); 
	((struct olsr*)pck)->olsr_packlen = htons(*size);
	
	olsr_printf(8, "[WOT]Packet length fields updated (packet size: %d, message size: %d)\n", ntohs(((struct olsr*)pck)->olsr_packlen), ntohs(msg->olsr_msgsize));

	/* copy one byte at a time */
	gpgme_data_seek(signature, 0, SEEK_SET);
	bytesread = 0;
	for (i = 0; i < ntohs(msg->olsr_msgsize); i++)
	{
		bytesread += gpgme_data_read(signature, (void *)&singlebytebuffer, 1);
		msg->sig.signature[i] = singlebytebuffer;
	}
	if(bytesread < gpgme_data_seek(signature,0,SEEK_END)) 
	{
		olsr_printf(1, "[WOT]Error while copying signature. %d/%d bytes read\n", bytesread, ntohs(msg->olsr_msgsize));
		return 0; /* error while copying */
	}
	
	olsr_printf(3, "[WOT]Packet signed\n");
	
	/* Release resources */ //TODO: release resources also on error!
	gpgme_data_release(packet);
	gpgme_data_release(signature);

#ifdef DEBUG
	olsr_printf(8,"[WOT]Doing signature check\n");
	//sanity check!!!!
	if (wotplugin_verify(pck, size, msg)) 
	{
		olsr_printf(8,"[WOT]Signature check, packet seqno %x: success!\n", msg->seqno);
	}
	else
	{
		olsr_printf(3,"[WOT]Signature check, packet seqno %x: FAILURE!\n", msg->seqno);
	}
#endif
	
	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Basic signing total time: %f milliseconds\n", tdiff(&tvend, &tvstart));
	return 1;
}

int 
wotplugin_challenge_sign(struct challengemsg *cmsg) 
{	/* sign a challenge message */
	gpgme_error_t err; 
	gpgme_data_t signature, message;
	gpgme_sign_result_t sigres;
	ssize_t bytesread;
	struct timeval tvstart, tvend;
	
	olsr_printf(3, "[WOT]Signing challenge message\n");

	gettimeofday(&tvstart, NULL);

	/* pad the signature length */
	memcpy(&cmsg->sig_size, &cmsg->challenge, sizeof(cmsg->sig_size));
	/* but pad also the olsr message size */
	memcpy(&cmsg->olsr_msgsize, &cmsg->challenge, sizeof(cmsg->sig_size));
	
	/* make a new data object from the message without the signature */
	err = gpgme_data_new_from_mem(&message, (char *)cmsg, (long)cmsg->signature - (long)cmsg, 1);
	if(!errorcheck(err, "Creating a new data object from a challenge message for signing")) return 0;

	/* and a new data object for the signature */
	err = gpgme_data_new(&signature);
	if(!errorcheck(err, "Creating a new data object for a challenge message's signature")) return 0;
	
	err = gpgme_op_sign(signcontext, message, signature, GPGME_SIG_MODE_DETACH);
	if(!errorcheck(err, "Creating signature for a challenge message")) return 0;
	
	sigres = gpgme_op_sign_result(signcontext);
	
	if(sigres == NULL) 
	{ 
		olsr_printf(1, "[WOT]Challenge message signature failed\n");
		return 0; /* signature failed */
	}
	
	if(sigres->invalid_signers != NULL) 
	{
		olsr_printf(1, "[WOT]Invalid signature\n");
		return 0; /* invalid signature */
	}
	
	if(sigres->signatures == NULL) 
	{
		olsr_printf(1, "[WOT]Error creating signature\n");
		return 0; /* something went wrong */
	}
	
	/* Write the signature in the message */
	/* rewind */
	if(gpgme_data_seek(signature, 0, SEEK_SET) == -1) 
	{
		olsr_printf(1, "[WOT]Error changing read-write position\n");
		return 0; /* error while changing the current read/write position */ 
	}
	
	/* write */
	if((bytesread = gpgme_data_read(signature, cmsg->signature, SIGSIZE)) == -1) 
	{
		olsr_printf(1, "[WOT]Error while reading\n");
		return 0; /* error while reading */
	}
	
	/* Release resources */ //TODO: release resources also on error!
	gpgme_data_release(message);
	gpgme_data_release(signature);
	
	cmsg->sig_size = htons(bytesread);
	cmsg->olsr_msgsize = htons(sizeof(struct challengemsg) - SIGSIZE + bytesread);

	/* pad to align the message on 32 bits */
	cmsg->olsr_msgsize += htons((4 - (ntohs(cmsg->olsr_msgsize) % 4)) % 4);
	
	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Challenge message signing total time: %f milliseconds\n", tdiff(&tvend, &tvstart));

	return 1;
}

int 
wotplugin_cres_sign(struct c_respmsg *msg) 
{	/* Sign a challenge-response message. */
	gpgme_error_t err; 
	gpgme_data_t message_signature, message; 
	gpgme_sign_result_t sigres;
	ssize_t bytesread;
	struct timeval tvstart, tvend;

	olsr_printf(3, "[WOT]Signing challenge-response message\n");
	
	gettimeofday(&tvstart, NULL);

	/* pad the signature length */
	memcpy(&msg->sig_size, &msg->timestamp, sizeof(msg->sig_size));
	/* but pad also the olsr message size */
	memcpy(&msg->olsr_msgsize, &msg->timestamp, sizeof(msg->olsr_msgsize));

	/* make a new data object from the message with the first signature (the checksum) */
	err = gpgme_data_new_from_mem(&message, (char *)msg, (long)msg->signature - (long)msg, 1);
	if(!errorcheck(err, "Make a new data object from the whole message for the second signature")) return 0;

	/* and a new data object for the signature */
	err = gpgme_data_new(&message_signature);
	if(!errorcheck(err, "Make a new data object for the second signature")) return 0;

	err = gpgme_op_sign(signcontext, message, message_signature, GPGME_SIG_MODE_DETACH);
	if(!errorcheck(err, "Creating signature")) return 0;

	sigres = gpgme_op_sign_result(signcontext);

	if(sigres == NULL) 
	{
		olsr_printf(1, "[WOT]Signature failed\n");
		return 0; /* signature failed */
	}

	if(sigres->invalid_signers != NULL) 
	{
		olsr_printf(1, "[WOT]Invalid signature\n");
		return 0; /* invalid signature */
	}

	if(sigres->signatures == NULL) 
	{
		olsr_printf(1, "[WOT]Error creating signature\n");
		return 0; /* something went wrong */
	}
	
	/* Write the signature in the message */
	/* rewind */
	if(gpgme_data_seek(message_signature, 0, SEEK_SET) == -1) 
	{
		olsr_printf(1, "[WOT]Error changing read-write position\n");
		return 0; /* error while changing the current read/write position */ 
	}

	/* write */
	if((bytesread = gpgme_data_read(message_signature, msg->signature, SIGSIZE)) == -1)
	{
		olsr_printf(1, "[WOT]Error while reading\n");
		return 0; /* error while reading */
	}
	
	/* Release resources */ //TODO: release resources also on error!
	gpgme_data_release(message);
	gpgme_data_release(message_signature);

	msg->sig_size = htons(bytesread);
	msg->olsr_msgsize = htons(((long)msg->signature - (long)msg) + bytesread);

	/* 32 bit aligned padding */
	msg->olsr_msgsize = htons(ntohs(msg->olsr_msgsize) + ((4 - (ntohs(msg->olsr_msgsize) % 4)) % 4));
	
	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Challenge-response message signing total time: %f milliseconds\n", tdiff(&tvend, &tvstart));

	return 1;
}

int 
wotplugin_rres_sign(struct r_respmsg *msg) 
{	/* Sign a response-response message. */
	gpgme_error_t err; 
	gpgme_data_t message_signature, message; 
	gpgme_sign_result_t sigres;
	ssize_t bytesread;
	struct timeval tvstart, tvend;

	olsr_printf(3, "[WOT]Signing response-response message\n");

	gettimeofday(&tvstart, NULL);

	/* pad the signature length */
	memcpy(&msg->sig_size, &msg->timestamp, sizeof(msg->sig_size));
	/* but pad also the olsr message size */
	memcpy(&msg->olsr_msgsize, &msg->timestamp, sizeof(msg->olsr_msgsize));

	/* make a new data object from the message with the first signature (the checksum) */
	err = gpgme_data_new_from_mem(&message, (char *)msg, (long)msg->signature - (long)msg, 1);
	if(!errorcheck(err, "Make a new data object from the whole message for the second signature")) return 0;

	/* and a new data object for the signature */
	err = gpgme_data_new(&message_signature);
	if(!errorcheck(err, "Make a new data object for the second signature")) return 0;

	err = gpgme_op_sign(signcontext, message, message_signature, GPGME_SIG_MODE_DETACH);
	if(!errorcheck(err, "Creating signature")) return 0;

	sigres = gpgme_op_sign_result(signcontext);

	if(sigres == NULL) 
	{
		olsr_printf(1, "[WOT]Signature failed\n");
		return 0; /* signature failed */
	}

	if(sigres->invalid_signers != NULL) 
	{
		olsr_printf(1, "[WOT]Invalid signature\n");
		return 0; /* invalid signature */
	}

	if(sigres->signatures == NULL) 
	{
		olsr_printf(1, "[WOT]Error creating signature\n");
		return 0; /* something went wrong */
	}
	
	/* Write the signature in the message */
	/* rewind */
	if(gpgme_data_seek(message_signature, 0, SEEK_SET) == -1) 
	{
		olsr_printf(1, "[WOT]Error changing read-write position\n");
		return 0; /* error while changing the current read/write position */ 
	}

	/* write */
	if((bytesread = gpgme_data_read(message_signature, msg->signature, SIGSIZE)) == -1)
	{
		olsr_printf(1, "[WOT]Error while reading\n");
		return 0; /* error while reading */
	}
	
	/* Release resources */ //TODO: release resources also on error!
	gpgme_data_release(message);
	gpgme_data_release(message_signature);

	msg->sig_size = htons(bytesread);
	msg->olsr_msgsize = htons(((long)msg->signature - (long)msg) + bytesread);

	/* 32 bit aligned padding */
	msg->olsr_msgsize = htons(ntohs(msg->olsr_msgsize) + ((4 - (ntohs(msg->olsr_msgsize) % 4)) % 4));
	
	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Response-response message signing total time: %f milliseconds\n", tdiff(&tvend, &tvstart));

	return 1;
}

int 
wotplugin_cresponse_verify(struct c_respmsg *msg)
{	/* Verify signature and digest of a timestamp exchange response message. */
	/* verify signature and timestamp return 1 if OK */
	gpgme_verify_result_t verifyresult;
	gpgme_error_t err; 
	gpgme_data_t signature, message;
	olsr_u16_t signaturesize, messagesize;
	gpgme_validity_t keytrust;
	struct timeval tvstart, tvend;
	
	olsr_printf(3, "[WOT]Verifying challenge-response message\n");
	
	gettimeofday(&tvstart, NULL);
	
	/* pad the signature length */
	memcpy(&signaturesize, &msg->sig_size, sizeof(signaturesize));
	memcpy(&msg->sig_size, &msg->timestamp, sizeof(msg->sig_size));

	/* but pad also the olsr message size */
	memcpy(&messagesize, &msg->olsr_msgsize, sizeof(messagesize));
	memcpy(&msg->olsr_msgsize, &msg->timestamp, sizeof(msg->olsr_msgsize));

	/* Now verify the signature */
	/* make a new data object from the message without the signature */
	err = gpgme_data_new_from_mem(&message, (char *)msg, (long)msg->signature - (long)msg, 1);
	if(!errorcheck(err, "New data object from message")) return 0;

	/* and a new data object from the signature */
	err = gpgme_data_new_from_mem(&signature, (char *)msg->signature, ntohs(signaturesize), 1);
	if(!errorcheck(err, "New data object from signature")) return 0;

	/* verify */
	err = gpgme_op_verify(verifycontext, signature, message, NULL);
	if(!errorcheck(err, "Verifying signature")) return 0;

	verifyresult = gpgme_op_verify_result(verifycontext);
	
	/* Release resources */
	gpgme_data_release(message);
	gpgme_data_release(signature);

	/* unpad */
	memcpy(&msg->sig_size, &signaturesize, sizeof(msg->sig_size));
	memcpy(&msg->olsr_msgsize, &messagesize, sizeof(msg->olsr_msgsize));

	if(
		verifyresult->signatures->summary & GPGME_SIGSUM_VALID ||
		verifyresult->signatures->summary & GPGME_SIGSUM_GREEN ||
		verifyresult->signatures->summary == 0 
	  )
	{
		olsr_printf(3, "[WOT]challenge-response signature is valid\n");
	}
	else
	{
		errorcheck(verifyresult->signatures->status, "signature verification");
		olsr_printf(1, "[WOT]challenge-response signature is NOT valid!\n");
		return 0; /* signature not ok */
	}
	
	/* Check that the author of the signature is the originator */
	if(wotplugin_check_author(verifyresult->signatures, msg->originator, &keytrust))
	{
		olsr_printf(3, "[WOT]challenge-response signature author is valid\n");
	}
	else
	{
		olsr_printf(1, "[WOT]challenge-response signature author is NOT valid or not trusted!\n");
		return 0; /* signature not ok */
	}

	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Challenge-response message verification total time: %f milliseconds\n", tdiff(&tvend, &tvstart));

	return 1;
	
}

int 
wotplugin_rresponse_verify(struct r_respmsg *msg)
{	/* Verify signature and digest of a timestamp exchange response message. */
	/* verify signature and timestamp return 1 if OK */
	gpgme_verify_result_t verifyresult;
	gpgme_error_t err; 
	gpgme_data_t signature, message;
	olsr_u16_t signaturesize, messagesize;
	gpgme_validity_t keytrust;
	struct timeval tvstart, tvend;
	
	olsr_printf(3, "[WOT]Verifying response-response message\n");
	
	gettimeofday(&tvstart, NULL);

	/* pad the signature length */
	memcpy(&signaturesize, &msg->sig_size, sizeof(signaturesize));
	memcpy(&msg->sig_size, &msg->timestamp, sizeof(msg->sig_size));

	/* but pad also the olsr message size */
	memcpy(&messagesize, &msg->olsr_msgsize, sizeof(messagesize));
	memcpy(&msg->olsr_msgsize, &msg->timestamp, sizeof(msg->olsr_msgsize));

	/* Now verify the signature */
	/* make a new data object from the message without the signature */
	err = gpgme_data_new_from_mem(&message, (char *)msg, (long)msg->signature - (long)msg, 1);
	if(!errorcheck(err, "New data object from message")) return 0;

	memcpy(&msg->sig_size, &signaturesize, sizeof(msg->sig_size));
	memcpy(&msg->olsr_msgsize, &messagesize, sizeof(msg->olsr_msgsize));

	/* and a new data object from the signature */
	err = gpgme_data_new_from_mem(&signature, (char *)msg->signature, ntohs(msg->sig_size), 1);
	if(!errorcheck(err, "New data object from signature")) return 0;

	/* verify */
	err = gpgme_op_verify(verifycontext, signature, message, NULL);
	if(!errorcheck(err, "Verifying signature")) return 0;

	verifyresult = gpgme_op_verify_result(verifycontext);
	
	/* Release resources */
	gpgme_data_release(message);
	gpgme_data_release(signature);
	
	if(
		verifyresult->signatures->summary & GPGME_SIGSUM_VALID ||
		verifyresult->signatures->summary & GPGME_SIGSUM_GREEN ||
		verifyresult->signatures->summary == 0 
	  )
	{
		olsr_printf(3, "[WOT]response-response signature is valid\n");
	}
	else
	{
		errorcheck(verifyresult->signatures->status, "signature verification");
		olsr_printf(1, "[WOT]response-response signature is NOT valid!\n");
		return 0; /* signature not ok */
	}
	
	/* Check that the author of the signature is the originator */
	if(wotplugin_check_author(verifyresult->signatures, msg->originator, &keytrust))
	{
		olsr_printf(3, "[WOT]response-response signature author is valid\n");
	}
	else
	{
		olsr_printf(1, "[WOT]response-response signature author is NOT valid or not trusted!\n");
		return 0; /* signature not ok */
	}

	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Response-response message verification total time: %f milliseconds\n", tdiff(&tvend, &tvstart));

	return 1;
}


int 
wotplugin_challenge_verify(struct challengemsg *msg)
{	/* Verify signature and digest of a timestamp exchange challenge message. */
	/* verify signature and timestamp return 1 if OK */
	gpgme_verify_result_t verifyresult;
	gpgme_error_t err; 
	gpgme_data_t signature, message;
	olsr_u16_t signaturesize, messagesize;
	gpgme_validity_t keytrust;
	struct timeval tvstart, tvend;

	olsr_printf(3, "[WOT]Verifying challenge message\n");
	
	gettimeofday(&tvstart, NULL);
	
	/* pad the signature length */
	memcpy(&signaturesize, &msg->sig_size, sizeof(signaturesize));
	memcpy(&msg->sig_size, &msg->challenge, sizeof(msg->sig_size));

	/* but pad also the olsr message size */
	memcpy(&messagesize, &msg->olsr_msgsize, sizeof(messagesize));
	memcpy(&msg->olsr_msgsize, &msg->challenge, sizeof(msg->olsr_msgsize));

	/* make a new data object from the message without the signature */
	err = gpgme_data_new_from_mem(&message, (char *)msg, (long)msg->signature - (long)msg , 1);
	if(!errorcheck(err, "New data object from message")) return 0;

	memcpy(&msg->sig_size, &signaturesize, sizeof(msg->sig_size));
	memcpy(&msg->olsr_msgsize, &messagesize, sizeof(msg->olsr_msgsize));

	/* and a new data object from the signature */
	err = gpgme_data_new_from_mem(&signature, (char *)msg->signature, ntohs(msg->sig_size), 1);
	if(!errorcheck(err, "Creating a new object for the signature")) return 0;

	/* verify */
	err = gpgme_op_verify(verifycontext, signature, message, NULL);
	if(!errorcheck(err, "Verifying signature")) return 0;

	verifyresult = gpgme_op_verify_result(verifycontext);

	/* Release resources */
	gpgme_data_release(message);
	gpgme_data_release(signature);

	if(
		verifyresult->signatures->summary & GPGME_SIGSUM_VALID ||
		verifyresult->signatures->summary & GPGME_SIGSUM_GREEN ||
		verifyresult->signatures->summary == 0 
	  )
	{
		olsr_printf(3, "[WOT]Challenge seqno=%x signature is valid\n", msg->seqno);
	}
	else
	{
		olsr_printf(9, "[WOT] signature summary: %x\n", verifyresult->signatures->summary);
		olsr_printf(9, "[WOT] signature validity: %d\n", verifyresult->signatures->validity);
		if(verifyresult->signatures->wrong_key_usage)
			olsr_printf(8, "[WOT] wrong key usage!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_KEY_REVOKED)
			olsr_printf(8, "[WOT] key revoked!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_KEY_EXPIRED)
			olsr_printf(8, "[WOT] key expired!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_SIG_EXPIRED)
			olsr_printf(8, "[WOT] signature expired!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_KEY_MISSING)
			olsr_printf(8, "[WOT] key missing!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_CRL_MISSING)
			olsr_printf(8, "[WOT] CRL missing!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_CRL_TOO_OLD)
			olsr_printf(8, "[WOT] CRL too old!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_BAD_POLICY)
			olsr_printf(8, "[WOT] Bad policy!\n");
		if(verifyresult->signatures->summary & GPGME_SIGSUM_SYS_ERROR)
			olsr_printf(8, "[WOT] System error!\n");
		errorcheck(verifyresult->signatures->status, "signature verification");
		errorcheck(verifyresult->signatures->validity_reason, "validity reason");
		olsr_printf(8, "[WOT]Signer's fingerprint: %s\n", verifyresult->signatures->fpr);

		olsr_printf(1, "[WOT]Challenge seqno=%x signature is NOT valid!\n", msg->seqno);

		return 0; /* signature not ok */
	}
	
	/* Check that the author of the signature is the originator */
	if(wotplugin_check_author(verifyresult->signatures, msg->originator, &keytrust))
	{
		olsr_printf(3, "[WOT]challenge signature author is valid\n");
	}
	else
	{
		olsr_printf(1, "[WOT]challenge signature author is NOT valid or not trusted!\n");
		return 0; /* signature not ok */
	}
	
	gettimeofday(&tvend, NULL);
	olsr_printf(7, "[WOT] Challenge message verification total time: %f milliseconds\n", tdiff(&tvend, &tvstart));

	return 1;
}

int
set_trust_state(gpgme_validity_t trustvalue)
{	/* Sets the value of the state of the trust */
	pthread_mutex_lock(&trust_state_mutex);
	state_of_the_trust = trustvalue;
	pthread_mutex_unlock(&trust_state_mutex);
	return 1;
}

gpgme_validity_t
get_trust_state(void)
{	/* Returns the value of the state of the trust */
	gpgme_validity_t ret;
	pthread_mutex_lock(&trust_state_mutex);
	ret = state_of_the_trust;
	pthread_mutex_unlock(&trust_state_mutex);
	return ret;
}

olsr_u8_t
wotplugin_validity2table(gpgme_validity_t validity)
{
		switch(validity)
		{
				case GPGME_VALIDITY_FULL:
						return WOT_FULL_TABLE;
				case GPGME_VALIDITY_MARGINAL:
						return WOT_MARGINAL_TABLE;
				default: /* GPGME_VALIDITY_UNKNOWN: */
						return WOT_UNKNOWN_TABLE;
		}
}

int 
wotplugin_add_policy_route(struct rt_entry *r) 
{
  gpgme_validity_t trustvalue;
  int ret = 1;
  trustvalue = get_trust_state();
  switch(trustvalue){
	  /* 'break' statements are intentionally omitted */
	  case GPGME_VALIDITY_FULL:
			ret = ret && olsr_netlink_pol_route(r, AF_INET, wotplugin_validity2table(GPGME_VALIDITY_FULL), RTM_NEWROUTE);
	  case GPGME_VALIDITY_MARGINAL:
			ret = ret && olsr_netlink_pol_route(r, AF_INET, wotplugin_validity2table(GPGME_VALIDITY_MARGINAL), RTM_NEWROUTE);
	  default: /* GPGME_VALIDITY_UNKNOWN: */
			ret = ret && olsr_netlink_pol_route(r, AF_INET, wotplugin_validity2table(GPGME_VALIDITY_UNKNOWN), RTM_NEWROUTE);
  }
  olsr_printf(6, "[WOT] added route to routing table, now updating prefix->trust association.\n");
  pfx2trust_map_update(pfx2trustmap, &r->rt_dst, trustvalue);
  olsr_printf(6, "[WOT] association updated.\n");
  olsr_printf(9, "[WOT] addresult: %d\n", ret);
  return ret;
}

int 
wotplugin_del_policy_route(struct rt_entry *r) 
{
  gpgme_validity_t trustvalue;
  int ret = 1;
  /* Retrieve the trust value associated to the prefix */
  trustvalue = pfx2trust_map_lookup(pfx2trustmap, &r->rt_dst);
  olsr_printf(6, "Retrieved trust value: %d\n", trustvalue);
  switch(trustvalue){
	  /* 'break' statements are intentionally omitted */
	  case GPGME_VALIDITY_FULL:
			ret = ret && olsr_netlink_pol_route(r, AF_INET, wotplugin_validity2table(GPGME_VALIDITY_FULL), RTM_DELROUTE);
	  case GPGME_VALIDITY_MARGINAL:
			ret = ret && olsr_netlink_pol_route(r, AF_INET, wotplugin_validity2table(GPGME_VALIDITY_MARGINAL), RTM_DELROUTE);
	  default: /* GPGME_VALIDITY_UNKNOWN: */
			ret = ret && olsr_netlink_pol_route(r, AF_INET, wotplugin_validity2table(GPGME_VALIDITY_UNKNOWN), RTM_DELROUTE);
  }
  olsr_printf(9, "[WOT] delresult: %d\n", ret);
  return ret;
}

