/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * lfd_encrypt.c,v 1.4.2.1 2002/01/14 21:51:24 noop Exp
 */

/*
   Encryption module uses software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)       
   Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 */

/*
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with 
 * several improvements and modifications by me.  
 */

/* 
 * Robert Stone <talby@trap.mtview.ca.us>
 * 2000/05/18	* Added cfb64 mode for tcp connections.  This should
 *		  significantly hinder known plaintext attacks.
 * 2000/05/24	* UDP algorithm cleanup.
 * 2000/06/04	* Now uses runtime generated session keys.  This should
 *		  greatly lessen the value of cyptanalysis on a tunnel.
 * planned	* Add a key rotation system so that there is a fixed limit
 *		  on the ammount of data encrypted under one sesion key.
 *		  (This will require a header on my layer of processing.)
 *		* Permutate ivec for tcp.  SSH doesn't bother, should we?
 *		* Add a runtime generated permutation-pad for udp mode
 *		  encryption to help address known plaintext attacks in ecb
 *		  mode.  Would this really help?  It does provide 40320
 *		  permutations on crypted text, but is that computationally
 *		  hard to unravel?
 */

/*
 * Greg Olszewski <noop@feh.nord.nwonknu.org>
 * 2000/08/28    * fixed key negotiation - added flags to vtun_host struct
 * 2000/08/29    * clients reset the ivec when reconnecting
 * 2001/05/13    * sent bf_ivec as well as session key
 * 2001/05/23    * Redid key negotiation again -- now using DH exchange;
 */
#include "config.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>


#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#ifdef HAVE_SSL

#include "vtun_dh.h"
#include <md5.h>
#include <blowfish.h>
#include <dh.h>
#include <openssl/rand.h>

#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 20
#define ENC_KEY_SIZE 16

static BF_KEY key;
static char *enc_buf = NULL;
static char *in_enc_buf = NULL;
static unsigned char bf_ivec[ENC_KEY_SIZE] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static int bf_num[2] = { 0, 0 };
static int (*crypt_buf) (int, char *, char *, int) = NULL;
extern char *title_start;
/* encryption could be stronger if the initial ivec was not
 * a constant, but this is only an issue with the first
 * packet. (first few packets?) */
/* bf_ivec is now sent after enc_key - GO 05/13/01 */
int str_crypt_buf(int len, char *ibuf, char *obuf, int enc)
{
	BF_cfb64_encrypt(ibuf, obuf, len, &key, bf_ivec + (enc << 3),
			 bf_num + enc, enc);
	return (len);
}

/* UDP packets get a header.  The first byte in the packet is the
 * length of the header.  The header pads the data out to an 8 byte
 * boundary */
int pkt_crypt_buf(int len, char *ibuf, char *obuf, int enc)
{
	char *ip = ibuf, *op = obuf;
	int i = len >> 3;
	char hdr[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	char hlen;

	memset(bf_ivec, 0, ENC_KEY_SIZE);

	if (enc == BF_ENCRYPT) {	/* build header */
		hlen = 8 - (len & 7);
		if (hlen == 0)
			hlen = 8;
		hdr[0] = hlen;
		memcpy(hdr + hlen, ip, 8 - hlen);
		BF_cbc_encrypt(hdr, op, 8, &key, bf_ivec, enc);
		op += 8;
		ip += 8 - hlen;
		len += hlen;
	} else {		/* strip header */
		BF_cbc_encrypt(ip, hdr, 8, &key, bf_ivec, enc);
		hlen = hdr[0];
		memcpy(op, hdr + hlen, 8 - hlen);
		op += 8 - hlen;
		ip += 8;
		len -= hlen;
	}
	BF_cbc_encrypt(ip, op, i, &key, bf_ivec, enc);
	return (len);
}

int encrypt_buf(int len, char *in, char **out)
{
	*out = enc_buf;
#ifdef STRONG_RANDOM
	if (!RAND_bytes(in_enc_buf, 4)) {
#else
	{
#endif
		int i;
		for (i = 0; i < 4; i++) {
			in_enc_buf[i] = rand();
		}
	}
	memcpy(in_enc_buf + 4, in, len);
	return (crypt_buf(len + 4, in_enc_buf, *out, BF_ENCRYPT));
}


int decrypt_buf(int len, char *in, char **out)
{
	int retlen;
	*out = enc_buf;

	retlen = crypt_buf(len, in, *out, BF_DECRYPT);
	*out += 4;
	return (retlen - 4);
}

static int read_bignum(int fd, BIGNUM * innum)
{
	int bytes;
	short bits;
	unsigned short netbits;
	unsigned char *buf;

	read(fd, &netbits, 2);
	bits = ntohs(netbits);
	bytes = (bits + 7) / 8;
	buf = lfd_alloc(bytes);
	if (!buf) {
		return 1;
	}
	read(fd, buf, bytes);
	BN_bin2bn(buf, bytes, innum);
	lfd_free(buf);
	return 0;
}

static int write_bignum(int fd, BIGNUM * bn)
{
	short bits = BN_num_bits(bn);
	int bytes = (bits + 7) / 8;
	int bytesto;
	unsigned short outshort;
	unsigned char *buf = lfd_alloc(bytes);
	if (!buf) {
		return 1;
	}
	bytesto = BN_bn2bin(bn, buf);
	outshort = htons(bits);
	if (bytesto != bytes) {
		lfd_free(buf);
		return 1;
	}
	write(fd, &outshort, 2);
	write(fd, buf, bytes);
	lfd_free(buf);

}

unsigned char *session_key_dh_client(struct vtun_host *host)
{
	DH *dhclient = DH_new();
	BIGNUM *spub = BN_new();
	int keysize, success;
	char *kbuf;

	dhclient->p = BN_new();
	dhclient->g = BN_new();
	dhclient->priv_key = BN_new();
	if (dhclient &&
	    spub && dhclient->p && dhclient->g && dhclient->priv_key) {
		read_bignum(host->rmt_fd, dhclient->p);
		read_bignum(host->rmt_fd, dhclient->g);
		if (BN_rand(dhclient->priv_key, 256, 0, 0)) {
			if (DH_generate_key(dhclient)) {
				write_bignum(host->rmt_fd,
					     dhclient->pub_key);
				read_bignum(host->rmt_fd, spub);
				keysize = DH_size(dhclient);
				kbuf = lfd_alloc(keysize);
				if (kbuf) {
					DH_compute_key(kbuf, spub,
						       dhclient);
					success = 1;
				}
#ifdef DEBUG_KEY
				syslog(LOG_ERR, "\np=%s",
				       BN_bn2hex(dhclient->p));
				syslog(LOG_ERR, "\ng=%s ",
				       BN_bn2hex(dhclient->g));
				syslog(LOG_ERR, "\nhis pub= %s ",
				       BN_bn2hex(spub));
				syslog(LOG_ERR, "\nmy pub= %s",
				       BN_bn2hex(dhclient->pub_key));
				syslog(LOG_ERR, "\n");
#endif
			}
		}
	}

	if (spub)
		BN_free(spub);
	if (dhclient)
		DH_free(dhclient);
	return ((success) ? kbuf : NULL);
}

unsigned char *session_key_dh_server(struct vtun_host *host)
{
	static unsigned char buf[ENC_KEY_SIZE];
	DH *dhserv = NULL;
	BIGNUM *cpub = NULL;
	int keysize;
	char *kbuf = NULL;
	int success = 0;

	dhserv = choose_dh(2048);
	cpub = BN_new();

	if (!dhserv) {
		return NULL;
	}

	write_bignum(host->rmt_fd, dhserv->p);
	write_bignum(host->rmt_fd, dhserv->g);
	dhserv->priv_key = BN_new();
	if (dhserv->priv_key) {
		if (BN_rand(dhserv->priv_key, 256, 0, 0)) {
			if (DH_generate_key(dhserv)) {
				if (cpub) {
					read_bignum(host->rmt_fd, cpub);
					write_bignum(host->rmt_fd,
						     dhserv->pub_key);
					keysize = DH_size(dhserv);
					kbuf = lfd_alloc(keysize);
					if (kbuf) {
						DH_compute_key(kbuf, cpub,
							       dhserv);
						success = 1;
					}
				}
			}
		}
	}
#ifdef DEBUG_KEY
	syslog(LOG_ERR, "\np=%s", BN_bn2hex(dhserv->p));
	syslog(LOG_ERR, "\ng=%s ", BN_bn2hex(dhserv->g));
	syslog(LOG_ERR, "\nhis pub= %s ", BN_bn2hex(cpub));
	syslog(LOG_ERR, "\nmy pub= %s", BN_bn2hex(dhserv->pub_key));
	syslog(LOG_ERR, "\n");
#endif
	DH_free(dhserv);
	BN_free(cpub);
	return ((success) ? kbuf : NULL);
}



unsigned char *session_key(struct vtun_host *host)
{
	static unsigned char buf[ENC_KEY_SIZE];
	char *keyret;
	if (host->more_flags & VTUN_IM_CLIENT) {
		keyret = session_key_dh_client(host);
	} else {
		keyret = session_key_dh_server(host);
	}
	if (!keyret)
		return keyret;
	memcpy(buf, keyret, ENC_KEY_SIZE);
	memset(keyret, 0, ENC_KEY_SIZE);
	lfd_free(keyret);
	return buf;
}

void get_new_key(struct vtun_host *host)
{
	unsigned char *newkey;
	newkey = session_key(host);
	if (newkey) {
		BF_set_key(&key, ENC_KEY_SIZE, newkey);
		memset(bf_num, 0, 2 * (sizeof(*bf_num)));
		memset(bf_ivec, 0, ENC_KEY_SIZE);
		host->more_flags &= ~VTUN_GET_KEY;
	} else {
		syslog(LOG_WARNING, "Couldn't renegotiate key");
	}
}

int alloc_encrypt(struct vtun_host *host)
{
	char *mode;
	char *skey;
	if (host->more_flags & VTUN_GET_KEY) {
		get_new_key(host);
		return 0;
	}
	if ((enc_buf = (char *) lfd_alloc(ENC_BUF_SIZE)) == NULL) {
		syslog(LOG_ERR, "Unable to allocate encryption buffer");
		return -1;
	}
	if ((in_enc_buf = (char *) lfd_alloc(ENC_BUF_SIZE)) == NULL) {
		syslog(LOG_ERR, "Unable to allocate encryption buffer");
		lfd_free(enc_buf);
		enc_buf = NULL;
		return -1;
	}
	skey = session_key(host);
	if (!skey) {
		syslog(LOG_ERR, "Unable to negotiate inital key");
		return -1;
	}

	BF_set_key(&key, ENC_KEY_SIZE, skey);
	memset(bf_ivec, 0, ENC_KEY_SIZE);
	memset(bf_num, 0, 2 * (sizeof(*bf_num)));
	if (host->flags & VTUN_TCP) {
		crypt_buf = str_crypt_buf;
		mode = "cfb64";
	} else {
		crypt_buf = pkt_crypt_buf;
		mode = "ecb";
	}
	syslog(LOG_INFO, "blowfish/%s encryption initialized", mode);
	return 0;
}

int free_encrypt()
{
	if (enc_buf) {
		lfd_free(enc_buf);
		enc_buf = NULL;
	}
	if (in_enc_buf) {
		lfd_free(in_enc_buf);
		in_enc_buf = NULL;
	}
	return 0;
}

/* 
 * Module structure.
 */
struct lfd_mod lfd_encrypt = {
	"Encryptor",
	alloc_encrypt,
	encrypt_buf,
	NULL,
	decrypt_buf,
	NULL,
	free_encrypt,
	NULL,
	NULL
};

#else				/* HAVE_SSL */

int no_encrypt(struct vtun_host *host)
{
	syslog(LOG_INFO, "Encryption is not supported");
	return -1;
}

struct lfd_mod lfd_encrypt = {
	"Encryptor",
	no_encrypt, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif				/* HAVE_SSL */
