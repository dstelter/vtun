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
 * lfd_encrypt.c,v 1.2.2.6 2002/04/25 09:19:50 bergolth Exp
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

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

#ifdef HAVE_SSL

#ifndef __APPLE_CC__
/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#else /* YAY - We're MAC OS */
#include <sys/md5.h>
#include <crypto/blowfish.h>
#endif  /* __APPLE_CC__ */

/*
#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 16 
*/
#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 128 
#define ENC_KEY_SIZE 16

BF_KEY key;
char * enc_buf;
char * dec_buf;

#define CIPHER_INIT	0
#define CIPHER_CODE	1	

struct vtun_host *phost;

int cipher_enc_state;
int cipher_dec_state;
int cipher;
int blocksize;
char * iv_buf;

EVP_CIPHER_CTX ctx_enc;	/* encrypt */
EVP_CIPHER_CTX ctx_dec;	/* decrypt */

EVP_CIPHER_CTX ctx_enc_ecb;	/* sideband ecb encrypt */
EVP_CIPHER_CTX ctx_dec_ecb;	/* sideband ecb decrypt */

int alloc_encrypt(struct vtun_host *host)
{
   if( !(enc_buf = lfd_alloc(ENC_BUF_SIZE)) ){
      vtun_syslog(LOG_ERR,"Can't allocate buffer for encryptor");
      return -1;
   }
   if( !(dec_buf = lfd_alloc(ENC_BUF_SIZE)) ){
      vtun_syslog(LOG_ERR,"Can't allocate buffer for decryptor");
      return -1;
   }

   EVP_CIPHER_CTX_init(&ctx_enc);
   EVP_CIPHER_CTX_init(&ctx_dec);

   phost = host;
   cipher = host->cipher;
   switch(cipher)
   {
      case VTUN_ENC_AES128OFB:
      case VTUN_ENC_AES128CFB:
      case VTUN_ENC_AES128CBC:
         blocksize = 16;
         EVP_CIPHER_CTX_init(&ctx_enc_ecb);
         EVP_CIPHER_CTX_init(&ctx_dec_ecb);
         EVP_EncryptInit_ex(&ctx_enc_ecb, EVP_aes_128_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL),NULL);
         EVP_DecryptInit_ex(&ctx_dec_ecb, EVP_aes_128_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL), NULL);
         EVP_CIPHER_CTX_set_padding(&ctx_enc_ecb, 0);
         EVP_CIPHER_CTX_set_padding(&ctx_dec_ecb, 0);
         cipher_enc_state=CIPHER_INIT;
         cipher_dec_state=CIPHER_INIT;
      break;
      case VTUN_ENC_AES128ECB:
         blocksize = 16;
         EVP_EncryptInit_ex(&ctx_enc, EVP_aes_128_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL),NULL);
         EVP_DecryptInit_ex(&ctx_dec, EVP_aes_128_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL), NULL);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         cipher_enc_state=CIPHER_CODE;
         cipher_dec_state=CIPHER_CODE;
         vtun_syslog(LOG_INFO, "AES-128-ECB encryption initialized");
      break;
      case VTUN_ENC_BF128OFB:
      case VTUN_ENC_BF128CFB:
      case VTUN_ENC_BF128CBC:
         blocksize = 8;
         EVP_CIPHER_CTX_init(&ctx_enc_ecb);
         EVP_CIPHER_CTX_init(&ctx_dec_ecb);
         EVP_EncryptInit_ex(&ctx_enc_ecb, EVP_bf_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL), NULL);
         EVP_DecryptInit_ex(&ctx_dec_ecb, EVP_bf_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL), NULL);
         EVP_CIPHER_CTX_set_padding(&ctx_enc_ecb, 0);
         EVP_CIPHER_CTX_set_padding(&ctx_dec_ecb, 0);
         cipher_enc_state=CIPHER_INIT;
         cipher_dec_state=CIPHER_INIT;
      break;
      case VTUN_ENC_BF128ECB: /* blowfish 128 ecb is the default */
      default:
         blocksize = 8;
         EVP_EncryptInit_ex(&ctx_enc, EVP_bf_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL), NULL);
         EVP_DecryptInit_ex(&ctx_dec, EVP_bf_ecb(), NULL,
            MD5(host->passwd,strlen(host->passwd), NULL), NULL);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         cipher_enc_state=CIPHER_CODE;
         cipher_dec_state=CIPHER_CODE;
         vtun_syslog(LOG_INFO, "Blowfish-128-ECB encryption initialized");
      break;
   } /* switch(host->cipher) */


   return 0;
}

int free_encrypt()
{
   lfd_free(enc_buf); enc_buf = NULL;
   lfd_free(dec_buf); dec_buf = NULL;

   EVP_CIPHER_CTX_cleanup(&ctx_enc);
   EVP_CIPHER_CTX_cleanup(&ctx_dec);

   return 0;
}

int encrypt_buf(int len, char *in, char **out)
{ 
   register int pad, p, msg_len;
   int outlen;
   register char *in_ptr, *out_ptr = enc_buf;

   msg_len = send_msg(len, in, out);
   in = *out;
   in_ptr = in+msg_len;
   memcpy(out_ptr,in,msg_len);
   out_ptr += msg_len;
   
   /* ( len % blocksize ) */
   p = (len & (blocksize-1)); pad = blocksize - p;
   
   memset(in_ptr+len, pad, pad);
   outlen=len+pad;
   if (pad == blocksize)
      RAND_bytes(in_ptr+len, blocksize-1);
   EVP_EncryptUpdate(&ctx_enc, out_ptr, &outlen, in_ptr, len+pad);
   *out = enc_buf;
   return outlen+msg_len;
}

int decrypt_buf(int len, char *in, char **out)
{
   register int pad;
   register char *in_ptr, *out_ptr = dec_buf;
   int outlen;

   len = recv_msg(len, in, out);
   in = *out;
   in_ptr = in;

   outlen=len;
   EVP_DecryptUpdate(&ctx_dec, out_ptr, &outlen, in_ptr, len);
   out_ptr += outlen-1;
   pad = *out_ptr;
   if (pad < 1 || pad > blocksize) {
      vtun_syslog(LOG_INFO, "decrypt_buf: bad pad length");
      return 0;
   }
   *out = dec_buf;
   return outlen - pad;
}

int cipher_enc_init(char * iv)
{
   switch(cipher)
   {
      case VTUN_ENC_AES128OFB:
         EVP_EncryptInit_ex(&ctx_enc, EVP_aes_128_ofb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL),iv);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         vtun_syslog(LOG_INFO, "AES-128-OFB encryption initialized");
      break;
      case VTUN_ENC_AES128CFB:
         EVP_EncryptInit_ex(&ctx_enc, EVP_aes_128_cfb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL),iv);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         vtun_syslog(LOG_INFO, "AES-128-CFB encryption initialized");
      break;
      case VTUN_ENC_AES128CBC:
         EVP_EncryptInit_ex(&ctx_enc, EVP_aes_128_cbc(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL),iv);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         vtun_syslog(LOG_INFO, "AES-128-CBC encryption initialized");
      break;
      case VTUN_ENC_BF128OFB:
         EVP_EncryptInit_ex(&ctx_enc, EVP_bf_ofb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL),iv);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         vtun_syslog(LOG_INFO, "Blowfish-128-OFB encryption initialized");
      break;
      case VTUN_ENC_BF128CFB:
         EVP_EncryptInit_ex(&ctx_enc, EVP_bf_cfb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL),iv);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         vtun_syslog(LOG_INFO, "Blowfish-128-CFB encryption initialized");
      break;
      case VTUN_ENC_BF128CBC:
         EVP_EncryptInit_ex(&ctx_enc, EVP_bf_cbc(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL),iv);
         EVP_CIPHER_CTX_set_padding(&ctx_enc, 0);
         vtun_syslog(LOG_INFO, "Blowfish-128-CBC encryption initialized");
      break;
   } /* switch(cipher) */
   return 0;
}

int cipher_dec_init(char * iv)
{
   switch(cipher)
   {
      case VTUN_ENC_AES128OFB:
         EVP_DecryptInit_ex(&ctx_dec, EVP_aes_128_ofb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL), iv);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         vtun_syslog(LOG_INFO, "AES-128-OFB decryption initialized");
      break;
      case VTUN_ENC_AES128CFB:
         EVP_DecryptInit_ex(&ctx_dec, EVP_aes_128_cfb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL), iv);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         vtun_syslog(LOG_INFO, "AES-128-CFB decryption initialized");
      break;
      case VTUN_ENC_AES128CBC:
         EVP_DecryptInit_ex(&ctx_dec, EVP_aes_128_cbc(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL), iv);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         vtun_syslog(LOG_INFO, "AES-128-CBC decryption initialized");
      break;
      case VTUN_ENC_BF128OFB:
         EVP_DecryptInit_ex(&ctx_dec, EVP_bf_ofb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL), iv);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         vtun_syslog(LOG_INFO, "Blowfish-128-OFB decryption initialized");
      break;
      case VTUN_ENC_BF128CFB:
         EVP_DecryptInit_ex(&ctx_dec, EVP_bf_cfb(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL), iv);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         vtun_syslog(LOG_INFO, "Blowfish-128-CFB decryption initialized");
      break;
      case VTUN_ENC_BF128CBC:
         EVP_DecryptInit_ex(&ctx_dec, EVP_bf_cbc(), NULL,
            MD5(phost->passwd,strlen(phost->passwd), NULL), iv);
         EVP_CIPHER_CTX_set_padding(&ctx_dec, 0);
         vtun_syslog(LOG_INFO, "Blowfish-128-CBC decryption initialized");
      break;
   } /* switch(cipher) */
   return 0;
}

int send_msg(int len, char *in, char **out)
{
   char * iv; char * in_ptr;
   int outlen;

   switch(cipher_enc_state)
   {
      case CIPHER_INIT:
         in_ptr = in - blocksize*2;
         iv = malloc(blocksize);
         RAND_bytes(iv, blocksize);
         strncpy(in_ptr,"ivec",4);
         in_ptr += 4;
         memcpy(in_ptr,iv,blocksize);
         in_ptr += blocksize;
         cipher_enc_init(iv);

         memset(iv,0,blocksize); free(iv); iv = NULL;
         RAND_bytes(in_ptr, in - in_ptr);

         in_ptr = in - blocksize*2;
         outlen = blocksize*2;
         EVP_EncryptUpdate(&ctx_enc_ecb, in_ptr, 
            &outlen, in_ptr, blocksize*2);
         *out = in_ptr;
         len = outlen;
         cipher_enc_state = CIPHER_CODE;
      break;

      case CIPHER_CODE:
      default:
         *out = in;
         len = 0;
      break;
   }
   return len;
}

int recv_msg(int len, char *in, char **out)
{
   char * iv; char * in_ptr;
   int outlen;

   switch(cipher_dec_state)
   {
      case CIPHER_INIT:
         in_ptr = in;
         iv = malloc(blocksize);
         outlen = blocksize*2;
         EVP_DecryptUpdate(&ctx_dec_ecb, in_ptr, &outlen, in_ptr, blocksize*2);
         
         if ( !strncmp(in_ptr, "ivec", 4) )
         {
            memcpy(iv, in_ptr+4, blocksize);
            cipher_dec_init(iv);

            *out = in_ptr + blocksize*2;
            len -= blocksize*2;
            cipher_dec_state = CIPHER_CODE;
         } 
         else 
         {
            len = 0;
            *out = in;
         }
         memset(iv,0,blocksize); free(iv); iv = NULL;
         memset(in_ptr,0,blocksize*2);         
      break;

      case CIPHER_CODE:
      default:
         *out = in;
      break;
   }
   return len;
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

#else  /* HAVE_SSL */

int no_encrypt(struct vtun_host *host)
{
     vtun_syslog(LOG_INFO, "Encryption is not supported");
     return -1;
}

struct lfd_mod lfd_encrypt = {
     "Encryptor",
     no_encrypt, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif /* HAVE_SSL */
