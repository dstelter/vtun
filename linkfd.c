/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998,1999  Maxim Krasnyansky <max_mk@yahoo.com>

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
 * Version: 2.0 12/30/1999 Maxim Krasnyansky <max_mk@yahoo.com>
 */

#include "config.h"
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <syslog.h>
#include <time.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

/* Host we are working with. 
 * Used by signal handlers that's why it is global. 
 */
struct vtun_host *lfd_host;

extern int errno;

struct lfd_mod *lfd_mod_head = NULL, *lfd_mod_tail = NULL;

/* Modules functions*/

/* Add module to the end of modules list */
void lfd_add_mod(struct lfd_mod *mod)
{
     if( !lfd_mod_head ){
        lfd_mod_head = lfd_mod_tail = mod;
	mod->next = mod->prev = NULL;
     } else {
        lfd_mod_tail->next = mod;
        mod->prev = lfd_mod_tail;
        mod->next = NULL;
        lfd_mod_tail = mod;
     }
}

/*  Initialize and allocate each module */
int lfd_alloc_mod(struct vtun_host *host)
{
     struct lfd_mod *mod = lfd_mod_head;

     while( mod ){
        if( mod->alloc && (mod->alloc)(host) )
	   return 1; 
	mod = mod->next;
     } 

     return 0;
}

/* Free all modules */
int lfd_free_mod(void)
{
     struct lfd_mod *mod = lfd_mod_head;

     while( mod ){
        if( mod->free && (mod->free)() )
	   return 1;
	mod = mod->next;
     } 
     lfd_mod_head = lfd_mod_tail = NULL;
     return 0;
}

 /* Run modules down (from head to tail) */
inline int lfd_run_down(int len, char *in, char **out)
{
     struct lfd_mod *mod = lfd_mod_head;
     
     *out = in;
     if( mod ) {
        for( ; mod && len > 0; mod = mod->next )
            if( mod->encode ){
               len = (mod->encode)(len,in,out);
               in = *out;
            }
     }
     return len;
}

/* Run modules up (from tail to head) */
inline int lfd_run_up(int len, char *in, char **out)
{
     struct lfd_mod *mod = lfd_mod_tail;
     
     *out = in;
     if( mod ) {
        for( ; mod && len > 0; mod = mod->prev )
	    if( mod->decode ){
	       len = (mod->decode)(len,in,out);
               in = *out;
	    }
     }
     return len;
}

/* Check if modules are accepting the data(down) */
inline int lfd_check_down(void)
{
     struct lfd_mod *mod = lfd_mod_head;
     int err = 1;	    
 
     if( mod ){
	for( ; mod && err > 0; mod = mod->next )
           if( mod->avail_encode )
              err = (mod->avail_encode)();
     }
	
     return err;
}

/* Check if modules are accepting the data(up) */
inline int lfd_check_up(void)
{
     struct lfd_mod *mod = lfd_mod_tail;
     int err = 1;	    

     if( mod ){
        for( ; mod && err > 0; mod = mod->prev)
           if( mod->avail_decode )
              err = (mod->avail_decode)();
     }

     return err;
}
/* Functions to read/write frames. */

int write_frame_udp(int fd, char *buf, int len)
{
     unsigned short nlen, cnt; 
     struct iovec iv[2];

     nlen = htons(len); 
     len  = len & VTUN_FSIZE_MASK;

     iv[0].iov_len  = sizeof(short); 
     iv[0].iov_base = (char *) &nlen; 
     if( buf ) {
        iv[1].iov_len  = len; 
        iv[1].iov_base = buf;
	cnt = 2;
     } else {
        /* Write flags only */
	cnt = 1;
     }

     while(1) {
        register int err;
	err = writev(fd, iv, cnt); 
	if( err < 0 && ( errno == EAGAIN || errno == EINTR ) )
	   continue;
	/* Even if we wrote only part of the frame
         * we can't use second write since it will produce 
         * another UDP frame */  
        return err;
     }
}

int read_frame_udp(int fd, char *buf)
{
     unsigned short len, flen, cnt;
     struct iovec iv[2];

     /* Get frame size */
     while(1) {
	register int err;     
        if( (err = recv(fd, &len, sizeof(short), MSG_PEEK)) > 0)
	   break;
	if( err < 0 && ( errno == EAGAIN || errno == EINTR ) )
	   continue;
	return err;
     }

     len = ntohs(len);
     flen = len & VTUN_FSIZE_MASK;

     if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ) {
     	/* Oversized frame, drop it.  
	 * On UDP socket read will drop remaining part of the frame */
        read(fd, buf, VTUN_FRAME_SIZE);
	return VTUN_BAD_FRAME;
     }	

     /* Read frame */
     iv[0].iov_len  = sizeof(short);
     iv[0].iov_base = (char *) &flen;
     if( len & ~VTUN_FSIZE_MASK ) {
	/* Read flags only */
	cnt = 1;
     } else {	
        iv[1].iov_len  = flen;
        iv[1].iov_base = buf;
	cnt = 2;
     }

     while(1) {
	register int err;     
	errno = 0;
        if( (err = readv(fd, iv, cnt)) > 0) 
	   return len;
	if( err < 0 && ( errno == EAGAIN || errno == EINTR ) )
	   continue;
	return err;
     }
}		

int write_frame_tcp(int fd, char *buf, int len)
{
     unsigned short nlen, cnt; 
     struct iovec iv[2];

     nlen = htons(len); 
     len  = len & VTUN_FSIZE_MASK;

     iv[0].iov_len  = sizeof(short); 
     iv[0].iov_base = (char *) &nlen; 
     if( buf ) {
        iv[1].iov_len  = len; 
        iv[1].iov_base = buf;
	cnt = 2;
     } else {
        /* Write flags only */
	cnt = 1;
     }

     while(1) {
        register int err;
	err = writev(fd, iv, cnt); 
	if( err < 0 && ( errno == EAGAIN || errno == EINTR ) )
	   continue;
	if( err > 0 && err < (len + sizeof(short)) ) {
	   /* We wrote only part of the frame, lets write the rest
	    * FIXME should check if wrote less than sizeof(short) */
	   err -= sizeof(short);
	   return write_n(fd, buf + err, len - err);
	}

	return err;
     }
}

int read_frame_tcp(int fd, char *buf)
{
     unsigned short len, flen;
     register int err;     

     /* Read frame size */
     if( (err = read_n(fd, &len, sizeof(short)) ) < 0)
	return err;

     len = ntohs(len);
     flen = len & VTUN_FSIZE_MASK;

     if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ) {
     	/* Oversized frame, drop it. */ 
        while(flen) {
	   len = min(flen, VTUN_FRAME_SIZE);
           if( (len = read_n(fd, buf, len)) <= 0 )
	      return VTUN_BAD_FRAME;
           flen -= len;
        }                                                               
	return VTUN_BAD_FRAME;
     }	

     if( len & ~VTUN_FSIZE_MASK ) {
	/* Return flags */
	return len;
     }

     /* Read frame */
     return read_n(fd, buf, flen);
}		

int (*write_frame)(int fd, char *buf, int len);
int (*read_frame)(int fd, char *buf);

/********** Linker *************/

/* Termination flag */
static int linker_term;

static void sig_term(int sig)
{
     syslog(LOG_INFO,"Closing connection");
     linker_term = 1;
}

/* Statistic dump */
void sig_alarm(int sig)
{
     static time_t tm;
     static char stm[20];
  
     tm = time(NULL);
     strftime(stm, sizeof(stm)-1, "%b %d %H:%M:%S", localtime(&tm)); 
     fprintf(lfd_host->stat.file,"%s %lu %lu %lu %lu\n", stm, 
	lfd_host->stat.byte_in, lfd_host->stat.byte_out,
	lfd_host->stat.comp_in, lfd_host->stat.comp_out); 
     
     alarm(VTUN_STAT_IVAL);
}    

static void sig_usr1(int sig)
{
     /* Reset statistic counters on SIGUSR1 */
     lfd_host->stat.byte_in = lfd_host->stat.byte_out = 0;
     lfd_host->stat.comp_in = lfd_host->stat.comp_out = 0; 
}

int lfd_linker(void)
{
     int fd1 = lfd_host->rmt_fd;
     int fd2 = lfd_host->loc_fd; 
     register int len, fl;
     struct timeval tv;
     char *buf, *out;
     fd_set fdset;
     int maxfd, idle = 0;

     if( !(buf = malloc(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD)) ){
	syslog(LOG_ERR,"Can't allocate buffer for the linker"); 
        return 1; 
     }

     maxfd = (fd1 > fd2 ? fd1 : fd2) + 1;

     linker_term = 0;
     while( !linker_term ){
	errno = 0;

        /* Wait for data */
        FD_ZERO(&fdset);
	FD_SET(fd1, &fdset);
	FD_SET(fd2, &fdset);
 	tv.tv_sec = 30; tv.tv_usec = 0;

	if( (len = select(maxfd, &fdset, NULL, NULL, &tv)) < 0 ){
	   if( errno != EAGAIN && errno != EINTR )
	      break;
	   else
	      continue;
	} 
	
	if( !len ){
	   /* We are idle, lets check connection */
	   if( lfd_host->flags & VTUN_KEEP_ALIVE ){
	      write_frame(fd1, NULL, VTUN_ECHO_REQ);
	      if( ++idle > 3 ){
	         syslog(LOG_INFO,"Session %s network timeout", lfd_host->host);
		 break;	
	      }
	   }
	   continue;
	}	   

	/* Read frames from network(fd1), decode and pass them to 
         * the local program (fd2) */
	if( FD_ISSET(fd1, &fdset) && lfd_check_up() ){
	   idle = 0; 
	   if( (len=read_frame(fd1,buf)) <= 0 )
	      break;

	   /* Handle frame flags */
	   fl = len & ~VTUN_FSIZE_MASK;
           len = len & VTUN_FSIZE_MASK;
	   if( fl ){
	      if( fl==VTUN_BAD_FRAME ){
		 syslog(LOG_ERR, "Received bad frame");
		 continue;
	      }
	      if( fl==VTUN_ECHO_REQ ){
		 /* Reply on echo request */
	 	 write_frame(fd1, NULL, VTUN_ECHO_REP);
		 continue;
	      }
   	      if( fl==VTUN_ECHO_REP ){
		 /* Just ignore echo reply */
		 continue;
	      }
	      if( fl==VTUN_CONN_CLOSE ){
	         syslog(LOG_INFO,"Connection closed by other side");
		 break;
	      }
	   }   

	   lfd_host->stat.comp_in += len; 
	   if( (len=lfd_run_up(len,buf,&out)) == -1 )
	      break;	
	   if( len && write_n(fd2,out,len) < 0 )
	      break; 
	   lfd_host->stat.byte_in += len; 
	}

	/* Read data from the local program(fd2), encode and pass it to 
         * the network (fd1) */
	if( FD_ISSET(fd2, &fdset) && lfd_check_down() ){
	   if( (len=read(fd2, buf, VTUN_FRAME_SIZE)) < 0 ){
	      if( errno != EAGAIN && errno != EINTR )
	         break;
	      else
		 continue;
	   }
	   if( !len ) break;
	
	   lfd_host->stat.byte_out += len; 
	   if( (len=lfd_run_down(len,buf,&out)) == -1 )
	      break;
	   if( len && write_frame(fd1, out, len) < 0 )
	      break;
	   lfd_host->stat.comp_out += len; 
	}
     }
     if( !linker_term && errno )
	syslog(LOG_INFO,"%s (%d)", strerror(errno), errno);
	
     /* Notify other end about our close */
     write_frame(fd1, NULL, VTUN_CONN_CLOSE);
     free(buf);

     return 0;
}

/* Link remote and local file descriptors */ 
int linkfd(struct vtun_host *host)
{
     struct sigaction sa, sat;
     int old_prio;

     lfd_host = host;
 
     old_prio=getpriority(PRIO_PROCESS,0);
     setpriority(PRIO_PROCESS,0,LINKFD_PRIO);

     /* Build modules stack */
     if(host->flags & VTUN_ZLIB)
	lfd_add_mod(&lfd_zlib);

     if(host->flags & VTUN_LZO)
	lfd_add_mod(&lfd_lzo);

     if(host->flags & VTUN_ENCRYPT)
	lfd_add_mod(&lfd_encrypt);

     if(host->flags & VTUN_SHAPE)
	lfd_add_mod(&lfd_shaper);

     if(lfd_alloc_mod(host))
	return -1;

     /* Initialize read/write frame functions */
     if( host->flags & VTUN_TCP ) {
	write_frame = write_frame_tcp;
	read_frame = read_frame_tcp;
     } else {	
 	write_frame = write_frame_udp;
	read_frame = read_frame_udp;
     }

     memset(&sa, 0, sizeof(sa));
     sa.sa_handler=sig_term;
     sigaction(SIGTERM,&sa,&sat);

     /* Initialize statstic dumps */
     if( host->flags & VTUN_STAT ){
	char file[40];

        sa.sa_handler=sig_alarm;
        sigaction(SIGALRM,&sa,NULL);
        sa.sa_handler=sig_usr1;
        sigaction(SIGUSR1,&sa,NULL);

	sprintf(file,"%s/%.20s", VTUN_STAT_DIR, host->host);
	if( (host->stat.file=fopen(file, "a")) ){
	   setvbuf(host->stat.file, NULL, _IOLBF, 0);
	   alarm(VTUN_STAT_IVAL);
	} else
	   syslog(LOG_ERR, "Can't open stats file %s", file);
     }

     lfd_linker();

     if( host->flags & VTUN_STAT ){
        alarm(0);
	fclose(host->stat.file);
     }

     lfd_free_mod();
     
     sigaction(SIGTERM,&sat,NULL);

     setpriority(PRIO_PROCESS,0,old_prio);

     return linker_term;
}
