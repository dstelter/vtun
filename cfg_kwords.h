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
 * $Id: cfg_kwords.h,v 1.1.1.1 2000/03/28 17:19:48 maxk Exp $
 */ 

extern int lineno;

struct kword {
   char *str;
   int  type;
}; 

struct kword cfg_keyword[] = {
   { "options",  K_OPTIONS }, 
   { "default",  K_DEFAULT },
   { "up",	 K_UP },
   { "down",	 K_DOWN },
   { "port",     K_PORT }, 
   { "srcaddr",  K_SRCADDR }, 
   { "addr",  	 K_ADDR }, 
   { "iface",  	 K_IFACE }, 
   { "persist",	 K_PERSIST }, 
   { "multi",	 K_MULTI }, 
   { "iface",    K_IFACE }, 
   { "timeout",	 K_TIMEOUT }, 
   { "passwd",   K_PASSWD }, 
   { "program",  K_PROG }, 
   { "speed",    K_SPEED }, 
   { "compress", K_COMPRESS }, 
   { "encrypt",  K_ENCRYPT }, 
   { "type",	 K_TYPE }, 
   { "proto",	 K_PROT }, 
   { "device",	 K_DEVICE }, 
   { "ppp",	 K_PPP },
   { "ifconfig", K_IFCFG },
   { "ifcfg", 	 K_IFCFG },
   { "firewall", K_FWALL }, 
   { "route", 	 K_ROUTE }, 
   { "keepalive",K_KALIVE }, 
   { "stat",	 K_STAT }, 
   { NULL , 0 }
};

struct kword cfg_param[] = {
   { "yes",      1 }, 
   { "no",       0 },
   { "allow",	 1 },
   { "deny",	 0 },
   { "enable",	 1 },
   { "disable",	 0 },
   { "tty",      VTUN_TTY }, 
   { "pipe",	 VTUN_PIPE }, 
   { "ether",	 VTUN_ETHER }, 
   { "tun",	 VTUN_TUN }, 
   { "tcp",      VTUN_TCP }, 
   { "udp",      VTUN_UDP }, 
   { "lzo",      VTUN_LZO }, 
   { "zlib",     VTUN_ZLIB }, 
   { "wait",	 1 },
   { "kill",	 VTUN_MULTI_KILL },
   { "inetd",	 VTUN_INETD },
   { "stand",	 VTUN_STAND_ALONE },
   { NULL , 0 }
};
