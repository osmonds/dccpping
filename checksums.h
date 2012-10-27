/******************************************************************************
Author: Samuel Jero <sj323707@ohio.edu>

Date: 10/2012

Description: IPv4 and IPv6 Checksum code
******************************************************************************/
#ifndef CHECKUMS_H
#define CHECKSUMS_H

#include <ctype.h>
#include <sys/types.h>

#define IP4_ADDR_LEN 	4
#define IP6_ADDR_LEN 	16

u_int16_t ipv6_pseudohdr_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type);
u_int16_t ipv4_pseudohdr_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type);
u_int16_t ipv4_chksum(unsigned char* buff, int len);


#endif
