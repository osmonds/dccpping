/******************************************************************************
Author: Samuel Jero <sj323707@ohio.edu>

Date: 10/2012

Description: IPv4 and IPv6 Checksum code
******************************************************************************/
#include <string.h>
#include <arpa/inet.h>
#include "checksums.h"

/*Stupid Solaris*/
#ifndef u_int32_t
#define u_int32_t uint32_t
#endif
#ifndef u_int16_t
#define u_int16_t uint16_t
#endif

//Pseudo Headers for checksums
struct ip6_pseudo_hdr{
	unsigned char src[IP6_ADDR_LEN];
	unsigned char dest[IP6_ADDR_LEN];
	unsigned int len;
	unsigned char zero[3];
	unsigned char nxt;
};
struct ip4_pseudo_hdr{
	unsigned char src[IP4_ADDR_LEN];
	unsigned char dest[IP4_ADDR_LEN];
	unsigned int len;
	unsigned char zero[3];
	unsigned char nxt;
};

/*From http://gitorious.org/freebsd/freebsd/blobs/HEAD/sbin/dhclient/packet.c
 * under GNU GPL*/
u_int32_t checksum(unsigned char *buf, unsigned nbytes, u_int32_t sum)
{
	int i;
	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (nbytes & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(buf + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < nbytes) {
		sum += buf[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return (sum);
}

/*From http://gitorious.org/freebsd/freebsd/blobs/HEAD/sbin/dhclient/packet.c
 * under GNU GPL*/
u_int32_t wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

u_int16_t ipv6_pseudohdr_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type){
	struct ip6_pseudo_hdr hdr;

	//create pseudo header
	memset(&hdr, 0, sizeof(struct ip6_pseudo_hdr));
	memcpy(hdr.src, src, IP6_ADDR_LEN);
	memcpy(hdr.dest, dest, IP6_ADDR_LEN);
	hdr.nxt=type;
	hdr.len=htonl(len);

	//calculate total checksum
	return wrapsum(checksum((unsigned char*)&hdr,sizeof(struct ip6_pseudo_hdr),checksum(buff,len,0)));
}

u_int16_t ipv4_pseudohdr_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type){
	struct ip4_pseudo_hdr hdr;

	//create pseudo header
	memset(&hdr, 0, sizeof(struct ip4_pseudo_hdr));
	memcpy(hdr.src, src, IP4_ADDR_LEN);
	memcpy(hdr.dest, dest, IP4_ADDR_LEN);
	hdr.nxt=type;
	hdr.len=htonl(len);

	//calculate total checksum
	return wrapsum(checksum((unsigned char*)&hdr,sizeof(struct ip4_pseudo_hdr),checksum(buff,len,0)));
}

u_int16_t ipv4_chksum(unsigned char* buff, int len){
	return wrapsum(checksum(buff,len,0));
}
