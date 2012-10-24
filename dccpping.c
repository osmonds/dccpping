/******************************************************************************
Author: Samuel Jero <sj323707@ohio.edu>

Date: 10/2012

Description: Program to ping hosts using DCCP REQ packets to test for DCCP connectivity.
******************************************************************************/
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <ctype.h>
#include <linux/dccp.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>

extern int errno;


//Pseudo Header for checksums
#define IP4_ADDR_LEN 	4
struct ip4_pseudo_hdr{
	unsigned char src[IP4_ADDR_LEN];
	unsigned char dest[IP4_ADDR_LEN];
	unsigned int len;
	unsigned char zero[3];
	unsigned char nxt;
};
#define IP6_ADDR_LEN 	16
struct ip6_pseudo_hdr{
	unsigned char src[IP6_ADDR_LEN];
	unsigned char dest[IP6_ADDR_LEN];
	unsigned int len;
	unsigned char zero[3];
	unsigned char nxt;
};


int debug=0;		/*set to 1 to turn on debugging information*/
int count=-1;
int dest_port=33434;
int ttl=64;
long interval=1000;
int ip_type=AF_UNSPEC;
socklen_t addrlen;
struct sockaddr *dest_addr;
struct sockaddr *src_addr;


void doping();
int ip6_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type, unsigned short* chksum);
int ip4_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type, unsigned short* chksum);
u_int32_t checksum(unsigned char *buf, unsigned nbytes, u_int32_t sum);
u_int32_t wrapsum(u_int32_t sum);
void dbgprintf(int level, const char *fmt, ...);
void sanitize_environment();
void usage();


/*Parse commandline options*/
int main(int argc, char *argv[])
{
	char c;
	char *src=NULL;
	char *dst=NULL;
	int err;
	struct addrinfo hint;
	struct addrinfo *dtmp, *stmp;
	struct ifaddrs *temp, *cur;
	struct sockaddr_in6* iv6;
	struct sockaddr_in6 lv6;
	struct sockaddr_in lv4;
	struct sockaddr_in* iv4;

	sanitize_environment();

	while ((c = getopt(argc, argv, "64c:p:i:dt:S:")) != -1) {
		switch (c) {
			case '6':
				ip_type=AF_INET6;
				break;
			case '4':
				ip_type=AF_INET;
				break;
			case 'c':
				count = atoi(optarg);
				if(count<=0){
					dbgprintf(0, "Error: count must be positive");
					exit(1);
				}
				break;
			case 'p':
				dest_port = atoi(optarg);
				break;
			case 'i':
				interval = (long)(atof(optarg) * 1000.0);
				if (interval <= 0) {
					fprintf(stderr, "Invalid interval\n");
					exit(1);
				}
				break;
			case 'd':
				debug++;
				break;
			case 't':
				ttl = atoi(optarg);
				if (ttl < 1 || ttl > 255) {
					fprintf(stderr, "Invalid TTL\n");
				}
				break;
			case 'S':
				src=optarg;
				//r = inet_aton(optarg, &src_ip);
				break;
			default:
				usage();
				break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
	}
	dst=argv[0];

	/*Lookup destination Address*/
	memset(&hint,0,sizeof(struct addrinfo));
	hint.ai_family=ip_type;
	hint.ai_flags=AI_V4MAPPED | AI_ADDRCONFIG;

	if((err=getaddrinfo(dst,NULL,&hint,&dtmp))!=0){
		dbgprintf(0,"Error: Couldn't lookup destination %s (%s)\n", dst, gai_strerror(err));
		exit(1);
	}
	if(dtmp==NULL){
		dbgprintf(0,"Error: Unknown Host %s\n", dst);
		exit(1);
	}else{
		hint.ai_family=ip_type=dtmp->ai_family;
		addrlen=dtmp->ai_addrlen;
		dest_addr=malloc(dtmp->ai_addrlen);
		if(dest_addr==NULL){
			dbgprintf(0,"Error: Can't allocate Memory\n");
			exit(1);
		}
		memcpy(dest_addr,dtmp->ai_addr,dtmp->ai_addrlen);
	}
	freeaddrinfo(dtmp);

	/*Get a meaningful source address*/
	if(src!=NULL){
		/*Use Commandline arg*/
		if((err=getaddrinfo(src,NULL,&hint,&stmp))!=0){
			dbgprintf(0,"Error: Source Address %s is invalid (%s)\n", src, gai_strerror(err));
			exit(1);
		}
		if(stmp==NULL){
			dbgprintf(0,"Error: Unknown Host %s\n", dst);
			exit(1);
		}else{
			src_addr=malloc(stmp->ai_addrlen);
			if(src_addr==NULL){
				dbgprintf(0,"Error: Can't allocate Memory\n");
				exit(1);
			}
			memcpy(src_addr,stmp->ai_addr,stmp->ai_addrlen);
		}
		freeaddrinfo(stmp);
	}else{
		/*Guess a good source address*/
		inet_pton(AF_INET6,"::1",&lv6);
		inet_pton(AF_INET,"127.0.0.1",&lv4);
		getifaddrs(&temp);
		cur=temp;
		while(cur!=NULL){
			if((cur->ifa_flags & IFF_BROADCAST) == IFF_BROADCAST){ /*Not broad cast*/
				cur=cur->ifa_next;
				continue;
			}
			if(cur->ifa_addr==NULL || cur->ifa_addr->sa_family!=ip_type){ /*Not matching ipv4/ipv6 of dest*/
				cur=cur->ifa_next;
				continue;
			}
			if(cur->ifa_addr!=NULL && cur->ifa_addr->sa_family==AF_INET6){
				iv6=(struct sockaddr_in6*)cur->ifa_addr;
				if(iv6->sin6_scope_id!=0){ /*Not globally valid address, if ipv6*/
					cur=cur->ifa_next;
					continue;
				}
				if(memcmp(&lv6.sin6_addr,&iv6->sin6_addr,sizeof(iv6->sin6_addr))==0){/*IPv6 loopback*/
					cur=cur->ifa_next;
					continue;
				}
			}
			if(cur->ifa_addr!=NULL && cur->ifa_addr->sa_family==AF_INET){
				iv4=(struct sockaddr_in*)cur->ifa_addr;
				if(memcmp(&lv4.sin_addr,&iv4->sin_addr,sizeof(iv4->sin_addr))==0){/*IPv4 loopback*/
					cur=cur->ifa_next;
					continue;
				}
			}

			src_addr=malloc(sizeof(struct sockaddr_storage));
			if(src_addr==NULL){
				dbgprintf(0,"Error: Can't allocate Memory\n");
				exit(1);
			}
			src_addr->sa_family=ip_type;
			memcpy(src_addr,cur->ifa_addr,addrlen);
			break;
		}
		freeifaddrs(temp);
	}

	doping();


	free(src_addr);
	free(dest_addr);
	return 0;
}

/*Preform the ping functionality*/
void doping(){
	int ds, is;
	int done=0;
	int seq=8;
	int slen=sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_request);
	unsigned char sbuffer[slen+1];
	unsigned char rbuffer[1000];
	char pbuf[1000];
	struct dccp_hdr *dhdr;
	struct dccp_hdr_ext *dhdre;
	struct dccp_hdr_request *dhdrr;
	struct sockaddr_storage rcv_addr;
	socklen_t rcv_addr_len=sizeof(struct sockaddr_storage);
	struct sockaddr_in *iv41, *iv42;
	struct sockaddr_in6 *tmp;
	int opt;
	int rlen;

	dbgprintf(0, "In doping()\n");

	/*Open Sockets*/
	ds=socket(ip_type, SOCK_RAW | SOCK_NONBLOCK ,IPPROTO_DCCP);
	if(ds<0){
		dbgprintf(0, "Error opening raw DCCP socket\n");
		exit(1);
	}
	/*opt=1;
	if(setsockopt(ds,IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt))<0){
		dbgprintf(0, "Error setting socket options on raw DCCP socket (%s)\n", strerror(errno));
		exit(1);
	}*/
	is=socket(ip_type,SOCK_RAW | SOCK_NONBLOCK ,IPPROTO_ICMP);
	if(is<0){
		dbgprintf(0,"Error opening raw ICMP socket\n");
		exit(1);
	}

	/*Build DCCP packet*/
	dhdr=(struct dccp_hdr*)sbuffer;
	dhdre=(struct dccp_hdr_ext*)(sbuffer+sizeof(struct dccp_hdr));
	dhdrr=(struct dccp_hdr_request*)(sbuffer+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext));
	dhdr->dccph_ccval=0;
	dhdr->dccph_checksum=0;
	dhdr->dccph_cscov=0;
	dhdr->dccph_doff=slen/4;
	dhdr->dccph_dport=htons(dest_port);
	dhdr->dccph_reserved=0;
	dhdr->dccph_sport=htons(dest_port+1);
	dhdr->dccph_x=1;
	dhdr->dccph_type=DCCP_PKT_REQUEST;
	dhdr->dccph_seq2=htonl(0); //Reserved for 48 bit sequence numbers
	dhdr->dccph_seq=htonl(0);  //just always make the high end 0
	dhdre->dccph_seq_low=htonl(seq)>>8;
	dhdrr->dccph_req_service= htonl(0x50455246);

	opt=((unsigned char*)&dhdr->dccph_checksum) - &sbuffer[0];
	if (setsockopt(ds, IPPROTO_IPV6, IPV6_CHECKSUM, &opt, sizeof(opt)) < 0){
		dbgprintf(0, "Error setting up checksums on raw DCCP socket (%s)\n", strerror(errno));
		exit(1);
	}
	if(ip_type==AF_INET){
		iv41=(struct sockaddr_in*)dest_addr;
		iv42=(struct sockaddr_in*)src_addr;
		ip4_chksum(sbuffer, slen, (unsigned char*) &iv41->sin_addr, (unsigned char*)&iv42->sin_addr, 33,&dhdr->dccph_checksum);
	}

	while(!done){
		rcv_addr_len=sizeof(struct sockaddr_storage);
		if(sendto(ds, &sbuffer, slen, MSG_DONTWAIT,(struct sockaddr*)dest_addr,addrlen)<0){
			dbgprintf(0,"Error: sendto failed\n");
		}
		tmp=(struct sockaddr_in6*)dest_addr;
		dbgprintf(0, "Sending DCCP Request to %s\n",inet_ntop(ip_type, (void*)&tmp->sin6_addr, pbuf, 1000));

		if((rlen=recvfrom(ds, &rbuffer, 1000,MSG_DONTWAIT,(struct sockaddr*)&rcv_addr,&rcv_addr_len))<0){
			if(errno!=EAGAIN){
				dbgprintf(0, "Error on receive from DCCP socket (%s)\n",strerror(errno));
			}
		}
		if(rlen>0){
			if(rlen< sizeof(struct dccp_hdr)){
				dbgprintf(0,"Received Non-DCCP data!\n");
			}
			dhdr=(struct dccp_hdr*)rbuffer;
			tmp=(struct sockaddr_in6*)&rcv_addr;
			dbgprintf(0,"Response from %s (%i)\n", inet_ntop(ip_type, (void*)&tmp->sin6_addr, pbuf, 1000),dhdr->dccph_type);
		}

		if((rlen=recvfrom(is, &rbuffer, 1000,MSG_DONTWAIT,(struct sockaddr*)&rcv_addr,&rcv_addr_len))<0){
			if(errno!=EAGAIN){
				dbgprintf(0, "Error on receive from ICMP socket (%s)\n",strerror(errno));
			}
		}
		if(rlen>0){
			dbgprintf(0,"Received ICMP data!\n");
		}

		if(count>-1){
			count--;
		}
		if(count==0){
			done=1;
			break;
		}
		sleep(interval/1000);
	}

	close(ds);
	close(is);
}

int ip6_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type, unsigned short* chksum){
	struct ip6_pseudo_hdr hdr;

	//create pseudo header
	memset(&hdr, 0, sizeof(struct ip6_pseudo_hdr));
	memcpy(hdr.src, src, IP6_ADDR_LEN);
	memcpy(hdr.dest, dest, IP6_ADDR_LEN);
	hdr.nxt=type;
	hdr.len=htonl(len);

	//calculate total checksum
	*chksum=wrapsum(checksum((unsigned char*)&hdr,sizeof(struct ip6_pseudo_hdr),checksum(buff,len,0)));
return 0;
}

int ip4_chksum(unsigned char* buff, int len, unsigned char* dest, unsigned char* src, int type, unsigned short* chksum){
	struct ip4_pseudo_hdr hdr;

	//create pseudo header
	memset(&hdr, 0, sizeof(struct ip4_pseudo_hdr));
	memcpy(hdr.src, src, IP4_ADDR_LEN);
	memcpy(hdr.dest, dest, IP4_ADDR_LEN);
	hdr.nxt=type;
	hdr.len=htonl(len);

	//calculate total checksum
	*chksum=wrapsum(checksum((unsigned char*)&hdr,sizeof(struct ip4_pseudo_hdr),checksum(buff,len,0)));
return 0;
}

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

u_int32_t wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

/*Usage information for program*/
void usage()
{
	dbgprintf(0, "dccpping: [-d] [-6|-4] [-c count] [-p port] [-i interval] [-t ttl] [-S srcaddress] remote_host\n");
	exit(0);
}

/*Program will probably be run setuid, so be extra careful*/
void sanitize_environment()
{
#if defined(_SVID_SOURCE) || defined(_XOPEN_SOURCE)
	clearenv();
#else
	extern char **environ;
	environ = NULL;
#endif
}

/*Debug Printf*/
void dbgprintf(int level, const char *fmt, ...)
{
    va_list args;
    if(debug>=level){
    	va_start(args, fmt);
    	vfprintf(stderr, fmt, args);
    	va_end(args);
    }
}
