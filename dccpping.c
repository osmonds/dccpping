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
#include <linux/dccp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <errno.h>
#include "checksums.h"

extern int errno;

typedef union ipaddr{
	struct sockaddr *gen;
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
} ipaddr_ptr_t;


int debug=0;			/*set to 1 to turn on debugging information*/
int count=-1;			/*Default number of pings (-1 is infinity)*/
int dest_port=33434;	/*Default port*/
int ttl=64;				/*Default TTL*/
long interval=1000;		/*Default delay between pings in ms*/
int ip_type=AF_UNSPEC;	/*IPv4 or IPv6*/
ipaddr_ptr_t dest_addr;
ipaddr_ptr_t src_addr;


void getAddresses(char *src, char* dst);
void doping();
void buildPacket(unsigned char* buffer, int *len);
void dbgprintf(int level, const char *fmt, ...);
void sanitize_environment();
void usage();


/*Parse commandline options*/
int main(int argc, char *argv[])
{
	char c;
	char *src=NULL;
	char *dst=NULL;


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

	getAddresses(src, dst);

	doping();

	free(src_addr.gen);
	free(dest_addr.gen);
	return 0;
}

void getAddresses(char *src, char* dst){
	struct addrinfo hint;
	struct addrinfo *dtmp, *stmp;
	struct ifaddrs *temp, *cur;
	struct sockaddr_in6* iv6;
	int addrlen;
	int err;

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
		addrlen=dtmp->ai_addrlen;
		hint.ai_family=ip_type=dtmp->ai_family;
		dest_addr.gen=malloc(dtmp->ai_addrlen);
		if(dest_addr.gen==NULL){
			dbgprintf(0,"Error: Can't allocate Memory\n");
			exit(1);
		}
		memcpy(dest_addr.gen,dtmp->ai_addr,dtmp->ai_addrlen);
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
			addrlen=stmp->ai_addrlen;
			src_addr.gen=malloc(stmp->ai_addrlen);
			if(src_addr.gen==NULL){
				dbgprintf(0,"Error: Can't allocate Memory\n");
				exit(1);
			}
			memcpy(src_addr.gen,stmp->ai_addr,stmp->ai_addrlen);
		}
		freeaddrinfo(stmp);
	}else{
		/*Guess a good source address*/
		getifaddrs(&temp);
		cur=temp;
		while(cur!=NULL){
			if(cur->ifa_addr==NULL || cur->ifa_addr->sa_family!=ip_type){ /*Not matching ipv4/ipv6 of dest*/
				cur=cur->ifa_next;
				continue;
			}
			if(cur->ifa_flags & IFF_LOOPBACK){ /*Don't use loopback addresses*/
				cur=cur->ifa_next;
				continue;
			}
			if(cur->ifa_addr!=NULL && cur->ifa_addr->sa_family==AF_INET6){
				iv6=(struct sockaddr_in6*)cur->ifa_addr;

				if(iv6->sin6_scope_id!=0){ /*Not globally valid address, if ipv6*/
					cur=cur->ifa_next;
					continue;
				}
			}

			src_addr.gen=malloc(sizeof(struct sockaddr_storage));
			if(src_addr.gen==NULL){
				dbgprintf(0,"Error: Can't allocate Memory\n");
				exit(1);
			}
			src_addr.gen->sa_family=ip_type;
			memcpy(src_addr.gen,cur->ifa_addr,addrlen);
			//break;
			cur=cur->ifa_next;
		}
		freeifaddrs(temp);
	}
	return;
}

/*Preform the ping functionality*/
void doping(){
	int rs, is,ds;
	int done=0;
	int addrlen;
	int slen=1500;
	unsigned char sbuffer[slen];
	unsigned char rbuffer[1000];
	char pbuf[1000];
	struct dccp_hdr *dhdr;
	struct sockaddr_storage rcv_addr;
	socklen_t rcv_addr_len=sizeof(struct sockaddr_storage);
	struct sockaddr_in6 *tmp;
	//int opt;
	int rlen;

	dbgprintf(0, "In doping()\n");

	/*Open Sockets*/
	rs=socket(ip_type, SOCK_RAW | SOCK_NONBLOCK ,IPPROTO_RAW);
	if(rs<0){
		dbgprintf(0, "Error opening raw socket\n");
		exit(1);
	}
	ds=socket(ip_type, SOCK_RAW | SOCK_NONBLOCK ,IPPROTO_DCCP);
	if(ds<0){
		dbgprintf(0, "Error opening raw DCCP socket\n");
		exit(1);
	}
	is=socket(ip_type,SOCK_RAW | SOCK_NONBLOCK ,IPPROTO_ICMP);
	if(is<0){
		dbgprintf(0,"Error opening raw ICMP socket\n");
		exit(1);
	}

	/*opt=((unsigned char*)&dhdr->dccph_checksum) - &sbuffer[0];
	if (setsockopt(ds, IPPROTO_IPV6, IPV6_CHECKSUM, &opt, sizeof(opt)) < 0){
		dbgprintf(0, "Error setting up checksums on raw DCCP socket (%s)\n", strerror(errno));
		exit(1);
	}*/

	buildPacket(sbuffer,&slen);
	if(ip_type==AF_INET){
		addrlen=sizeof(struct sockaddr_in);
	}else{
		addrlen=sizeof(struct sockaddr_in6);
	}

	while(!done){

		if(sendto(rs, &sbuffer, slen, MSG_DONTWAIT,(struct sockaddr*)dest_addr.gen,addrlen)<0){
			dbgprintf(0,"Error: sendto failed\n");
		}

		if(ip_type==AF_INET){
			dbgprintf(0, "Sending DCCP Request to %s\n",inet_ntop(ip_type, (void*)&dest_addr.ipv4->sin_addr, pbuf, 1000));
		}else{
			dbgprintf(0, "Sending DCCP Request to %s\n",inet_ntop(ip_type, (void*)&dest_addr.ipv6->sin6_addr, pbuf, 1000));
		}

		rcv_addr_len=sizeof(struct sockaddr_storage);
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

	close(rs);
	close(is);
	close(ds);
}

void buildPacket(unsigned char* buffer, int *len){
	struct dccp_hdr *dhdr;
	struct dccp_hdr_ext *dhdre;
	struct dccp_hdr_request *dhdrr;
	struct iphdr* ip4hdr;
	struct ip6_hdr* ip6hdr;

	int ip_hdr_len;
	int dccp_hdr_len=sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_request);
	int seq=8;

	memset(buffer, 0, *len);

	/*IP header*/
	ip4hdr=NULL;
	if(ip_type==AF_INET){
		ip_hdr_len=sizeof(struct iphdr);
		ip4hdr=(struct iphdr*)buffer;
		ip4hdr->check=htons(0);
		memcpy(&ip4hdr->daddr, &dest_addr.ipv4->sin_addr, sizeof(dest_addr.ipv4->sin_addr));
		ip4hdr->frag_off=htons(0);
		ip4hdr->id=htons(1);//first
		ip4hdr->ihl=5;
		ip4hdr->protocol=IPPROTO_DCCP;
		memcpy(&ip4hdr->saddr, &src_addr.ipv4->sin_addr, sizeof(src_addr.ipv4->sin_addr));
		ip4hdr->tos=0;
		ip4hdr->tot_len=htons(ip_hdr_len+dccp_hdr_len);
		ip4hdr->ttl=ttl;
		ip4hdr->version=4;
	}else{
		ip_hdr_len=sizeof(struct ip6_hdr);
		ip6hdr=(struct ip6_hdr*)buffer;
		memcpy(&ip6hdr->ip6_dst, &dest_addr.ipv6->sin6_addr, sizeof(dest_addr.ipv6->sin6_addr));
		memcpy(&ip6hdr->ip6_src, &src_addr.ipv6->sin6_addr, sizeof(src_addr.ipv6->sin6_addr));
		ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_flow=htonl(6<<28); //version, traffic class, flow label
		ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim=ttl;
		ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt=IPPROTO_DCCP;
		ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_plen=htons(dccp_hdr_len);
	}

	/*DCCP header*/
	dhdr=(struct dccp_hdr*)(buffer+ip_hdr_len);
	dhdre=(struct dccp_hdr_ext*)(buffer+ip_hdr_len+sizeof(struct dccp_hdr));
	dhdrr=(struct dccp_hdr_request*)(buffer+ip_hdr_len+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext));
	dhdr->dccph_ccval=0;
	dhdr->dccph_checksum=0;
	dhdr->dccph_cscov=0;
	dhdr->dccph_doff=dccp_hdr_len/4;
	dhdr->dccph_dport=htons(dest_port);
	dhdr->dccph_reserved=0;
	dhdr->dccph_sport=htons(dest_port);
	dhdr->dccph_x=1;
	dhdr->dccph_type=DCCP_PKT_REQUEST;
	dhdr->dccph_seq2=htonl(0); //Reserved if using 48 bit sequence numbers
	dhdr->dccph_seq=htonl(0);  //High 16bits of sequence number. Always make 0 for simplicity.
	dhdre->dccph_seq_low=htonl(seq);
	dhdrr->dccph_req_service= htonl(0x50455246);

	/*Checksums*/
	if(ip_type==AF_INET){
		dhdr->dccph_checksum=ipv4_pseudohdr_chksum((buffer+ip_hdr_len), dccp_hdr_len,
				(unsigned char*) &dest_addr.ipv4->sin_addr,
				(unsigned char*)&src_addr.ipv4->sin_addr, IPPROTO_DCCP);
		ip4hdr->check=ipv4_chksum(buffer,ip_hdr_len);
	}else{
		dhdr->dccph_checksum=ipv6_pseudohdr_chksum((buffer+ip_hdr_len), dccp_hdr_len,
				(unsigned char*) &dest_addr.ipv6->sin6_addr,
				(unsigned char*)&src_addr.ipv6->sin6_addr, IPPROTO_DCCP);
	}
	*len=ip_hdr_len+dccp_hdr_len;
	return;
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
