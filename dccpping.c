/******************************************************************************
Utility to ping hosts using DCCP Request packets to test for DCCP connectivity.

Copyright (C) 2012  Samuel Jero <sj323707@ohio.edu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Author: Samuel Jero <sj323707@ohio.edu>
Date: 11/2012
******************************************************************************/
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/dccp.h>
#include "checksums.h"


/*Use the DCCP source port to multiplex DCCP Ping streams by PID*/
#define DCCP_SERVICE_CODE 0x50455246
#define DEFAULT_PORT 33434

#define DCCPPING_VERSION 1.0
#define MAX(x,y) (x>y ? x : y)
extern int errno;
#ifndef NI_IDN
#define NI_IDN 32
#endif


/*Structure for simpler IPv4/IPv6 Address handling*/
typedef union ipaddr{
	struct sockaddr *gen;
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
} ipaddr_ptr_t;

/*Possible Responses to a Request*/
enum responses{
	UNKNOWN=0,
	RESET,
	RESPONSE,
	SYNC,
	DEST_UNREACHABLE,
	TTL_EXPIRATION,
	TOO_BIG,
	PARAMETER_PROBLEM,
	DCCP_ERROR
};

/*Output strings corresponding to enum responses*/
static const char* response_label[]= {
"Unknown",
"Closed Port (Reset)",
"Open Port (Response)",
"Open Port (Sync)",
"Destination Unreachable",
"TTL Expiration",
"Packet Too Big",
"DCCP Not Supported (Parameter Problem)",
"Protocol Error (DCCP Reset)"
};

/*Structure to keep track of information about a request*/
struct request{
	int				request_seq;
	int				packet_seq;
	int				num_replies;
	int				num_errors;
	struct timeval	sent;
	struct timeval	reply;
	enum responses	reply_type;
	struct request  *next;
	struct request  *prev;
};

/*Request Queue head structure*/
struct request_queue{
	struct request *head;
	struct request *tail;
};

/*Statistics about the requests and replies sent*/
struct stats{
	int				requests_sent;
	int				replies_received;
	int				errors;
	double  		rtt_min;
	double			rtt_avg;
	double 			rtt_max;
	struct timeval 	start;
	struct timeval 	stop;
};

struct params{
	int count;				/*Number of pings (-1 is infinity)*/
	int	no_resolve;			/*1 if we shouldn't resolve IP addresses*/
	int dest_port;			/*Destination port*/
	int src_port;			/*Source port---used to encode pid*/
	int ttl;				/*TTL*/
	long interval;			/*Delay between pings in ms*/
	int ip_type;			/*IPv4 or IPv6*/
	ipaddr_ptr_t dest_addr;	/*Destination Address*/
	ipaddr_ptr_t src_addr;	/*Source Address*/
	int dccp_socket;		/*DCCP Socket used to grab src addr/port*/
	char* hostname;			/*Originally requested hostname*/
};


int 					debug=0;		/*set to 1 to turn on debugging information*/
struct request_queue 	queue;			/*Queue of requests to track RTT/duplicate information*/
struct stats			ping_stats;		/*Ping Statistics*/
struct params			parms;			/*Parameters for ping*/
char 					addr2str_buf[1000]; 	/*Buffer for printing addresses*/
char 					addr2nm_buf[1000]; 		/*Buffer for printing addresses*/
char 					addr2both_buf[1000]; 	/*Buffer for printing addresses*/


void getAddresses(char *src, char* dst);
void doping();
void handleDCCPpacket(int rcv_socket, int send_socket);
void handleICMP4packet(int rcv_socket);
void handleICMP6packet(int rcv_socket);
void buildRequestPacket(unsigned char* buffer, int *len, int seq);
void updateRequestPacket(unsigned char* buffer, int *len, int seq);
int logPacket(int req_seq, int packet_seq);
int logResponse(ipaddr_ptr_t *src, int seq, int type);
void clearQueue();
void sigHandler();
char* addr2str(ipaddr_ptr_t *res, int nores);
void usage();
void version();
void sanitize_environment();
void dbgprintf(int level, const char *fmt, ...);


/*Parse commandline options*/
int main(int argc, char *argv[])
{
	char c;
	char *src=NULL;
	char *dst=NULL;

	/*Set Defaults*/
	queue.head=NULL;
	queue.tail=NULL;
	ping_stats.replies_received=0;
	ping_stats.requests_sent=0;
	ping_stats.rtt_avg=0;
	ping_stats.rtt_max=0;
	ping_stats.rtt_min=0;
	ping_stats.errors=0;
	parms.count=-1;
	parms.dest_port=DEFAULT_PORT;
	parms.ttl=64;
	parms. interval=1000;
	parms.ip_type=AF_UNSPEC;
	parms.dest_addr.gen=NULL;
	parms.src_addr.gen=NULL;
	parms.dccp_socket=-1;
	parms.no_resolve=0;
	parms.hostname=NULL;

	sanitize_environment();

	while ((c = getopt(argc, argv, "64vhnc:p:i:dt:S:")) != -1) {
		switch (c) {
			case '6':
				parms.ip_type=AF_INET6;
				break;
			case '4':
				parms.ip_type=AF_INET;
				break;
			case 'c':
				parms.count = atoi(optarg);
				if(parms.count<=0){
					dbgprintf(0, "Error: count must be positive");
					exit(1);
				}
				break;
			case 'p':
				parms.dest_port = atoi(optarg);
				break;
			case 'i':
				parms.interval = (long)(atof(optarg) * 1000.0);
				if (parms.interval <= 0) {
					dbgprintf(0, "Error: Invalid interval\n");
					exit(1);
				}
				break;
			case 'd':
				debug++;
				break;
			case 'n':
				parms.no_resolve=1;
				break;
			case 't':
				parms.ttl = atoi(optarg);
				if (parms.ttl < 1 || parms.ttl > 255) {
					dbgprintf(0,"Error: Invalid TTL\n");
				}
				break;
			case 'S':
				src=optarg;
				break;
			case 'v':
				version();
				break;
			case 'h':
				/*Intentional Fall-through*/
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
	parms.hostname=argv[0];

	getAddresses(src, dst);
	if(parms.src_addr.gen==NULL || parms.dest_addr.gen==NULL){
		dbgprintf(0,"Error: Can't determine source or destination address\n");
		exit(1);
	}

	signal(SIGINT, sigHandler);
	doping();

	free(parms.src_addr.gen);
	free(parms.dest_addr.gen);
	close(parms.dccp_socket);
	clearQueue();
	return 0;
}

void getAddresses(char *src, char* dst){
	struct addrinfo hint;
	struct addrinfo *dtmp, *stmp;
	struct ifaddrs *temp, *cur;
	ipaddr_ptr_t ipv;
	struct sockaddr_in6* iv61;
	struct sockaddr_in6* iv62;
	struct sockaddr_in* iv41;
	struct sockaddr_in* iv42;
	int addrlen;
	int err;

	/*Lookup destination Address*/
	memset(&hint,0,sizeof(struct addrinfo));
	hint.ai_family=parms.ip_type;
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
		hint.ai_family=parms.ip_type=dtmp->ai_family;
		parms.dest_addr.gen=malloc(dtmp->ai_addrlen);
		if(parms.dest_addr.gen==NULL){
			dbgprintf(0,"Error: Can't allocate Memory\n");
			exit(1);
		}
		memcpy(parms.dest_addr.gen,dtmp->ai_addr,dtmp->ai_addrlen);
		parms.dest_addr.gen->sa_family=dtmp->ai_family;
	}
	freeaddrinfo(dtmp);

	/*Get a meaningful source address*/
	if(src!=NULL){
		/*Use Commandline arg*/

		/*Convert arg to address*/
		if((err=getaddrinfo(src,NULL,&hint,&stmp))!=0){
			dbgprintf(0,"Error: Source Address %s is invalid (%s)\n", src, gai_strerror(err));
			exit(1);
		}
		if(stmp==NULL){
			dbgprintf(0,"Error: Unknown Host %s\n", dst);
			exit(1);
		}

		/*Compare to interface addresses*/
		getifaddrs(&temp);
		cur=temp;
		while(cur!=NULL){
			if(cur->ifa_addr==NULL || cur->ifa_addr->sa_family!=stmp->ai_family){
				/*Not matching ipv4/ipv6 of dest*/
				cur=cur->ifa_next;
				continue;
			}
			if(stmp->ai_family==AF_INET){
				iv41=(struct sockaddr_in*)stmp->ai_addr;
				iv42=(struct sockaddr_in*)cur->ifa_addr;
				if(memcmp(&iv41->sin_addr,&iv42->sin_addr, sizeof(iv41->sin_addr))==0){
					parms.src_addr.gen=malloc(sizeof(struct sockaddr_storage));
					if(parms.src_addr.gen==NULL){
						dbgprintf(0,"Error: Can't allocate Memory\n");
						exit(1);
					}
					parms.src_addr.gen->sa_family=parms.ip_type;
					memcpy(parms.src_addr.gen,cur->ifa_addr,addrlen);
					break;
				}
			}else{
				iv61=(struct sockaddr_in6*)stmp->ai_addr;
				iv62=(struct sockaddr_in6*)cur->ifa_addr;
				if(memcmp(&iv61->sin6_addr,&iv62->sin6_addr, sizeof(iv61->sin6_addr))==0){
					parms.src_addr.gen=malloc(sizeof(struct sockaddr_storage));
					if(parms.src_addr.gen==NULL){
						dbgprintf(0,"Error: Can't allocate Memory\n");
						exit(1);
					}
					parms.src_addr.gen->sa_family=parms.ip_type;
					memcpy(parms.src_addr.gen,cur->ifa_addr,addrlen);
					break;
				}
			}
			cur=cur->ifa_next;
		}
		if(parms.src_addr.gen==NULL){
			ipv.gen=(struct sockaddr*)stmp->ai_addr;
			dbgprintf(0,"Error: Source Address %s does not belong to any interface!\n",addr2str(&ipv,1));
			exit(1);
		}
		freeifaddrs(temp);
		freeaddrinfo(stmp);
	}

	/*Create socket to auto respond for open connections and reserve a source port*/
	parms.dccp_socket=socket(parms.ip_type,SOCK_DCCP, IPPROTO_DCCP);
	if(parms.dccp_socket<0){
		dbgprintf(0, "Error: Failed opening DCCP Socket (%s)\n",strerror(errno));
		exit(1);
	}
	fcntl(parms.dccp_socket, F_SETFL, O_NONBLOCK);


	if(parms.src_addr.gen==NULL){
		/*Auto-detect source address*/
		parms.src_addr.gen=malloc(sizeof(struct sockaddr_storage));
		if(parms.src_addr.gen==NULL){
			dbgprintf(0,"Error: Can't allocate Memory\n");
			exit(1);
		}
		memset(parms.src_addr.gen,0,sizeof(struct sockaddr_storage));
		parms.src_addr.gen->sa_family=parms.ip_type;
	}else{
		/*Bind to the given source address*/
		if(bind(parms.dccp_socket,parms.src_addr.gen,sizeof(struct sockaddr_storage))<0){
			dbgprintf(0, "Error: Failed bind() on DCCP socket (%s)\n",strerror(errno));
			exit(1);
		}
	}

	/*Connect socket to get source address/port*/
	if(parms.ip_type==AF_INET){
		parms.dest_addr.ipv4->sin_port=htons(parms.dest_port);
	}else{
		parms.dest_addr.ipv6->sin6_port=htons(parms.dest_port);
	}
	if(connect(parms.dccp_socket,parms.dest_addr.gen,sizeof(struct sockaddr_storage))<0){
		if(errno!=EINPROGRESS){
			dbgprintf(0, "Error: Failed connect() on DCCP socket (%s)\n",strerror(errno));
			exit(1);
		}
	}

	/*Get source address and port number!*/
	addrlen=sizeof(struct sockaddr_storage);
	if(getsockname(parms.dccp_socket,parms.src_addr.gen,(socklen_t*)&addrlen)<0){
		dbgprintf(0, "Error: Failed getsockname() on DCCP socket (%s)\n",strerror(errno));
		exit(1);
	}
	if(parms.ip_type==AF_INET){
		parms.src_port=ntohs(parms.src_addr.ipv4->sin_port);
		parms.dest_addr.ipv4->sin_port=0;
	}else{
		parms.src_port=ntohs(parms.src_addr.ipv6->sin6_port);
		parms.dest_addr.ipv6->sin6_port=0;
	}
	return;
}

/*Preform the ping functionality*/
void doping(){
	int rs, is4,is6,ds;
	int done=0;
	int addrlen;
	int slen=1500;
	unsigned char sbuffer[slen];
	fd_set sel;
	struct timeval timeout;
	struct timeval t,delay, add;
	int request_seq=1;
	int packet_seq;

	/*Open Sockets*/
	rs=socket(parms.ip_type, SOCK_RAW ,IPPROTO_RAW);
	if(rs<0){
		dbgprintf(0, "Error opening raw socket\n");
		exit(1);
	}
	ds=socket(parms.ip_type, SOCK_RAW ,IPPROTO_DCCP);
	if(ds<0){
		dbgprintf(0, "Error opening raw DCCP socket\n");
		exit(1);
	}
	is4=socket(parms.ip_type,SOCK_RAW,IPPROTO_ICMP);
	if(is4<0){
		dbgprintf(0,"Error opening raw ICMPv4 socket\n");
		exit(1);
	}
	is6=socket(parms.ip_type,SOCK_RAW,IPPROTO_ICMPV6);
	if(is6<0){
		dbgprintf(0,"Error opening raw ICMPv6 socket\n");
		exit(1);
	}


	/*Build DCCP packet*/
	packet_seq=rand();
	buildRequestPacket(sbuffer,&slen,packet_seq);
	if(parms.ip_type==AF_INET){
		addrlen=sizeof(struct sockaddr_in);
	}else{
		addrlen=sizeof(struct sockaddr_in6);
	}

	/*Start Message*/
	printf("PINGING %s (%s) on DCCP port %i\n",parms.hostname, addr2str(&parms.dest_addr,1),parms.dest_port);

	while(!done){
		/*Send Ping*/
		if(sendto(rs, &sbuffer, slen, MSG_DONTWAIT,(struct sockaddr*)parms.dest_addr.gen,addrlen)<0){
			if(errno!=EINTR){
				dbgprintf(0,"Error: sendto() failed (%s)\n",strerror(errno));
			}
		}
		if(parms.count==0){done=1; break;}

		if (logPacket(request_seq,packet_seq)<0){
			dbgprintf(0,"Error: Couldn't record request!\n");
		}
		if(parms.ip_type==AF_INET){
			dbgprintf(1, "Sending DCCP Request to %s\n",
					addr2str(&parms.dest_addr,0));
		}else{
			dbgprintf(1, "Sending DCCP Request to %s\n",
					addr2str(&parms.dest_addr,0));
		}

		/*Use select to wait on packets or until interval has passed*/
		add.tv_sec=parms.interval/1000;
		add.tv_usec=(parms.interval%1000)*1000;
		gettimeofday(&t,NULL);
		timeradd(&t,&add,&delay);
		while(timercmp(&t,&delay,<)){
			/*Prepare for select*/
			FD_ZERO(&sel);
			FD_SET(ds,&sel);
			FD_SET(is4,&sel);
			FD_SET(is6,&sel);
			timersub(&delay,&t,&timeout);

			/*Do select call*/
			if(select(MAX(ds+1,MAX(is4+1,is6+1)),&sel, NULL,NULL,&timeout)<0){
				if(errno!=EINTR){
					dbgprintf(0,"Select() error (%s)\n",strerror(errno));
				}
			}
			if(parms.count==0){done=1;break;}

			if(FD_ISSET(ds,&sel)){
				/*Data on the DCCP socket*/
				handleDCCPpacket(ds,rs);

			}
			if(FD_ISSET(is4,&sel) && parms.ip_type==AF_INET){
				/*Data on the ICMPv4 socket*/
				handleICMP4packet(is4);
			}
			if(FD_ISSET(is6,&sel) && parms.ip_type==AF_INET6){
				/*Data on the ICMPv6 socket*/
				handleICMP6packet(is6);
			}
			gettimeofday(&t,NULL);
		}

		/*Update count*/
		if(parms.count>-1){
			parms.count--;
		}
		request_seq++;
		packet_seq=rand();
		updateRequestPacket(sbuffer,&slen, packet_seq);
	}

	close(rs);
	close(is4);
	close(is6);
	close(ds);
}

void handleDCCPpacket(int rcv_socket, int send_socket){
	int rlen=1500;
	unsigned char rbuffer[rlen];
	ipaddr_ptr_t rcv_addr;
	socklen_t rcv_addr_len;
	struct dccp_hdr *dhdr;
	struct dccp_hdr_reset *dhdr_re;
	struct dccp_hdr_response *dhdr_rp;
	struct dccp_hdr_ack_bits *dhdr_sync;
	unsigned char* ptr;
	struct iphdr* iph;

	/*Memory for socket address*/
	rcv_addr_len=sizeof(struct sockaddr_storage);
	rcv_addr.gen=malloc(rcv_addr_len);
	if(rcv_addr.gen==NULL){
		dbgprintf(0,"Error: Can't Allocate Memory!\n");
		exit(1);
	}

	/*Receive Packet*/
	rcv_addr_len=sizeof(struct sockaddr_storage);
	if((rlen=recvfrom(rcv_socket, &rbuffer, 1500,0,rcv_addr.gen,&rcv_addr_len))<0){
		if(errno!=EINTR){
			dbgprintf(0, "Error on receive from DCCP socket (%s)\n",strerror(errno));
		}
	}
	if(rlen<0){
		return;
	}

	if(rcv_addr.gen->sa_family!=parms.ip_type){ //confirm IP type
		dbgprintf(1, "DCCP packet on %s. Tossing.\n", (parms.ip_type==AF_INET) ? "IPv4" : "IPv6");
		free(rcv_addr.gen);
		return;
	}

	if(rcv_addr.gen->sa_family==AF_INET){
		/*IPv4*/
		if(memcmp(&rcv_addr.ipv4->sin_addr,&parms.dest_addr.ipv4->sin_addr,
				sizeof(parms.dest_addr.ipv4->sin_addr))!=0){ //not from destination
			dbgprintf(1,"DCCP packet from 3rd host\n");
			free(rcv_addr.gen);
			return;
		}
		if(rlen < sizeof(struct dccp_hdr)+sizeof(struct iphdr)){ //check packet size

			dbgprintf(1, "Packet smaller than possible DCCP packet received on DCCP socket\n");
			free(rcv_addr.gen);
			return;
		}
		iph=(struct iphdr*)rbuffer;
		ptr=rbuffer+iph->ihl*4;
	}else{
		/*IPv6*/
		if(memcmp(&rcv_addr.ipv6->sin6_addr, &parms.dest_addr.ipv6->sin6_addr,
				sizeof(parms.dest_addr.ipv6->sin6_addr))!=0){ //not from destination
			dbgprintf(1,"DCCP packet from 3rd host\n");
			free(rcv_addr.gen);
			return;
		}
		if(rlen < sizeof(struct dccp_hdr)){ //check packet size

			dbgprintf(1, "Packet smaller than possible DCCP packet received on DCCP socket\n");
			free(rcv_addr.gen);
			return;
		}
		ptr=rbuffer;
	}

	/*DCCP checks*/
	dhdr=(struct dccp_hdr*)ptr;
	if(dhdr->dccph_sport!=htons(parms.dest_port)){
		dbgprintf(1,"DCCP packet with wrong Source Port (%i)\n", ntohs(dhdr->dccph_sport));
		free(rcv_addr.gen);
		return;
	}
	if(dhdr->dccph_dport!=htons(parms.src_port)){
		dbgprintf(1,"DCCP packet with wrong Destination Port\n");
		free(rcv_addr.gen);
		return;
	}

	/*Pick Response*/
	if(dhdr->dccph_type==DCCP_PKT_RESET){
		if(rlen < (ptr-rbuffer)+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_reset)){
			dbgprintf(1, "Tossing DCCP Reset packet that's small!\n");
			return;
		}
		dhdr_re=(struct dccp_hdr_reset*)(ptr+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext));

		/*Log*/
		if(dhdr_re->dccph_reset_code==DCCP_RESET_CODE_NO_CONNECTION){
			logResponse(&rcv_addr, ntohl(dhdr_re->dccph_reset_ack.dccph_ack_nr_low), RESET);
		}else{
			logResponse(&rcv_addr, ntohl(dhdr_re->dccph_reset_ack.dccph_ack_nr_low), DCCP_ERROR);
		}
		/*Nothing else to do*/
	}
	if(dhdr->dccph_type==DCCP_PKT_RESPONSE){
		if(rlen < (ptr-rbuffer)+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_response)){
			dbgprintf(1, "Tossing DCCP Response packet that's too small!\n");
			return;
		}

		/*Log*/
		dhdr_rp=(struct dccp_hdr_response*)(ptr+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext));
		logResponse(&rcv_addr,ntohl(dhdr_rp->dccph_resp_ack.dccph_ack_nr_low),RESPONSE);

		/*DCCP socket opened in getAddresses() will send Reset*/
	}
	if(dhdr->dccph_type==DCCP_PKT_SYNC || dhdr->dccph_type==DCCP_PKT_SYNCACK){
		if(rlen < (ptr-rbuffer)+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_ack_bits)){
			dbgprintf(1, "Tossing DCCP Sync/SyncAck packet that's too small!\n");
			return;
		}

		/*Log*/
		dhdr_sync=(struct dccp_hdr_ack_bits*)(ptr+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext));
		logResponse(&rcv_addr,ntohl(dhdr_sync->dccph_ack_nr_low),SYNC);

		/*DCCP socket opened in getAddresses() will send Reset*/
	}

	free(rcv_addr.gen);
}

void handleICMP4packet(int rcv_socket){
	int rlen=1500;
	unsigned char rbuffer[rlen];
	ipaddr_ptr_t rcv_addr;
	socklen_t rcv_addr_len;
	struct icmphdr *icmp4;
	struct dccp_hdr *dhdr;
	struct dccp_hdr_ext *dhdre;
	struct iphdr* ip4hdr;
	struct iphdr* iph;
	int type;

	/*Memory for socket address*/
	rcv_addr_len=sizeof(struct sockaddr_storage);
	rcv_addr.gen=malloc(rcv_addr_len);
	if(rcv_addr.gen==NULL){
		dbgprintf(0,"Error: Can't Allocate Memory!\n");
		exit(1);
	}

	/*Receive Packet*/
	if((rlen=recvfrom(rcv_socket, &rbuffer, 1500,0,rcv_addr.gen,&rcv_addr_len))<0){
		if(errno!=EINTR){
			dbgprintf(0, "Error on receive from ICMPv4 socket (%s)\n",strerror(errno));
		}
	}
	if(rlen<0){
		return;
	}

	iph=(struct iphdr*)rbuffer;


	if(rlen < sizeof(struct icmphdr)+sizeof(struct iphdr)){ //check packet size
		dbgprintf(1, "Packet smaller than possible ICMPv4 packet!\n");
		free(rcv_addr.gen);
		return;
	}

	icmp4=(struct icmphdr*)(rbuffer+iph->ihl*4);
	if(icmp4->type!=ICMP_DEST_UNREACH && icmp4->type!=ICMP_TIME_EXCEEDED){ //check icmp types
		dbgprintf(1, "Tossing ICMPv4 packet of type %i\n", icmp4->type);
		free(rcv_addr.gen);
		return;
	}

	/*Check packet size again*/
	if(rlen<sizeof(struct icmphdr)+2*sizeof(struct iphdr)+4){
		dbgprintf(1, "Tossing ICMPv4 packet that's too small to contain DCCP header!\n");
		free(rcv_addr.gen);
		return;
	}

	/*Decode IPv4 header*/
	ip4hdr=(struct iphdr*)(rbuffer+iph->ihl*4+sizeof(struct icmphdr));
	if(memcmp(&parms.src_addr.ipv4->sin_addr,&ip4hdr->saddr,sizeof(parms.src_addr.ipv4->sin_addr))!=0){
		/*Source address doesn't match*/
		dbgprintf(1,"Tossing ICMPv4 packet because the embedded IPv4 source address isn't us\n");
		free(rcv_addr.gen);
		return;
	}
	if(memcmp(&parms.dest_addr.ipv4->sin_addr,&ip4hdr->daddr,sizeof(parms.dest_addr.ipv4->sin_addr))!=0){
		/*Destination address doesn't match*/
		dbgprintf(1,"Tossing ICMPv4 packet because the embedded IPv4 destination address isn't our target\n");
		free(rcv_addr.gen);
		return;
	}
	if(ip4hdr->protocol!=IPPROTO_DCCP){
		/*Not DCCP!*/
		dbgprintf(1,"Tossing ICMPv4 packet because the embedded packet isn't DCCP\n");
		free(rcv_addr.gen);
		return;
	}

	/*Decode DCCP header*/
	dhdr=(struct dccp_hdr*)(rbuffer+iph->ihl*4+sizeof(struct icmphdr)+ip4hdr->ihl*4);
	if(dhdr->dccph_dport!=htons(parms.dest_port)){
		/*DCCP Destination Ports don't match*/
		dbgprintf(1,"Tossing ICMPv4 packet because the embedded packet doesn't have our DCCP destination port\n");
		free(rcv_addr.gen);
		return;
	}
	if(dhdr->dccph_sport!=htons(parms.src_port)){
		/*DCCP Source Ports don't match*/
		dbgprintf(1,"Tossing ICMPv4 packet because the embedded packet doesn't have our DCCP source port\n");
		free(rcv_addr.gen);
		return;
	}
	dhdre=(struct dccp_hdr_ext*)(rbuffer+iph->ihl*4+sizeof(struct icmphdr)+ip4hdr->ihl*4+sizeof(struct dccp_hdr));

	/*Log*/
	if(icmp4->type==ICMP_DEST_UNREACH){
		type=DEST_UNREACHABLE;
	}
	if(icmp4->type==ICMP_TIME_EXCEEDED){
		type=TTL_EXPIRATION;
	}
	if(rlen<sizeof(struct icmphdr)+2*sizeof(struct iphdr)+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)){
		logResponse(&rcv_addr,-1,type);
	}else{
		logResponse(&rcv_addr,ntohl(dhdre->dccph_seq_low),type);
	}
	free(rcv_addr.gen);
	return;
}

void handleICMP6packet(int rcv_socket){
	int rlen=1500;
	unsigned char rbuffer[rlen];
	ipaddr_ptr_t rcv_addr;
	socklen_t rcv_addr_len;
	struct icmp6_hdr *icmp6;
	struct ip6_hdr* ip6hdr;
	struct dccp_hdr *dhdr;
	struct dccp_hdr_ext *dhdre;
	int type;

	/*Memory for socket address*/
	rcv_addr_len=sizeof(struct sockaddr_storage);
	rcv_addr.gen=malloc(rcv_addr_len);
	if(rcv_addr.gen==NULL){
		dbgprintf(0,"Error: Can't Allocate Memory!\n");
		exit(1);
	}

	/*Receive Packet*/
	if((rlen=recvfrom(rcv_socket, &rbuffer, 1500,0,rcv_addr.gen,&rcv_addr_len))<0){
		dbgprintf(0, "Error on receive from ICMPv6 socket (%s)\n",strerror(errno));
	}

	if(rlen < sizeof(struct icmp6_hdr)){ //check packet size
		dbgprintf(1, "Packet smaller than possible ICMPv6 packet!\n");
		free(rcv_addr.gen);
		return;
	}

	icmp6=(struct icmp6_hdr*)rbuffer;
	if(icmp6->icmp6_type!=ICMP6_DST_UNREACH && icmp6->icmp6_type!=ICMP6_PACKET_TOO_BIG
			&& icmp6->icmp6_type!=ICMP6_TIME_EXCEEDED && icmp6->icmp6_type!=ICMP6_PARAM_PROB){ //check icmp types
		dbgprintf(1, "Tossing ICMPv6 packet of type %i\n", icmp6->icmp6_type);
		free(rcv_addr.gen);
		return;
	}

	/*Check packet size again*/
	if(rlen<sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr)+sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)){
		dbgprintf(1, "Tossing ICMPv6 packet that's too small to contain DCCP header!\n");
		free(rcv_addr.gen);
		return;
	}

	/*Decode IPv6 header*/
	ip6hdr=(struct ip6_hdr*)(rbuffer+sizeof(struct icmp6_hdr));
	if(memcmp(&parms.src_addr.ipv6->sin6_addr,&ip6hdr->ip6_src,sizeof(parms.src_addr.ipv6->sin6_addr))!=0){
		dbgprintf(1,"Tossing ICMPv6 packet because the embedded IPv6 source address isn't us\n");
		/*Source address doesn't match*/
		free(rcv_addr.gen);
		return;
	}
	if(memcmp(&parms.dest_addr.ipv6->sin6_addr,&ip6hdr->ip6_dst,sizeof(parms.dest_addr.ipv6->sin6_addr))!=0){
		/*Destination address doesn't match*/
		dbgprintf(1,"Tossing ICMPv6 packet because the embedded IPv6 destination address isn't our target\n");
		free(rcv_addr.gen);
		return;
	}
	if(ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt!=IPPROTO_DCCP){
		/*Not DCCP!*/
		dbgprintf(1,"Tossing ICMPv6 packet because the embedded packet isn't DCCP\n");
		free(rcv_addr.gen);
		return;
	}

	/*Decode DCCP header*/
	dhdr=(struct dccp_hdr*)(rbuffer+sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr));
	if(dhdr->dccph_dport!=htons(parms.dest_port)){
		/*DCCP Destination Ports don't match*/
		dbgprintf(1,"Tossing ICMPv6 packet because the embedded packet doesn't have our DCCP destination port\n");
		free(rcv_addr.gen);
		return;
	}
	if(dhdr->dccph_sport!=htons(parms.src_port)){
		/*DCCP Source Ports don't match*/
		dbgprintf(1,"Tossing ICMPv6 packet because the embedded packet doesn't have our DCCP source port\n");
		free(rcv_addr.gen);
		return;
	}
	dhdre=(struct dccp_hdr_ext*)(rbuffer+sizeof(struct icmp6_hdr)+sizeof(struct ip6_hdr)+sizeof(struct dccp_hdr));

	/*Log*/
	if(icmp6->icmp6_type==ICMP6_DST_UNREACH){
		type=DEST_UNREACHABLE;
	}
	if(icmp6->icmp6_type==ICMP6_PACKET_TOO_BIG){
		type=TOO_BIG;
	}
	if(icmp6->icmp6_type==ICMP6_TIME_EXCEEDED){
		type=TTL_EXPIRATION;
	}
	if(icmp6->icmp6_type==ICMP6_PARAM_PROB){
		type=PARAMETER_PROBLEM;
	}
	logResponse(&rcv_addr,ntohl(dhdre->dccph_seq_low),type);
	free(rcv_addr.gen);
	return;
}

void buildRequestPacket(unsigned char* buffer, int *len, int seq){
	struct dccp_hdr *dhdr;
	struct dccp_hdr_ext *dhdre;
	struct dccp_hdr_request *dhdrr;
	struct iphdr* ip4hdr;
	struct ip6_hdr* ip6hdr;

	int ip_hdr_len;
	int dccp_hdr_len=sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_request);

	if(*len < dccp_hdr_len+sizeof(struct ip6_hdr)){
		dbgprintf(0, "Error: Insufficient buffer space\n");
		exit(1);
	}

	memset(buffer, 0, *len);

	/*IP header*/
	ip4hdr=NULL;
	if(parms.ip_type==AF_INET){
		ip_hdr_len=sizeof(struct iphdr);
		ip4hdr=(struct iphdr*)buffer;
		ip4hdr->check=htons(0);
		memcpy(&ip4hdr->daddr, &parms.dest_addr.ipv4->sin_addr, sizeof(parms.dest_addr.ipv4->sin_addr));
		ip4hdr->frag_off=htons(0);
		ip4hdr->id=htons(1);//first
		ip4hdr->ihl=5;
		ip4hdr->protocol=IPPROTO_DCCP;
		memcpy(&ip4hdr->saddr, &parms.src_addr.ipv4->sin_addr, sizeof(parms.src_addr.ipv4->sin_addr));
		ip4hdr->tos=0;
		ip4hdr->tot_len=htons(ip_hdr_len+dccp_hdr_len);
		ip4hdr->ttl=parms.ttl;
		ip4hdr->version=4;
	}else{
		ip_hdr_len=sizeof(struct ip6_hdr);
		ip6hdr=(struct ip6_hdr*)buffer;
		memcpy(&ip6hdr->ip6_dst, &parms.dest_addr.ipv6->sin6_addr, sizeof(parms.dest_addr.ipv6->sin6_addr));
		memcpy(&ip6hdr->ip6_src, &parms.src_addr.ipv6->sin6_addr, sizeof(parms.src_addr.ipv6->sin6_addr));
		ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_flow=htonl(6<<28); //version, traffic class, flow label
		ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim=parms.ttl;
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
	dhdr->dccph_dport=htons(parms.dest_port);
	dhdr->dccph_reserved=0;
	dhdr->dccph_sport=htons(parms.src_port);
	dhdr->dccph_x=1;
	dhdr->dccph_type=DCCP_PKT_REQUEST;
	dhdr->dccph_seq2=htonl(0); //Reserved if using 48 bit sequence numbers
	dhdr->dccph_seq=htonl(0);  //High 16bits of sequence number. Always make 0 for simplicity.
	dhdre->dccph_seq_low=htonl(seq);
	dhdrr->dccph_req_service=htonl(DCCP_SERVICE_CODE);

	/*Checksums*/
	if(parms.ip_type==AF_INET){
		dhdr->dccph_checksum=ipv4_pseudohdr_chksum((buffer+ip_hdr_len), dccp_hdr_len,
				(unsigned char*) &parms.dest_addr.ipv4->sin_addr,
				(unsigned char*)&parms.src_addr.ipv4->sin_addr, IPPROTO_DCCP);
		ip4hdr->check=ipv4_chksum(buffer,ip_hdr_len);
	}else{
		dhdr->dccph_checksum=ipv6_pseudohdr_chksum((buffer+ip_hdr_len), dccp_hdr_len,
				(unsigned char*) &parms.dest_addr.ipv6->sin6_addr,
				(unsigned char*)&parms.src_addr.ipv6->sin6_addr, IPPROTO_DCCP);
	}
	*len=ip_hdr_len+dccp_hdr_len;
	return;
}

void updateRequestPacket(unsigned char* buffer, int *len, int seq){
	struct dccp_hdr *dhdr;
	struct dccp_hdr_ext *dhdre;
	struct iphdr* ip4hdr;

	int ip_hdr_len;
	int dccp_hdr_len=sizeof(struct dccp_hdr)+sizeof(struct dccp_hdr_ext)+sizeof(struct dccp_hdr_request);

	/*IP header*/
	ip4hdr=NULL;
	if(parms.ip_type==AF_INET){
		ip_hdr_len=sizeof(struct iphdr);
		ip4hdr=(struct iphdr*)buffer;
		ip4hdr->check=htons(0);
		ip4hdr->id=htons(seq);
	}else{
		ip_hdr_len=sizeof(struct ip6_hdr);
	}

	/*DCCP header*/
	dhdr=(struct dccp_hdr*)(buffer+ip_hdr_len);
	dhdre=(struct dccp_hdr_ext*)(buffer+ip_hdr_len+sizeof(struct dccp_hdr));
	dhdr->dccph_checksum=0;
	dhdre->dccph_seq_low=htonl(seq);

	/*Checksums*/
	if(parms.ip_type==AF_INET){
		dhdr->dccph_checksum=ipv4_pseudohdr_chksum((buffer+ip_hdr_len), dccp_hdr_len,
				(unsigned char*) &parms.dest_addr.ipv4->sin_addr,
				(unsigned char*)&parms.src_addr.ipv4->sin_addr, IPPROTO_DCCP);
		ip4hdr->check=ipv4_chksum(buffer,ip_hdr_len);
	}else{
		dhdr->dccph_checksum=ipv6_pseudohdr_chksum((buffer+ip_hdr_len), dccp_hdr_len,
				(unsigned char*) &parms.dest_addr.ipv6->sin6_addr,
				(unsigned char*)&parms.src_addr.ipv6->sin6_addr, IPPROTO_DCCP);
	}
	*len=ip_hdr_len+dccp_hdr_len;
	return;
}

int logPacket(int req_seq, int packet_seq){
	struct request *tmp;

	/*Add new request to queue*/
	tmp=malloc(sizeof(struct request));
	if(tmp==NULL){
		dbgprintf(0,"Error: Can't allocate Memory!\n");
		exit(1);
	}
	tmp->next=NULL;
	tmp->prev=NULL;
	tmp->num_replies=0;
	tmp->num_errors=0;
	tmp->packet_seq=packet_seq;
	tmp->request_seq=req_seq;
	tmp->reply_type=UNKNOWN;
	gettimeofday(&tmp->sent,NULL);

	if(queue.head==NULL){
		queue.head=queue.tail=tmp;
	}else{
		queue.head->prev=tmp;
		tmp->next=queue.head;
		queue.head=tmp;
	}

	/*Update Statistics*/
	if(ping_stats.requests_sent==0){
		gettimeofday(&ping_stats.start,NULL);
	}
	ping_stats.requests_sent++;
	return 0;
}

int logResponse(ipaddr_ptr_t *src, int seq, int type){
	struct request *cur;
	double diff;

	if(queue.tail==NULL){
		dbgprintf(1,"Response received but no requests sent!\n");
		return -1;
	}

	/*Locate request*/
	cur=queue.tail;
	while(cur!=NULL){
		if(cur->packet_seq==seq){
			gettimeofday(&cur->reply,NULL);
			if(cur->num_replies>0){
				printf("Duplicate packet detected! (%i)\n",cur->request_seq);
			}
			if(type<DEST_UNREACHABLE && type!=UNKNOWN){
				cur->num_replies++;
			}else{
				cur->num_errors++;
			}
			cur->reply_type=type;
			break;
		}
		cur=cur->prev;
	}

	if(cur==NULL){
		if(parms.ip_type==AF_INET && seq==-1){
			/*IPv4 didn't include enough of the packet to get sequence numbers!*/
			printf("%s from %s\n",response_label[type],addr2str(src,0));
			ping_stats.errors++;
			return 0;
		}else{
			dbgprintf(1,"Response received but no requests sent with sequence number %i!\n", seq);
			return -1;
		}
	}

	diff=(cur->reply.tv_usec + 1000000*cur->reply.tv_sec) - (cur->sent.tv_usec + 1000000*cur->sent.tv_sec);
	diff=diff/1000.0;

	/*Print Message*/
	if(type<DEST_UNREACHABLE && type!=UNKNOWN){
		printf( "Response from %s : seq=%i  time=%.1fms  status=%s\n",
					addr2str(src,0),cur->request_seq, diff,response_label[type]);
	}else{
		printf("%s from %s : seq=%i\n",response_label[type],addr2str(src,0),cur->request_seq);
	}

	/*Update statistics*/
	if(type<DEST_UNREACHABLE && type!=UNKNOWN){
		/*Good Response*/
		if(cur->num_replies==1){
			ping_stats.rtt_avg=((ping_stats.replies_received*ping_stats.rtt_avg)+(diff))/(ping_stats.replies_received+1);
			ping_stats.replies_received++;
		}else{
			ping_stats.errors++;
		}
		if(diff < ping_stats.rtt_min || ping_stats.rtt_min==0){
			ping_stats.rtt_min=diff;
		}
		if(diff > ping_stats.rtt_max){
			ping_stats.rtt_max=diff;
		}
	}else{
		/*Error*/
		ping_stats.errors++;
	}
	gettimeofday(&ping_stats.stop,NULL);
	return 0;
}

void clearQueue(){
	struct request *cur;
	struct request *tmp;

	cur=queue.head;
	while(cur!=NULL){
		tmp=cur;
		cur=cur->next;
		free(tmp);
	}
	queue.head=NULL;
	queue.tail=NULL;
	return;
}

void sigHandler(){
	int diff;
	double ploss;

	/*Print Stats*/
	gettimeofday(&ping_stats.stop,NULL);
	printf("-----------%s PING STATISTICS-----------\n",parms.hostname);

	diff=(ping_stats.stop.tv_usec + 1000000*ping_stats.stop.tv_sec) -
			(ping_stats.start.tv_usec + 1000000*ping_stats.start.tv_sec);
	diff=diff/1000.0;
	ploss=(1.0*(ping_stats.requests_sent-ping_stats.replies_received)/ping_stats.requests_sent*1.0)*100;
	printf("%i packets transmitted, %i received, %i errors, %.2f%% loss, time %ims\n",
			ping_stats.requests_sent,ping_stats.replies_received,ping_stats.errors,
			ploss,diff);
	printf("rtt min/avg/max = %.1f/%.1f/%.1f ms\n",
			ping_stats.rtt_min,ping_stats.rtt_avg,ping_stats.rtt_max);


	/*Exit Quickly*/
	parms.count=0;
}

char* addr2str(ipaddr_ptr_t *res, int nores){
	int size;
	int ret;
	if (!res->gen->sa_family)
		return NULL;

	if(res->gen->sa_family==AF_INET){
		size=sizeof(struct sockaddr_in);
	}else if(res->gen->sa_family==AF_INET6){
		size=sizeof(struct sockaddr_in6);
	}else{
		return NULL;
	}
	if((ret=getnameinfo(res->gen, size,
			addr2str_buf, sizeof (addr2str_buf), 0, 0, NI_NUMERICHOST))<0){
		dbgprintf(0,"Error! %s\n",gai_strerror(ret));
	}

	if (parms.no_resolve||nores){
		return addr2str_buf;
	}else{
	    addr2nm_buf[0] = '\0';
	    getnameinfo(res->gen, size,
				addr2nm_buf, sizeof (addr2nm_buf), 0, 0, NI_IDN);
	    snprintf(addr2both_buf,1000," %s (%s)", addr2nm_buf[0] ? addr2nm_buf : addr2str_buf, addr2str_buf);
	    return addr2both_buf;
	}
	return NULL;
}

/*Usage information for program*/
void usage()
{
	dbgprintf(0, "dccpping: [-d] [-v] [-h] [-n] [-6|-4] [-c count] [-p port] [-i interval]\n");
	dbgprintf(0, "          [-t ttl] [-S srcaddress] remote_host\n");
	dbgprintf(0, "\n");
	dbgprintf(0, "          -d   Debug. May be repeated for aditional verbosity\n");
	dbgprintf(0, "          -v   Version information\n");
	dbgprintf(0, "          -h   Help\n");
	dbgprintf(0, "          -n   Numeric output only\n");
	dbgprintf(0, "          -6   Force IPv6 mode\n");
	dbgprintf(0, "          -4   Force IPv4 mode\n");
	exit(0);
}

void version(){
	dbgprintf(0, "dccpping version %.1f\nCopyright (C) 2012 Samuel Jero <sj323707@ohio.edu>\n", DCCPPING_VERSION);
	dbgprintf(0, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	dbgprintf(0, "This is free software, and you are welcome to\nredistribute it under certain conditions.\n");
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
