#ifndef structures
#define structures

#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
//#include <netinet/tcp_seq.h>

#define ETHER_ADDR_LEN	6
typedef u_int tcp_seq;

#pragma pack(push,1)
struct ether_header {
	unsigned char dhost[ETHER_ADDR_LEN];	// Destination host address
	unsigned char shost[ETHER_ADDR_LEN];	// Source host address
	unsigned short type;			// IP? ARP? RARP? etc
};
#pragma pack(pop)



#pragma pack(push,1)
struct ip_header {
	unsigned char	vhl;		// version << 4 | header length >> 2
	unsigned char	tos;		// type of service
	unsigned short	len;		// total length
	unsigned short	id;			// identification
	unsigned short	off;		// fragment offset field
	unsigned char	ttl;		// time to live
	unsigned char	prot;		// protocol
	unsigned short	sum;		// checksum
	struct in_addr src;
	struct in_addr dst;	// source and dest address 
};
#pragma pack(pop)


#pragma pack(push,1)
struct udp_header {
	unsigned short	sport;		// source port
	unsigned short	dport;		// destination port
	unsigned short	length;		// udp length
	unsigned short	checksum;	// udp checksum
};
#pragma pack(pop)

#pragma pack(push,1)
struct tcp_header {
	unsigned short	sport;	// source port
	unsigned short	dport;	// destination port
	tcp_seq	seq;	// sequence number
	tcp_seq	ack;	// acknowledgement number
	unsigned char	offx2;	// data offset, rsvd
	unsigned char	flags;
	unsigned short	win;	// window
	unsigned short	sum;	// checksum
	unsigned short	urp;	// urgent pointer
};
#pragma pack(pop)


/*
http://www.nersc.gov/~scottc/software/snort/dns_head.html

Header
Question
Answer
Authority
Additional
*/

#pragma pack(push,1)
struct dns_header {
	unsigned short id;
	unsigned short flags;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
};
#pragma pack(pop)


/*
Resourse record
NAME		Name of the node to which this record pertains.	(variable)
TYPE		Type of RR. For example, MX is type 15.	2
CLASS		Class code.	2
TTL		Unsigned time in seconds that RR stays valid, maximum is 2147483647.	4
RDLENGTH	Length of RDATA field.	2
RDATA		Additional RR-specific data.	(variable)
*/


#pragma pack(push,1)
typedef struct {
	uint16_t type;
	uint16_t clas;
	uint32_t ttl;
	uint16_t rdlength;
} static_RR;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct {
	struct ether_header eth;
	struct ip_header ip;
	struct udp_header udp;
	struct dns_header dns;
	char data[0];
} packet_desc_old;
#pragma pack(pop)


#pragma pack(push,1)
/* The radio capture header precedes the 802.11 header. */
struct ieee80211_radiotap_header {
        uint8_t        version;     
        uint8_t        pad;
        uint16_t       len;         
        uint32_t       present;
	struct in_addr src;
	struct in_addr dst;
};
#pragma pack(pop)


#pragma pack(push,1)
struct llc_header {
	uint8_t llc[8];
};
#pragma pack(pop)



#pragma pack(push,1)
typedef struct {
	struct ieee80211_radiotap_header wifi;
	struct llc_header llc;
	struct ip_header ip;
	struct udp_header udp;
	struct dns_header dns;
	char data[0];
} packet_desc;
#pragma pack(pop)

#endif
