#include <sys/types.h>
#include <arpa/inet.h>

/*
 * Infomation extract from packet
 */
struct  pkt_info {
    uint16_t    ether_type;
    char        *ether_type_name;
    struct  ip  *iphdr;
    struct  tcp *tcphdr;
};
typedef struct pkt_info *pkt_info_p;

/*
 * Function
 */
void print_ether(pkt_info_p pi, const u_char *bytes);
void print_ip(pkt_info_p pi, const u_char *bytes);
void print_arp(pkt_info_p pi, const u_char *bytes);
void print_rarp(pkt_info_p pi, const u_char *bytes);
void print_tcp(pkt_info_p pi, const u_char *bytes);
void print_udp(pkt_info_p pi, const u_char *bytes);
void print_icmp(pkt_info_p pi, const u_char *bytes);
void print_http(pkt_info_p pi, const u_char *bytes);

/*
 *
 *
 *  Ethernet Part
 *
 *
 */

#define	ETHER_ADDR_LEN      6       /* The number of bytes in an ethernet (MAC) address */
#define ETHER_HDRLEN        14      /* Length of 802.3 Ethernet header */
#define ETHERTYPE_LEN       2       /* Length of Type parameter */
#define ETHERTYPE_IP        0x0800  /* IP protocol */
#define ETHERTYPE_ARP       0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_RARP      0x8035  /* reverse Addr. resolution protocol */
#define ETHERTYPE_IPV6      0x86dd  /* IPv6 protocal */

struct	ether_header {
	uint8_t		ether_dhost[ETHER_ADDR_LEN];
	uint8_t		ether_shost[ETHER_ADDR_LEN];
	uint16_t	ether_type;//typedef unsigned short uint16_t;
};

/*
 *
 *
 *  IP Part
 *
 *
 */

/*
 * Definitions for convention
 */
#define	IPVERSION           4
#define	IP_MAXPACKET        65535	/* maximum packet size */
#define	MAXTTL              255		/* maximum time to live (seconds) */
#define	IPDEFTTL            64		/* default ttl, from RFC 1340 */
#define	IP_MSS              576		/* default maximum segment size */

/*
 * Definitions for IP type of service (ip_tos)
 */
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04

/*
 * Definitions for IP type of protocols (ip_p)
 */
#define	IPPROTO_ICMP		1		/* control message protocol */
#define	IPPROTO_IGMP		2		/* control message protocol */
#define IPPROTO_IPV4		4
#define	IPPROTO_TCP         6		/* tcp */
#define	IPPROTO_EGP         8		/* exterior gateway protocol */
#define IPPROTO_PIGP		9       /* gateway protocol */
#define	IPPROTO_UDP         17		/* user datagram protocol */
#define IPPROTO_IPV6		41

struct ip {
    //typedef unsigned char uint8_t;
	uint8_t		ip_vhl;             /* header length, version */
    #define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
    #define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	uint8_t		ip_tos;             /* type of service */
	uint16_t	ip_len;             /* total length */
	uint16_t	ip_id;              /* identification */
	uint16_t	ip_off;             /* fragment offset field */
    #define	IP_DF 0x4000			/* dont fragment flag */
    #define	IP_MF 0x2000			/* more fragments flag */
    #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	uint8_t		ip_ttl;             /* time to live */
	uint8_t		ip_p;               /* protocol */
	uint16_t	ip_sum;             /* checksum */
	struct in_addr    ip_src,ip_dst;      /* source and dest address */
} ;

/*
 *
 *
 *  TCP Part
 *
 *
 */

typedef uint32_t tcp_seq;

/*
 * TCP header(RFC 793)
 */
struct tcp {
	uint16_t	th_sport;		/* source port */
	uint16_t	th_dport;		/* destination port */
	tcp_seq		th_seq;			/* sequence number */
	tcp_seq		th_ack;			/* acknowledgement number */
	uint8_t		th_offx2;		/* data offset, rsvd */
	uint8_t		th_flags;
	uint16_t	th_win;			/* window */
	uint16_t	th_sum;			/* checksum */
	uint16_t	th_urp;			/* urgent pointer */
};

#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

/*
 * TCP flags
 */
#define	TH_FIN     0x01
#define	TH_SYN	   0x02
#define	TH_RST	   0x04
#define	TH_PUSH	   0x08
#define	TH_ACK	   0x10
#define	TH_URG	   0x20

#define FTP_PORT        21
#define SSH_PORT        22
#define TELNET_PORT     23
#define SMTP_PORT       25
#define DNS_PORT        53
#define HTTP_PORT       80

/*
 *
 *
 *  UDP Part
 *
 *
 */

/*
 * Udp protocol header(RFC 768)
 */
struct udp {
	uint16_t	uh_sport;		/* source port */
	uint16_t	uh_dport;		/* destination port */
	uint16_t	uh_ulen;		/* udp length */
	uint16_t	uh_sum;			/* udp checksum */
};


/*
 *
 *
 *  ARP Part
 *
 *
 */

#define ARPHRD_ETHER    1       /* ethernet hardware format */
#define ARPHRD_IEEE802  6       /* token-ring hardware format */
#define ARPHRD_ARCNET   7       /* arcnet hardware format */
#define ARPHRD_FRELAY   15      /* frame relay hardware format */
#define ARPHRD_ATM2225  19      /* ATM (RFC 2225) */
#define ARPHRD_STRIP    23      /* Ricochet Starmode Radio hardware format */
#define ARPHRD_IEEE1394 24      /* IEEE 1394 (FireWire) hardware format */

#define ARPOP_REQUEST   1       /* request to resolve address */
#define ARPOP_REPLY     2       /* response to previous request */
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#define ARPOP_REVREPLY  4       /* response giving protocol address */
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#define ARPOP_INVREPLY  9       /* response identifying peer */
#define ARPOP_NAK       10      /* NAK - only valif for ATM ARP */

struct  arp_pkthdr {
    uint16_t    ar_hrd;         /* format of hardware address */
    uint16_t    ar_pro;         /* format of protocol address */
    uint8_t     ar_hln;         /* length of hardware address */
    uint8_t     ar_pln;         /* length of protocol address */
    uint16_t    ar_op;          /* op */
	uint8_t     ar_sha[8];      /* sender hardware address */
	struct in_addr	ar_spa;         /* sender protocol address */
	uint8_t     ar_tha[8];      /* target hardware address */
	struct in_addr	ar_tpa;         /* target protocol address */
};

/*
 *
 *
 *  HTTP Part
 *
 *
 */

struct http {
    int o;
};
