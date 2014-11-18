#include <stdio.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "sniffer.h"

/*
 * extern getopt() variables.
 */
extern char *optarg;
extern int optind;

/*
 * System defined variable.
 */
static int buffer_size	=	65535;
static int packet_count	=	-1;
static int time_out     =   1000;

int Aflag   =   0;  //  Application
int Bflag   =   0;	//	Buffer size.
int Cflag   =   0;	//	Packet Count.
int Dflag   =   0;	//	list available Devices and exit.
int Eflag   =   0;  //  print Ethernet header.
int Iflag   =   0;  //	Interface specific.
int Mflag   =   0;  //  proMiscuous
int Rflag   =   0;	//	Read packet from file.
int Vflag   =   0;  //  Verbose print IP hdr.
int Wflag   =   0;	//	Write packet to file.

static pcap_t *pd;

char *copy_argv(char **argv);
void err(char *s);
void usage();
void print_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
static void ifprint(pcap_if_t *d);
static char *iptos(bpf_u_int32 in);
void printalldevs();

int main(int argc, char **argv) {
	char *cmdbuf, *dev, *RPathname, *WPathname, *cp;
    unsigned char *temp;
    char ebuf[PCAP_ERRBUF_SIZE];
	int op, status, user;
    bpf_u_int32 localnet, netmask;
    struct bpf_program fcode;
    struct in_addr addr, mask;
    
    cmdbuf      =   NULL;
    dev         =   NULL;
    RPathname   =   NULL;
    WPathname   =   NULL;
    temp        =   NULL;
    op          =   0;
    status      =   0;
    localnet    =   0;
    netmask     =   0;
    user        =   0;
    
	while ((op = getopt(argc, argv, "ahdmveb:c:r:w:i:")) != -1) {
		switch (op) {
            case 'a':
                Aflag=1;
                break;
			case 'b':
                Bflag=1;
                if(Bflag)
                    buffer_size=atoi(optarg);
                if (buffer_size < 0) {
                    usage();
                }
                break;
			case 'c':
                Cflag=1;
                if(Cflag)
                    packet_count=atoi(optarg);
                if (packet_count < -1) {
                    usage();
                }
                break;
			case 'd':
                Dflag=1;
                break;
            case 'e':
                Eflag=1;
                break;
			case 'i':
                Iflag=1;
                dev=optarg;
                break;
            case 'm':
                Mflag=1;
                break;
			case 'r':
                Rflag=1;
                RPathname=optarg;
                break;
            case 'v':
                Vflag=1;
                break;
			case 'w':
                Wflag=1;
                WPathname=optarg;
                break;
            case 'h':
                usage();
                break;
			case '?':
                usage();
                break;
			default :
                usage();
                break;
		}
	}
    
    cmdbuf = copy_argv(&argv[optind]);
    
    if (Dflag) {
        printalldevs();
    }
    
    if (!Iflag) {
        dev = pcap_lookupdev(ebuf);
        if (dev == NULL) {
            err(ebuf);
        }
    }
    *ebuf = '\0';
    
    if (Rflag) {
        //Read from "savefile"
    }
    else {
        pd = pcap_create(dev, ebuf);
        if (pd == NULL)
            err(ebuf);
    }
    if (pcap_set_snaplen(pd, 65535) != 0) {
        err(ebuf);
    }
    if (pcap_set_timeout(pd, time_out) != 0) {
        err(ebuf);
    }
    if (pcap_set_buffer_size(pd, buffer_size) != 0 ) {
        err(ebuf);
    }
    if (pcap_set_promisc(pd, Mflag) != 0) {
        printf("can't set promiscuous\n");
        err(ebuf);
    }
    
    status = pcap_activate(pd);
    if (status < 0) {
        /*
         * pcap_activate() failed
         */
        err(ebuf);
    }
    else if (status > 0) {
        /*
         * pcap_activate() succeeded, but it's warning us
         * of a problem it had.
         */
        cp = pcap_geterr(pd);
        if (status == PCAP_WARNING)
            printf("%s\n", cp);
        else if (status == PCAP_WARNING_PROMISC_NOTSUP &&
                 *cp != '\0')
            printf("%s: %s\n(%s)", dev, pcap_statustostr(status), cp);
        else
            printf("%s: %s", dev, pcap_statustostr(status));
    }
    
    if (pcap_lookupnet(dev, &localnet, &netmask, ebuf) < 0) {
        localnet = 0;
        netmask = 0;
        printf("%s\n", ebuf);
    }
    addr.s_addr = localnet;
    mask.s_addr = netmask;
    printf("addr:%s\t", inet_ntoa(addr));
    printf("mask:%s\n", inet_ntoa(mask));
    
    status = pcap_compile(pd, &fcode, cmdbuf, 1, netmask);
    if (status < 0) {
        cp = pcap_geterr(pd);
        err(cp);
    }
    if (pcap_setfilter(pd, &fcode) < 0)
		err(ebuf);
    
    pcap_freecode(&fcode);
	printf("Listening on %s\n\n", dev);
    
    pcap_loop(pd, packet_count, print_packet, (u_char *)&user);
    
	return 0;
}


// Copy arg vector into a new buffer, concatenating arguments with spaces.
char *copy_argv(char **argv) {
	char **p;
	u_int len = 0;
	char *buf;
	char *src, *dst;
    
	p = argv;
	if (*p == 0)
		return 0;
    
	while (*p){
		len += strlen(*p++) + 1;
    }
	buf = (char *)malloc(len);
	if (buf == NULL) {
		printf("copy_argv: malloc\n");
        exit(0);
    }
    p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';
    
	return buf;
}


void err(char *s) {
    /*
     va_list ap;
     
     va_start(ap, fmt);
     (void)vfprintf(stderr, fmt, ap);
     va_end(ap);
     if (*fmt) {
     fmt += strlen(fmt);
     if (fmt[-1] != '\n')
     (void)fputc('\n', stderr);
     }
     exit(1);
     */
    printf("%s\n",s);
    exit(0);
}

void usage() {
    printf("Usage: sniff [-ahdmve] [-b buffer_size] [-c packet_count]\n\t\t\t[-i dev] [-r file] [-w file]\n\t\t\t[expression]");
    printf("\n\t\ta:print Application\n\t\td:list all variable Devices\n\t\tm:set proMiscuous\n\t\tv:print IP header Verbose\n\t\te:print Ethernet header\n");
    exit(0);
}

void print_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
    int *id;
    struct ether_header *ehp;
    pkt_info_p pi;
    
    id  =   (int *)user;
    ehp =   (struct ether_header *)bytes;
    pi  =   (pkt_info_p)malloc(sizeof(struct pkt_info));
    
    printf("COUNT: %d\t", ++(*id));
    printf("Packet length: %d\t", h->len);
    /*printf("Capture length: %d\t", h->caplen); */
    printf("Recieved time: %s\n", ctime((const time_t *)&h->ts.tv_sec));
    
    print_ether(pi, bytes);
    
    /*
     for(i=0;i < h->len;i++) {
     printf(" %02x", bytes[i]);
     if((i + 1)%16 == 0) {
     printf("\n");
     }
     }
     */
    
    free(pi);
    printf("\n\n");
}

void printalldevs() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char *s;
    bpf_u_int32 net, mask;
    
    char errbuf[PCAP_ERRBUF_SIZE+1];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
        exit(1);
    }
    for(d=alldevs;d;d=d->next) {
        ifprint(d);
    }
    
    if ( (s = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr,"Error in pcap_lookupdev: %s\n",errbuf);
    }
    else {
        printf("Preferred device name: %s\n",s);
    }
    
    if (pcap_lookupnet(s, &net, &mask, errbuf) < 0) {
        fprintf(stderr,"Error in pcap_lookupnet: %s\n",errbuf);
    }
    else {
        printf("Preferred device is on network: %s/%s\n",iptos(net), iptos(mask));
    }
    
    exit(0);
}

static void ifprint(pcap_if_t *d) {
    pcap_addr_t *a;
#ifdef INET6
    char ntop_buf[INET6_ADDRSTRLEN];
#endif
    
    printf("%s\n",d->name);
    if (d->description)
        printf("\tDescription: %s\n",d->description);
    printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");
    
    for(a=d->addresses;a;a=a->next) {
        switch(a->addr->sa_family)
        {
            case AF_INET:
                printf("\tAddress Family: AF_INET\n");
                if (a->addr)
                    printf("\t\tAddress: %s\n",
                           inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
                if (a->netmask)
                    printf("\t\tNetmask: %s\n",
                           inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr));
                if (a->broadaddr)
                    printf("\t\tBroadcast Address: %s\n",
                           inet_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr));
                if (a->dstaddr)
                    printf("\t\tDestination Address: %s\n",
                           inet_ntoa(((struct sockaddr_in *)(a->dstaddr))->sin_addr));
                break;
#ifdef INET6
            case AF_INET6:
                printf("\tAddress Family: AF_INET6\n");
                if (a->addr)
                    printf("\t\tAddress: %s\n",
                           inet_ntop(AF_INET6,
                                     ((struct sockaddr_in6 *)(a->addr))->sin6_addr.s6_addr,
                                     ntop_buf, sizeof ntop_buf));
                if (a->netmask)
                    printf("\t\tNetmask: %s\n",
                           inet_ntop(AF_INET6,
                                     ((struct sockaddr_in6 *)(a->netmask))->sin6_addr.s6_addr,
                                     ntop_buf, sizeof ntop_buf));
                if (a->broadaddr)
                    printf("\t\tBroadcast Address: %s\n",
                           inet_ntop(AF_INET6,
                                     ((struct sockaddr_in6 *)(a->broadaddr))->sin6_addr.s6_addr,
                                     ntop_buf, sizeof ntop_buf));
                if (a->dstaddr)
                    printf("\t\tDestination Address: %s\n",
                           inet_ntop(AF_INET6,
                                     ((struct sockaddr_in6 *)(a->dstaddr))->sin6_addr.s6_addr,
                                     ntop_buf, sizeof ntop_buf));
                break;
#endif
            default:
                printf("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
                break;
        }
    }
    printf("\n");
}

/* From tcptraceroute */
#define IPTOSBUFFERS	12
static char *iptos(bpf_u_int32 in) {
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;
    
	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

