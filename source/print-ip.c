#include <stdio.h>
#include "sniffer.h"
extern int Vflag;
void print_ip(pkt_info_p pi, const u_char *bytes) {
    struct ip *iphdr;
    char *temp;
    
    iphdr       =   (struct ip *)(bytes+ETHER_HDRLEN);
    pi->iphdr   =   iphdr;
    
    temp    =   inet_ntoa(iphdr->ip_src);
    printf("%s > ",temp);
    temp    =   inet_ntoa(iphdr->ip_dst);
    printf("%s ",temp);
    
    if (Vflag) {
        /* print description about IP header */
    }
    
    switch (iphdr->ip_p) {
        case IPPROTO_TCP:
            print_tcp(pi, bytes);
            break;
        case IPPROTO_UDP:
            print_udp(pi, bytes);
            break;
        case IPPROTO_ICMP:
            printf("IP->ICMP; ");
            print_icmp(pi, bytes);
            break;
        case IPPROTO_EGP:
            printf("IP->EGP\n");
            break;
        case IPPROTO_IPV6:
            printf("IP->IPV6\n");
            break;
        default:
            printf("Undefined IP protocol(0x%x)\n", iphdr->ip_p);
            break;
    }
    
}