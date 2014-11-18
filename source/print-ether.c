#include <stdio.h>
#include <arpa/inet.h>
#include "sniffer.h"

extern int Eflag;

void print_ether(pkt_info_p pi, const u_char *bytes) {
    int i;
    uint16_t ether_type;
    struct ether_header *ehp;
    
    ehp             =   (struct ether_header *)bytes;
    ether_type      =   ntohs(ehp->ether_type);
    pi->ether_type  =   ether_type;
    
    /* print link-layer info */
    if (Eflag) {
        for (i = 0; i < ETHER_ADDR_LEN ; i++) {
            if (i < 5)
                printf("%x:", ehp->ether_shost[i]);
            else
                printf("%x > ", ehp->ether_shost[i]);
        }
        for (i = 0; i < ETHER_ADDR_LEN ; i++) {
            if (i < 5)
                printf("%x:", ehp->ether_dhost[i]);
            else
                printf("%x, ", ehp->ether_dhost[i]);
        }
    }
    
    switch (ether_type) {
        case ETHERTYPE_IP:
            if (Eflag)
                printf("Ethertype IPV4(0x%x); ", ETHERTYPE_IP);
            pi->ether_type_name = "IP";
            print_ip(pi, bytes);
            break;
        case ETHERTYPE_ARP:
            if (Eflag)
                printf("Ethertype ARP(0x%x); ", ETHERTYPE_ARP);
            pi->ether_type_name = "ARP";
            print_arp(pi, bytes);
            break;
        case ETHERTYPE_RARP:
            if (Eflag)
                printf("Ethertype RARP(0x%x); ", ETHERTYPE_RARP);
            pi->ether_type_name = "RARP";
            print_rarp(pi, bytes);
            break;
        case ETHERTYPE_IPV6:
            printf("Ethertype IPv6(0x%x)\n", ETHERTYPE_IPV6);
            pi->ether_type_name = "RARP";
            break;
        default:
            printf("Undefined Ethertype(0x%x)\n",ether_type);
            break;
    }
}
