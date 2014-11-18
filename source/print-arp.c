#include <stdio.h>
#include "sniffer.h"
void print_arp(pkt_info_p pi, const u_char *bytes) {
    struct arp_pkthdr *ap;
    uint8_t ar_hln, ar_pln;
    uint16_t ar_hrd, ar_pro, ar_op;
    int i;
    char *temp;
    
    ap      =   (struct arp_pkthdr *)(bytes + ETHER_HDRLEN);
    ar_hrd  =   ntohs(ap->ar_hrd);
    ar_pro  =   ntohs(ap->ar_pro);
    ar_hln  =   ap->ar_hln;
    ar_pln  =   ap->ar_pln;
    ar_op   =   ntohs(ap->ar_op);
    
    printf("ARP: ");
    //1.hardware type
    switch (ar_hrd) {
        case ARPHRD_ETHER:
            printf("Hardware type-Ethernet(1), ");
            break;
        default:
            printf("Undefined hardware format(ARP).\n");
            break;
    }
    //2.protocol type
    switch (ar_pro) {
        case ETHERTYPE_IP:
            printf("Protocol type-IP(0x0800), ");
            break;
        default:
            printf("Undefined protocol type for arp.\n");
            break;
    }
    //3.hardware&protocol length
    printf("Hardware Address size %u, Protocol Address size %u, ", ar_hln, ar_pln);
    //4.op
    switch (ar_op) {
        case ARPOP_REQUEST:
            printf("REQUEST, ");
            break;
        case ARPOP_REPLY:
            printf("REPLY, ");
            break;
        case ARPOP_REVREQUEST:
            printf("REVREQUEST, ");
            break;
        case ARPOP_REVREPLY:
            printf("REVREPLY, ");
            break;
        case ARPOP_INVREQUEST:
            printf("REQUEST, ");
            break;
        case ARPOP_INVREPLY:
            printf("INVREPLY, ");
            break;
        case ARPOP_NAK:
            printf("NAK, ");
            break;
        default:
            break;
    }
    //5.address
    temp = inet_ntoa(ap->ar_spa);
    printf("source-");
    for (i = 0; i < ETHER_ADDR_LEN ; i++) {
        if (i < 5)
            printf("%x:", ap->ar_sha[i]);
        else
            printf("%x", ap->ar_sha[i]);
    }
    printf("(%s), target-", temp);
    
    temp = inet_ntoa(ap->ar_tpa);
    for (i = 0; i < ETHER_ADDR_LEN ; i++) {
        if (i < 5)
            printf("%x:", ap->ar_tha[i]);
        else
            printf("%x", ap->ar_tha[i]);
    }
    printf("(%s)\n", temp);
    
}