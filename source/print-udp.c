#include <stdio.h>
#include "sniffer.h"
void print_udp(pkt_info_p pi, const u_char *bytes){
    struct udp * udphdr;
    uint16_t uh_sport, uh_dport, uh_ulen;
    
    udphdr      =   (struct udp *)(bytes + ETHER_HDRLEN + IP_HL(pi->iphdr) * 4);
    uh_sport    =   ntohs(udphdr->uh_sport);
    uh_dport    =   ntohs(udphdr->uh_dport);
    uh_ulen     =   ntohs(udphdr->uh_ulen);
    
    //1.port
    printf("UDP: %u > %u, ", uh_sport, uh_dport);
    
    /*
     *      Future Work
     *  Classify each port, then deliver to each print-xxx.
     *
     */
    
    
    //2.length
    printf("length %u\n", uh_ulen);
}
