#include <stdio.h>
#include "sniffer.h"

extern int Aflag;
void print_http(pkt_info_p pi, const u_char *bytes) {
    struct http *hp;
    const u_char *temp;
    temp    =   (bytes + ETHER_HDRLEN + IP_HL(pi->iphdr) * 4 + TH_OFF(pi->tcphdr) * 4);
    hp      =   (struct http *)temp;
    if (Aflag)
    {
    	printf("\nHTTP: %s\n", temp);
    }
    
}
