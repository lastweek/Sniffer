#include <stdio.h>
#include "sniffer.h"

/*
 Flags:
 { TH_FIN, "F" },
 { TH_SYN, "S" },
 { TH_RST, "R" },
 { TH_PUSH, "P" },
 { TH_ACK, "." },
 { TH_URG, "U" },
 */

void print_tcp(pkt_info_p pi, const u_char *bytes){
    struct tcp *tcphdr;
    uint8_t flag;
    uint16_t win, sport, dport;
    tcp_seq seq, ack;
    
    tcphdr      =   (struct tcp *)(bytes + ETHER_HDRLEN + IP_HL(pi->iphdr) * 4);
    pi->tcphdr  =   tcphdr;
    sport       =   ntohs(tcphdr->th_sport);
    dport       =   ntohs(tcphdr->th_dport);
    flag        =   tcphdr->th_flags & 0x3f;
    seq         =   ntohl(tcphdr->th_seq);
    ack         =   ntohl(tcphdr->th_ack);
    win         =   ntohs(tcphdr->th_win);
    
    //1.port
    printf("TCP: %u > %u, ", sport, dport);
    //2.flags
    printf("Flags[");
    switch (flag) {
        //use %u to print unsigned variables.
        case TH_ACK:
            printf(".], ack %u, ", ack);
            break;
        case TH_SYN:
            printf("S], seq %u, ", seq);
            break;
        case TH_URG:
            printf("U], seq %u, ack %u, ", seq, ack);
            break;
        case (TH_URG|TH_ACK):
            printf("U.], seq %u, ack %u, ", seq, ack);
            break;
        case (TH_ACK|TH_SYN):
            printf("S.], seq %u, ack %u, ", seq, ack);
            break;
        case (TH_ACK|TH_FIN):
            printf("F.], seq %u, ack %u, ", seq, ack);
            break;
        case (TH_ACK|TH_PUSH):
            printf("P.], seq %u, ack %u, ", seq, ack);
            break;
        case TH_RST:
            printf("R], seq %u, ", seq);
            break;
        case (TH_SYN|TH_PUSH|TH_RST):
            printf("SPR], seq %u, ack %u, ", seq, ack);
            break;
        default:
            printf("Undefined Flag=%x\n",flag);
            break;
    }
    //3.window
    printf("win %u, ", win);
    //4.Application Layer
    if ((sport == HTTP_PORT) || (dport == HTTP_PORT)) {
        print_http(pi, bytes);
    }
    
}
