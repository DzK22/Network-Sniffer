#ifndef ARP_H
#define ARP_H
#include "network.h"

/*struct c_arphdr {
    unsigned short int ar_hrd;
    unsigned short int ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    unsigned short int ar_op;
    struct ether_addr ar_sha;
    struct in_addr ar_sip;
    struct ether_addr ar_tha;
    struct in_addr ar_tip;
};*/

void treat_arp(const unsigned char *, int);
void put_arp_opcode (int);

#endif
