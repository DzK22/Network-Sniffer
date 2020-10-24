#ifndef NETWORK_H
#define NETWORK_H
#include "analyseur.h"
#define IPV6_LENGTH 40

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

char* get_protocol(int);
void treat_network(const unsigned char *, int, int *, int *, int, int *);
int treat_ipv4(const unsigned char *, int, int *, int *);
void treat_ipv6(const unsigned char *, int);
void treat_arp(const unsigned char *, int);
void put_arp_opcode (int);

#endif
