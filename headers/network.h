#ifndef NETWORK_H
#define NETWORK_H
#include "analyseur.h"
#define IPV6_LENGTH 40

struct c_arphdr {
    u_char ar_sha[ETH_ALEN];
    u_char ar_tha[ETH_ALEN];
    u_char ar_sip[4];
    u_char ar_tip[4];
};

char* get_protocol(int);
void treat_network(const unsigned char *, int, int *, unsigned *, int);
int treat_ipv4(const unsigned char *, int);
void treat_ipv6(const unsigned char *, int);
void treat_arp(const unsigned char *, int);
void put_arp_opcode (int);

#endif
