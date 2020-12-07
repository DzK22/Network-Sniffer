#ifndef ARP_H
#define ARP_H
#include "network.h"

void treat_arp(const unsigned char *, int, int);
void put_arp_opcode (int);

#endif
