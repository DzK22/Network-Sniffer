#ifndef NETWORK_H
#define NETWORK_H
#include "analyseur.h"
#define IPV6_LENGTH 40

char* get_protocol(int);
void threat_network(const unsigned char *, int, int *, unsigned *, int);
int threat_ipv4(const unsigned char *, int);
int threat_ipv6(const unsigned char *, int);

#endif
