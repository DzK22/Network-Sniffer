#ifndef NETWORK_H
#define NETWORK_H
#include "analyseur.h"
#define IPV6_LENGTH 40

int threat_ipv4(const unsigned char *, int, unsigned *);
int threat_ipv6(const unsigned char *, int, unsigned *);

#endif
