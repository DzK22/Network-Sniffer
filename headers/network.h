#ifndef NETWORK_H
#define NETWORK_H
#include "analyseur.h"
#include "ip.h"
#include "arp.h"
#define IPV6_LENGTH 40

void treat_network(const unsigned char *, int, int *, int *, int, int *);

#endif
