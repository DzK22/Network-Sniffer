#ifndef TRANSPORT_H
#define TRANSPORT_H
#include "analyseur.h"

void threat_transport(const unsigned char *, int, int *, int *, unsigned *, int);
void threat_udp(const unsigned char *, int *, int *, int);
void threat_tcp(const unsigned char *, unsigned *, int *, int *, int);
void threat_icmp();
#endif
