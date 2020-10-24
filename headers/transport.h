#ifndef TRANSPORT_H
#define TRANSPORT_H
#include "analyseur.h"

void treat_transport(const unsigned char *, int, int *, int *, int *, int);
void treat_udp(const unsigned char *, int *, int *, int);
void treat_tcp(const unsigned char *, int *, int *, int *, int);
void treat_icmp();
#endif
