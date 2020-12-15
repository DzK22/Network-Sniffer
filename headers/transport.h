#ifndef TRANSPORT_H
#define TRANSPORT_H
#include "analyseur.h"
#include "ospf.h"
#define TCP 6
#define UDP 17
#define OSPF 89
#define NOP 1
#define MSS 2
#define WS 3
#define SACKP 4
#define SACK 5
#define TS 8

void treat_transport(const unsigned char *, int, int *, int *, int *, int);
void treat_udp(const unsigned char *, int *, int *, int);
void treat_tcp(const unsigned char *, int *, int *, int *, int);
void treat_icmp();
#endif
