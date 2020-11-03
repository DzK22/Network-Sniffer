#ifndef TRANSPORT_H
#define TRANSPORT_H
#include "analyseur.h"
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
void put_tcp_options (int);
#endif
