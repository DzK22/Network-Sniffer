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

#if __BYTE_ORDER == __LITTLE_ENDIAN
    #define DESERIALIZE_UINT8TO32(_UINT8_ARRAY, i) (0x0 | _UINT8_ARRAY[i + 3] << 24 | _UINT8_ARRAY[i + 2] << 16 | _UINT8_ARRAY[i + 1] << 8 | _UINT8_ARRAY[i + 0])
#elif __BYTE_ORDER == __BIG_ENDIAN
    #define DESERIALIZE_UINT8TO32(_UINT8_ARRAY, i) (0x0 | _UINT8_ARRAY[i + 0] << 24 | _UINT8_ARRAY[i + 1] << 16 | _UINT8_ARRAY[i + 2] << 8 | _UINT8_ARRAY[i + 3])
#endif

void treat_transport(const unsigned char *, int, int *, int *, int *, int);
void treat_udp(const unsigned char *, int *, int *, int);
void treat_tcp(const unsigned char *, int *, int *, int *, int);
void treat_icmp();
#endif
