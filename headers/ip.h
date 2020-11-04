#ifndef IP_H
#define IP_H
#include "network.h"

uint8_t treat_ipv4(const unsigned char *, int, int *, int *);
uint8_t treat_ipv6(const unsigned char *, int);
char* get_protocol(int);

#endif
