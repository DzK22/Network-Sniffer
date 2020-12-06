#ifndef ICMP_H
#define ICMP_H
#include "network.h"

void treat_icmp (const unsigned char *, int);
void put_type(u_int8_t);

#endif
