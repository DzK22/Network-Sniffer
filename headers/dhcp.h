#ifndef DHCP_H
#define DHCP_H
#include "application.h"

void treat_bootp (const unsigned char *, int);
void print_dhcp (const unsigned char *, int);
u_int32_t get_time (const unsigned char *, int);
char *get_dhcp_type (int);

#endif
