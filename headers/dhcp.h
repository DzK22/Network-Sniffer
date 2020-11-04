#ifndef DHCP_H
#define DHCP_H
#include "application.h"
#define IP_TYPE {TAG_SUBNET_MASK, TAG_SERVER_ID}

void treat_bootp (const unsigned char *, int);
bool is_dhcp (const unsigned char *);
void print_dhcp (const unsigned char *, int);
void put_dhcp_options (int);
u_int32_t get_time (const unsigned char *, int);
int *get_ip (const unsigned char *, int);
char *get_dhcp_type (int);

#endif
