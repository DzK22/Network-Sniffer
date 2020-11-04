#ifndef DHCP_H
#define DHCP_H
#include "application.h"

void treat_bootp (const unsigned char *, int);
bool is_dhcp (const unsigned char *);

#endif
