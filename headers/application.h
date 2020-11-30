#ifndef APPLICATION_H
#define APPLICATION_H
#include "analyseur.h"
#include "dns.h"
#include "transfer.h"
#include "dhcp.h"
#include "bootp.h"
#define POP    110
#define IMAP   143
#define SMTP   25
#define SMTPS  587
#define HTTP   80
#define DNS    53
#define HTTPS  443
#define TELNET 23
#define DHCP   67
#define FTPD   20
#define FTPC   21
#define MDNS 5353
#define ICMP 1
#define REQUEST 1
#define RESPONSE 0

bool get_app (const unsigned char *, int, int, int, int);
void treat_app (const unsigned char *, int, int, int, int);

#endif
