#ifndef APPLICATION_H
#define APPLICATION_H
#include "analyseur.h"
#include "dns.h"
#include "transfer.h"
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
#define TCP 6
#define UDP 17
#define ICMP 1
#define REQUEST 0x1005
#define RESPONSE 0x995

bool get_app (const unsigned char *, int, int, int, int);
void treat_app (const unsigned char *, int, int, int *, int, int);

#endif
