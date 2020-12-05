#ifndef APPLICATION_H
#define APPLICATION_H
#include "analyseur.h"
#include "dns.h"
#include "transfer.h"
#include "dhcp.h"
#include "bootp.h"
#include "telnet.h"
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
#define ICMP 1
#define MDNS 5353

bool get_app (const unsigned char *, int, bool, int, int);
void treat_app (const unsigned char *, int, int, int, int);
int c_print(char);
void print(const unsigned char*, int);

#endif
