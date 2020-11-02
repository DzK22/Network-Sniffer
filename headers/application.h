#ifndef APPLICATION_H
#define APPLICATION_H
#include "analyseur.h"
#define REQUEST 0x1005
#define RESPONSE 0x995
#define DNSQUERY 0
#define DNSIQUERY 1
#define DNSSSR 2
#define DNSNOTIFY 4
#define DNSUPDATE 5

bool get_app (const unsigned char *, int, int, int, int);
void treat_app (const unsigned char *, int, int, int *, int, int);
void treat_https (const unsigned char *, int, int, int);
void treat_dns (const unsigned char *, int);
#endif
