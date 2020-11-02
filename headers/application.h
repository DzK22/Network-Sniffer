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
#define DNOERROR 0
#define DFORMERR 1
#define DSERVFAIL 2
#define DNXDOMAIN 3
#define DNOTIMP 4
#define DREFUSED 5
#define DYXDOMAIN 6
#define DXRRSET 7
#define DNOTAUTH 8
#define DNOTZONE 9

#define PTRMASK 0b11000000
#define PTRVALUE 192
#define PTRINDEXMASK 0b0011111111111111

bool get_app (const unsigned char *, int, int, int, int);
void treat_app (const unsigned char *, int, int, int *, int, int);
void treat_https (const unsigned char *, int, int, int);
void treat_dns (const unsigned char *, int);
void put_opcode (unsigned);
void put_rcode (unsigned);
unsigned get_name (const unsigned char *, const unsigned char *);

struct q_datas {
    u_int16_t type;
    u_int16_t clss;
};

#endif
