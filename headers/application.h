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
#define IN 1
#define CS 2
#define CH 3
#define HS 4

#define SOA 6
#define A 1
#define AAAA 28
#define NS 2
#define PTR 12
#define MX 15
#define CNAME 5
#define TXT 16
#define HINFO 13

bool get_app (const unsigned char *, int, int, int, int);
void treat_app (const unsigned char *, int, int, int *, int, int);
void treat_https (const unsigned char *, int, int, int);

/*Fonctions DNS*/
void treat_dns (const unsigned char *, int);
void put_opcode (unsigned);
void put_rcode (unsigned);
unsigned resolve (const unsigned char *, const unsigned char *);
void dns_print(const char *, const unsigned char *, const unsigned char *, u_int16_t);
char *get_class (u_int16_t);
char *get_type (u_int16_t);
/*Fin Fonctions DNS*/

struct q_datas {
    u_int16_t type;
    u_int16_t clss;
};

struct m_datas   {
    u_int16_t type;
    u_int16_t clss;
    u_int32_t ttl;
    u_int16_t len;
};

#endif
