#ifndef DDNS_H
#define DDNS_H
#include "application.h"

#define PTRMASK 0b11000000
#define PTRINDEXMASK 0b00111111
#define IN 1
#define CS 2
#define CH 3
#define HS 4
#define SOA 6

void treat_dns (const unsigned char *, int, int);
void put_opcode (unsigned);
void put_rcode (unsigned);
unsigned resolve (const unsigned char *, const unsigned char *);
void dns_print(const char *, const unsigned char *, const unsigned char *, u_int16_t, bool);
char *get_class (u_int16_t);
char *get_type (u_int16_t);

struct q_datas {
    u_int16_t type;
    u_int16_t clss;
};

//Ressources Records {RFC 1035}
struct r_datas   {
    u_int16_t type;
    u_int16_t clss;
    u_int32_t ttl;
    u_int16_t len;
};
#endif
