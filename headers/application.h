#ifndef APPLICATION_H
#define APPLICATION_H
#include "analyseur.h"
#include "dns.h"
#include "transfer.h"
#define REQUEST 0x1005
#define RESPONSE 0x995

bool get_app (const unsigned char *, int, int, int, int);
void treat_app (const unsigned char *, int, int, int *, int, int);

#endif
