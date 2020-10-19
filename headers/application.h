#ifndef APPLICATION_H
#define APPLICATION_H
#include "analyseur.h"
#define REQUEST 0x1005
#define RESPONSE 0x995

bool get_app (const unsigned char *, int, int, int, int);
void treat_app (const unsigned char *, int, int, unsigned *, int, int);
void treat_https (const unsigned char *, int, int);
#endif
