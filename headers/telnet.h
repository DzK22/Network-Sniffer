#ifndef TELNET_H
#define TELNET_H
#include "application.h"
//Options
#define NL 0
#define RECON 2
#define ECHO 1
#define SGO_AHEAD 3
#define STS 5
#define TMG_MARK 6
#define LINE_WIDTH 8
#define T_TYPE 24
#define W_SIZE 31
#define T_SPEED 32
#define REM_FCTRL 33
#define LINE_MODE 34
#define ENV_VAR 26

//Commandes
#define SEND 240 //Fin subgnegoc
#define NNOP 241
#define DM 242
#define BRK 243
#define IP 244
#define AO 245
#define AYT 246
#define EC 247
#define EL 248
#define GA 249
#define SBEGIN 250 //Début subgnegoc
#define WILL 251
#define WONT 252
#define DO 253
#define DONT 254
#define IAC 255


void treat_telnet (const unsigned char *, int, int);
void negoc(const unsigned char *, int);
void put_opt (int);

#endif
