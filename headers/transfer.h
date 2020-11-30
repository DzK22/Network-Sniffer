#ifndef TRANSFER_H
#define TRANSFER_H
#include "application.h"
/*Fichiers pour gérer les protocoles de transfert de la couche applicative (HTTP/FTP/SMTP...etc)*/
void treat_transfer (const unsigned char *, bool, int, int, int);
#endif
