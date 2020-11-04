#ifndef TRANSFER_H
#define TRANSFER_H
#include "application.h"
/*Fichiers pour gérer les protocoles de transfert de la couche applicative (HTTP/FTP/SMTP...etc)*/
/*Fonctions HTTP/HTTPS*/
void treat_https (const unsigned char *, int, int, int);
/*Fin fonctions HTTP/HTTPS*/
#endif
