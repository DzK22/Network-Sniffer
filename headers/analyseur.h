#ifndef ANALYSEYR_H
#define ANALYSEUR_H
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <unistd.h>
#include "liaison.h"
#include "network.h"


#define V3 3
#define V2 2
#define V1 1
#define COL_RESET "\e[0;m"
#define GREEN "\e[38;2;100;200;60m"
#define PINK "\e[38;2;250;20;160m"
#define YELLOW "\e[38;2;255;250;0m"
#define LEN 512

void callback(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
void usage (int);
int test_snprintf(int, int);

#endif
