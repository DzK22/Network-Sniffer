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
#include <arpa/nameser_compat.h>
#include <arpa/nameser.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include "datalink.h"
#include "network.h"
#include "transport.h"
#include <time.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "application.h"
#include <ctype.h>
#include <signal.h>
#include <net/if_arp.h>

#define V3 3
#define V2 2
#define V1 1
#define COL_RESET "\e[0;m"
#define GREEN "\e[38;2;100;200;60m"
#define PINK "\e[38;2;250;20;160m"
#define YELLOW "\e[38;2;255;250;0m"
#define CYAN "\e[0;36m"
#define SUPPR "\e[D\e[D\e[K"
#define LEN 1024

void sigint_handler (int);
void callback(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
void usage (int);
int test_snprintf(int, int);

#endif
