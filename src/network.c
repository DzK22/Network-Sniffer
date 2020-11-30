#include "../headers/network.h"

//Fonction qui gère la couche réseau dans sa globalité
void treat_network(const unsigned char *packet, int e_protocol, int *t_protocol, int *to_add, int level, int *dataLen) {
    int port = -1;
    switch(e_protocol) {
        case ETHERTYPE_IP:
            //appelez fonction IP
            if (level != V1)
                fprintf(stdout, YELLOW"\tType = IPv4 (0x%04x)\n"COL_RESET, e_protocol);
            port = treat_ipv4(packet, level, to_add, dataLen);
            break;

        case ETHERTYPE_IPV6:
            if (level != V1)
                fprintf(stdout, YELLOW"\tType = IPv6 (0x%04x)\n"COL_RESET, e_protocol);
            port = treat_ipv6(packet, level);
            *to_add = sizeof(struct ip6_hdr);
            break;

        case ETHERTYPE_ARP:
            if (level != V1)
                fprintf(stdout, YELLOW"\tType = ARP (0x%04x)\n"COL_RESET, e_protocol);
            treat_arp(packet, level);
            *to_add = sizeof(struct arphdr);
            break;

        default :
            if (level != V1)
                fprintf(stdout, "\tUnknown Type (0x%04x)\n", e_protocol);
            break;
    }
    fprintf(stdout, COL_RESET);
    *t_protocol = port;
}
