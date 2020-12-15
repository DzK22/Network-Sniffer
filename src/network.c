#include "../headers/network.h"

/*
 * Function: treat_network
 * ----------------------------
 *   Traite la couche réseau
 *
 *   packet: la partie du paquet correspondante à l'en-tête du protocole réseau à traîter
 *   e_protocol: type du protocole
 *   t_protocol: pointeur où l'on va stocker le port du protocole de transport utilisé
 *   to_add: taille de l'en-tête traîtée (utile pour pouvoir la rajouter au paquet traîté pour trouver le prochain protocole à traîter)
 *   level: niveau de verbosité
 *   dataLen: taille totale de l'en-tête ip (variable pour ipv4)
 *
 *   returns: void
 */
void treat_network(const unsigned char *packet, int e_protocol, int *t_protocol, int *to_add, int level, int *dataLen) {
    int port = -1;
    switch(e_protocol) {
        case ETHERTYPE_IP:
            //appelez fonction IP
            port = treat_ipv4(packet, level, to_add, dataLen);
            break;

        case ETHERTYPE_IPV6:
            port = treat_ipv6(packet, level);
            *to_add = sizeof(struct ip6_hdr);
            break;

        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:
            treat_arp(packet, level, e_protocol);
            *to_add = sizeof(struct arphdr);
            break;

        default :
            if (level == V3)
                fprintf(stdout, YELLOW"   └─ Unknown Type (0x%04x)\n"COL_RESET, e_protocol);
            break;
    }
    fprintf(stdout, COL_RESET);
    *t_protocol = port;
}
