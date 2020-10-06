#include "../headers/analyseur.h"

void analyse (const unsigned char * packet, int level) {
    int nextInPacket;
    unsigned nextLength;
    nextInPacket = threat_ethernet(packet, level, &nextLength);
    while (nextInPacket) {
        switch(nextInPacket) {
            case ETHERTYPE_IP:
            //appelez fonction IP
            fprintf(stdout, YELLOW"Type = IPv4\n"COL_RESET);
            nextInPacket = threat_ipv4(packet + nextLength, level, &nextLength);
            break;

            case ETHERTYPE_IPV6:
            fprintf(stdout, YELLOW"Type = IPv6\n"COL_RESET);
            //appeler fonction IPV6
            nextInPacket = 0;
            break;

            case ETHERTYPE_ARP:
                fprintf(stdout, YELLOW"Type = ARP\n"COL_RESET);
                nextInPacket = 0;
                break;

            default :
            nextInPacket = 0;
            break;
            //sortie de boucle
        }
    }
    fprintf(stdout, COL_RESET"\n");
}

void callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
    (void)header;
    static unsigned long packetID = 0;
    packetID++;
    fprintf(stdout, "packet number = %ld\n", packetID);
    analyse(packet, args[0]);
}

void usage (int argc) {
    if ((argc - 1) % 2 != 0) {
        fprintf(stderr, "Nombre d'arguments invalide %d\n", argc - 1);
        exit(EXIT_FAILURE);
    }
}

int test_snprintf(int res, int bytes) {
    if (res < 0 || res >= bytes) {
        fprintf(stderr, "snprintf error\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
