#include "../headers/analyseur.h"

void analyse (const unsigned char * packet, int level) {
    int nextInPacket;
    unsigned nextLength;
    nextInPacket = threat_ethernet(packet, level, &nextLength);
    while (nextInPacket) {
        switch(nextInPacket) {
            case ETHERTYPE_IP:
            //appelez fonction IP
            fprintf(stdout, YELLOW"\tType = IPv4\n"COL_RESET);
            nextInPacket = threat_ipv4(packet + nextLength, level, &nextLength);
            break;

            case ETHERTYPE_IPV6:
            fprintf(stdout, YELLOW"\tType = IPv6\n"COL_RESET);
            nextInPacket = threat_ipv6(packet + nextLength, level, &nextLength);
            break;

            case ETHERTYPE_ARP:
                fprintf(stdout, YELLOW"\tType = ARP\n"COL_RESET);
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
    struct tm res;
    if (localtime_r(&header->ts.tv_sec, &res) == NULL) {
        fprintf(stderr, "localtime error\n");
        exit(EXIT_FAILURE);
    }
    char str_time[LEN];
    if (strftime(str_time, LEN, "%X", &res)  == 0) {
        fprintf(stderr, "strftime error\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "packet ID = %ld arrived at %s\n", packetID, str_time);
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
