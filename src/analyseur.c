#include "../headers/analyseur.h"

void callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
    (void)header;
    static unsigned long packetID = 0;
    packetID++;
    fprintf(stdout, "packet number = %ld\n", packetID);
    int protocol, level = args[0];
    int ethernet = threat_ethernet(packet, &protocol, level);
    int ipv4 = threat_ipv4(packet, &protocol, level);
    fprintf(stdout,"ETHERNET READ = %d\n", ethernet);
    fprintf(stdout,"IP READ = %d\n", ipv4);
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
