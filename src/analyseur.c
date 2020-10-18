#include "../headers/analyseur.h"
void print(const char c) {
    if (c == '\n')
        fprintf(stdout, "\\n");
    else if (isprint(c))
        fprintf(stdout, "%c", c);
    else
        fprintf(stdout, ".");
}

void callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
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
    int e_protocol, t_protocol, sport, dport, len = header->len, level = args[0];
    unsigned previewHeaderLength, to_add;
    threat_ethernet(packet, &e_protocol, level);
    previewHeaderLength = sizeof(struct ether_header);

    //Couche réseau
    threat_network(packet + previewHeaderLength, e_protocol, &t_protocol, &to_add, level);
    previewHeaderLength += to_add;

    //Couche transport
    threat_transport(packet + previewHeaderLength, t_protocol, &sport, &dport, &to_add, level);
    previewHeaderLength += to_add;

    //Couche applicative
    threat_app(packet + previewHeaderLength, sport, dport, &to_add, level, len);
    fprintf(stdout, "\n");
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
