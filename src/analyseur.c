#include "../headers/analyseur.h"
void print(const unsigned char *packet, int len) {
    int i, cpt = 0;
    fprintf(stdout, "\t");
    for (i = 0; i < len; i++) {
        if (packet[i] == '\n') {
            fprintf(stdout, "\\n");
            cpt++;
        }
        else if (packet[i] == '\r') {
            fprintf(stdout, "\\r");
            cpt++;
        }
        else if (packet[i] == '\t') {
            fprintf(stdout, "\\t");
            cpt++;
        }
        else if (isprint(packet[i]) || isspace(packet[i])) {
            fprintf(stdout, "%c", packet[i]);
            cpt++;
        }
        else {
            fprintf(stdout, ".");
            cpt++;
        }
        if (cpt == 20) {
            fprintf(stdout, "\n\t");
            cpt = 0;
        }
    }
    fprintf(stdout, "\n");
}

void data_print(const unsigned char *packet) {
    unsigned i;
    fprintf(stdout, "\tDatas: ");
    for (i = 0; i < 50; i++) {
        if (packet[i])
            fprintf(stdout, "%02x", packet[i]);
        else
            break;
    }
    fprintf(stdout, " ...\n");
}


void print_packet (const unsigned char *packet, int len) {
    int i;
    for (i = 0; i < len; i++)
        fprintf(stdout, "%02x ", packet[i]);
    fprintf(stdout, "\n\n");
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
    if (level == 3)
        //Afficher les 10 premiers octets
        print_packet(packet, 10);
    treat_ethernet(packet, &e_protocol, level);
    previewHeaderLength = sizeof(struct ether_header);

    //Couche réseau
    treat_network(packet + previewHeaderLength, e_protocol, &t_protocol, &to_add, level);
    previewHeaderLength += to_add;

    //Couche transport
    treat_transport(packet + previewHeaderLength, t_protocol, &sport, &dport, &to_add, level);
    previewHeaderLength += to_add;

    //Couche applicative
    treat_app(packet + previewHeaderLength, sport, dport, &to_add, level, len);
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
