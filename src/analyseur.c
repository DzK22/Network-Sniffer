#include "../headers/analyseur.h"

int c_print(char c) {
    if (c == '\r') {
        fprintf(stdout, "\\r");
    }
    else if (c == '\n') {
        fprintf(stdout, "\\n");
        fprintf(stdout, "\n");
    }
    else if (isprint(c) || isspace(c))
        fprintf(stdout, "%c", c);
    else {
        fprintf(stdout, ".");
        return -1;
    }
    return c;
}
void print(const unsigned char *packet, int len) {
    int i;
    fprintf(stdout, "\t");
    for (i = 0; i < len; i++) {
        if (c_print(packet[i]) == '\n')
            fprintf(stdout, "\t");
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
    if (strftime(str_time, LEN, "%a %Y-%m-%d %H:%M:%S %Z", &res)  == 0) {
        fprintf(stderr, "strftime error\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "packet ID = %ld arrived at %s\n", packetID, str_time);
    int e_protocol, t_protocol, sport, dport, len = header->len, level = args[0], previewHeaderLength, to_add, dataLen;

    //Couche liaison
    fprintf(stdout, "[+2] Couche Liaison:\n");
    treat_ethernet(packet, &e_protocol, level);
    previewHeaderLength = sizeof(struct ether_header);

    //Couche réseau
    fprintf(stdout, "\n[+3] Couche Réseau:\n");
    treat_network(packet + previewHeaderLength, e_protocol, &t_protocol, &to_add, level, &dataLen);
    previewHeaderLength += to_add;
    //Couche transport
    fprintf(stdout, "\n[+4] Couche Transport:\n");
    treat_transport(packet + previewHeaderLength, t_protocol, &sport, &dport, &to_add, level);
    previewHeaderLength += to_add;

    //Couche applicative
    fprintf(stdout, "\n[+7] Couche Application:\n");
    if (t_protocol == UDP)
        treat_app(packet + previewHeaderLength, sport, dport, &to_add, level, len - dataLen);
    else if (t_protocol == TCP)
        treat_app(packet + previewHeaderLength, sport, dport, &to_add, level, len - previewHeaderLength);
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
