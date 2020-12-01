#include "../headers/analyseur.h"
unsigned long packetID = 0;

//Fonction qui check si le protocole ethernet est supporté par l'analyseur (Utile pour balayer certains affichages)
static inline bool supported_ep (int e_protocol) {
    return (e_protocol == ETHERTYPE_IP) || (e_protocol == ETHERTYPE_IPV6) || (e_protocol == ETHERTYPE_ARP);
}

static inline bool supported_tr (int t_protocol) {
    return (t_protocol == UDP) || (t_protocol == TCP);
}

static inline bool supported_app (int app) {
    return (app == HTTP) || (app == HTTPS) || (app == FTPC) || (app == FTPD) || \
    (app == SMTP) || (app == SMTPS) || (app == DNS) || (app == DHCP) || (app == MDNS) || \
    (app == TELNET) || (app == POP) || (app == IMAP);
}

int c_print(char c) {
    if (c == '\r')
        fprintf(stdout, "\\r");

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
    packetID++;
    struct tm res;
    if (localtime_r(&header->ts.tv_sec, &res) == NULL) {
        fprintf(stderr, "localtime error\n");
        exit(EXIT_FAILURE);
    }
    char str_time[LEN];
    int e_protocol, t_protocol, sport, dport, len = header->len, level = args[0], previewHeaderLength, to_add, dataLen;
    fprintf(stdout, "<----------------------------------------------------------------------------------------------------->\n");
    switch (level) {
        case V1:
            fprintf(stdout, "[%ld]: ", packetID);
            break;

        case V2:
            fprintf(stdout, "** Packet ID = %ld **\n", packetID);
            break;

        case V3:
            if (strftime(str_time, LEN, "%a %Y-%m-%d %H:%M:%S %Z", &res)  == 0) {
                fprintf(stderr, "strftime error\n");
                exit(EXIT_FAILURE);
            }
            fprintf(stdout, "Packet ID = %ld arrived at %s with Length : %d bytes\n", packetID, str_time, header->len);
            break;
    }
    //Couche liaison
    if (level == V3)
        fprintf(stdout, "[+2] Couche Liaison:\n");

    treat_ethernet(packet, &e_protocol, level);
    previewHeaderLength = sizeof(struct ether_header);

    //Couche réseau
    if (supported_ep(e_protocol) && level == V3)
        fprintf(stdout, "\n[+3] Couche Réseau:\n");
    else if (level == V1 && !supported_ep(e_protocol))
        fprintf(stdout, "\n");

    treat_network(packet + previewHeaderLength, e_protocol, &t_protocol, &to_add, level, &dataLen);
    previewHeaderLength += to_add;

    //Couche transport
    if (supported_ep(e_protocol) && supported_tr(t_protocol) && level == V3)
        fprintf(stdout, "\n[+4] Couche Transport:\n");

    treat_transport(packet + previewHeaderLength, t_protocol, &sport, &dport, &to_add, level);
    previewHeaderLength += to_add;

    //Couche applicative
    if (supported_ep(e_protocol) && supported_tr(t_protocol) && (supported_app(sport) || supported_app(dport)) && level == V3)
        fprintf(stdout, "\n[+7] Couche Application:\n");

    if (t_protocol == UDP)
        treat_app(packet + previewHeaderLength, sport, dport, level, len - dataLen);
    else if (t_protocol == TCP)
        treat_app(packet + previewHeaderLength, sport, dport, level, len - previewHeaderLength);

    if (fflush(stdout) == EOF) {
        fprintf(stderr, "fflush error\n");
        exit(EXIT_FAILURE);
    }

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
