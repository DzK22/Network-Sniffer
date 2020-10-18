#include "../headers/application.h"

bool get_app (const unsigned char *packet, int port, int type, int level, int len) {
    (void)level;
    (void)type;
    (void)packet;
    switch (port) {
        case DHCP:
            break;

        case DNS:
            break;

        case TELNET:
            break;

        case HTTPS:
            fprintf(stdout, "\tHTTP\n");
            threat_http (packet, type, len);
            break;

        case SMTP:
            break;

        case SMTPS:
            break;

        default:
            return false;
    }
    return true;
}
void threat_app (const unsigned char *packet, int sport, int dport, unsigned *to_add, int level, int len) {
    (void)to_add;
    (void)level;
    if (!get_app(packet, sport, REQUEST, level, len) && !get_app(packet, dport, RESPONSE, level, len))
        fprintf(stderr, "THERE IS NO APP MATCHING\n");
}

void threat_http (const unsigned char *packet, int type, int len) {
    (void)packet;
    if (type == REQUEST)
        fprintf(stdout, "\t\tREQUEST\n");
    else
        fprintf(stdout, "\t\tRESPONSE\n");
    if (len <= 0)
        return;
    int i;
    for (i = 0; i < len; i++) {
        print(packet[i]);
    }
}
