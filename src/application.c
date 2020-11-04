#include "../headers/application.h"

bool get_app (const unsigned char *packet, int port, int type, int level, int len) {
    (void)level;
    (void)packet;
    switch (port) {
        case HTTPS:
            treat_transfer(packet, type, len, level, HTTPS);
            break;

        case HTTP:
            treat_transfer(packet, type, len, level, HTTP);
            break;

        case FTPC:
            treat_transfer(packet, type, len, level, FTPC);
            break;

        case FTPD:
            treat_transfer(packet, type, len, level, FTPD);
            break;

        case SMTP:
            treat_transfer(packet, type, len, level, SMTP);
            break;

        case SMTPS:
            treat_transfer(packet, type, len, level, SMTPS);
            break;

        case DNS:
            fprintf(stdout, "\tDNS [%d]\n", port);
            treat_dns(packet, level);
            break;

        case DHCP:
            fprintf(stdout, "\tDHCP [%d] =>", port);
            break;

        default:
            return false;
    }
    return true;
}
void treat_app (const unsigned char *packet, int sport, int dport, int *to_add, int level, int len) {
    (void)to_add;
    (void)level;
    if (!get_app(packet, sport, REQUEST, level, len) && !get_app(packet, dport, RESPONSE, level, len))
        fprintf(stderr, "\n\tTHERE IS NO APP MATCHING\n");
}
