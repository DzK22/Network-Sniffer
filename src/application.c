#include "../headers/application.h"

bool get_app (const unsigned char *packet, int port, int type, int level, int len) {
    (void)level;
    (void)packet;
    switch (port) {
        case DHCP:
            fprintf(stdout, "\tDHCP [%d] =>", port);
            break;

        case DNS:
            fprintf(stdout, "\tDNS [%d]\n", port);
            treat_dns(packet, level);
            break;

        case TELNET:
            fprintf(stdout, "\tTELNET [%d] =>", port);
            break;

        case HTTPS:
            fprintf(stdout, "\tHTTPS [%d] =>", port);
            treat_https(packet, type, len, level);
            break;

        case HTTP:
            fprintf(stdout, "\tHTTP [%d] =>", port);
            treat_https(packet, type, len, level);
            break;

        case SMTP:
            fprintf(stdout, "\tSMTP [%d] =>", port);
            break;

        case SMTPS:
            fprintf(stdout, "\tSMTPS [%d] =>", port);
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
