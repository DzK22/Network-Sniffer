#include "../headers/application.h"

//Fonction qui invoque la fonction nécessaire selon le protocole applicatif
bool get_app (const unsigned char *packet, int port, int type, int level, int len) {
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
            if (level == V1)
                break;
            treat_dns(packet, level);
            break;

        case DHCP:
            fprintf(stdout, "\tBOOTP [%d]\n", port);
            if (level == V1)
                break;
            treat_bootp(packet, level);
            break;

        case MDNS:
            fprintf(stdout, "\tMDNS [%d]\n", port);
            break;

        default:
            return false;
    }
    return true;
}

//Fonction qui vérifie si un des ports sources et destinations match avec un port applicatif
void treat_app (const unsigned char *packet, int sport, int dport, int level, int len) {
    if (!get_app(packet, sport, REQUEST, level, len) && !get_app(packet, dport, RESPONSE, level, len))
        fprintf(stderr, "\n\tTHERE IS NO APP MATCHING\n");
}
