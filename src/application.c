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
            if (level == V3)
                fprintf(stdout, "\tDNS [%d]\n", port);
            treat_dns(packet, level);
            break;

        case DHCP:
            if (level == V3)
                fprintf(stdout, "\tBOOTP [%d]\n", port);
            treat_bootp(packet, level);
            break;

        case MDNS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| MDNS\n");
                    break;

                case V2:
                    fprintf(stdout, "MDNS: port: %d\n", port);
                    break;

                case V3:
                    fprintf(stdout, "\tMDNS [%d]\n", port);
                    break;
            }
            break;

        default:
            return false;
    }
    return true;
}

//Fonction qui vérifie si un des ports sources et destinations match avec un port applicatif
void treat_app (const unsigned char *packet, int sport, int dport, int level, int len) {
    if (!get_app(packet, sport, REQUEST, level, len) && !get_app(packet, dport, RESPONSE, level, len)) {
        switch (level) {
            case V1:
                fprintf(stdout, "|| No App\n");
                break;

            case V2:
                fprintf(stdout, "No App matching\n");
                break;

            case V3:
                fprintf(stderr, "\n\tThere is no app matching with ports number %d && %d\n", sport, dport);
                break;
        }
    }
}
