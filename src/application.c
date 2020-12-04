#include "../headers/application.h"

//Fonction qui invoque la fonction nécessaire selon le protocole applicatif
bool get_app (const unsigned char *packet, int port, bool resp, int level, int len) {
    switch (port) {
        case HTTPS:
            treat_transfer(packet, resp, len, level, HTTPS);
            break;

        case HTTP:
            treat_transfer(packet, resp, len, level, HTTP);
            break;

        case FTPC:
            treat_transfer(packet, resp, len, level, FTPC);
            break;

        case FTPD:
            treat_transfer(packet, resp, len, level, FTPD);
            break;

        case SMTP:
            treat_transfer(packet, resp, len, level, SMTP);
            break;

        case SMTPS:
            treat_transfer(packet, resp, len, level, SMTPS);
            break;

        case POP:
            treat_transfer(packet, resp, len, level, POP);
            break;

        case IMAP:
            treat_transfer(packet, resp, len, level, IMAP);
            break;

        case DNS:
            if (level == V3)
                fprintf(stdout, "\tDNS [%d]\n", port);
            treat_dns(packet, level);
            break;

        case DHCP:
            treat_bootp(packet, level);
            break;

        case TELNET:
            if (level == V3)
                fprintf(stdout, "\tTELNET [%d]\n", port);
            treat_telnet(packet, len, level);
            break;

        case MDNS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| MDNS");
                    break;

                case V2:
                    fprintf(stdout, "$> MDNS: port: %d\n", port);
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
    if (!get_app(packet, sport, true, level, len) && !get_app(packet, dport, false, level, len)) {
        switch (level) {
            case V1:
                fprintf(stdout, "|| No App");
                break;

            case V2:
                fprintf(stdout, "$> No App matching\n");
                break;

            case V3:
                fprintf(stderr, "           └─ There is no app matching with ports number %d && %d\n", sport, dport);
                break;
        }
    }
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
