#include "../headers/application.h"

//Fonction qui invoque la fonction nécessaire selon le protocole applicatif
bool get_app (const unsigned char *packet, int port, bool resp, int level, int len) {
    switch (port) {
        case HTTPS:
        case HTTP:
        case FTPC:
        case FTPD:
        case SMTP:
        case SMTPS:
        case POP:
        case IMAP:
            treat_transfer(packet, resp, len, level, port);
            break;

        case MDNS:
        case DNS:
            treat_dns(packet, level, port);
            break;

        case DHCP:
            treat_bootp(packet, level);
            break;

        case TELNET:
            if (level == V3)
                fprintf(stdout, CYAN"          └─ TELNET [%d]\n"COL_RESET, port);
            treat_telnet(packet, len, level);
            break;

        default:
            return false;
    }
    return true;
}

//Fonction qui vérifie si un des ports source ou destination match avec un port applicatif (traité)
void treat_app (const unsigned char *packet, int sport, int dport, int level, int len) {
    if (!get_app(packet, sport, true, level, len) && !get_app(packet, dport, false, level, len)) {
        switch (level) {
            case V1:
                fprintf(stdout, "|| No App");
                break;

            case V2:
                fprintf(stdout, CYAN"$> No App matching\n"COL_RESET);
                break;

            case V3:
                fprintf(stderr, CYAN"           └─ There is no app matching with ports number %d && %d\n"COL_RESET, sport, dport);
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
    if (len > 0)
        fprintf(stdout, CYAN"             └─ "COL_RESET);
    for (i = 0; i < len; i++) {
        if (c_print(packet[i]) == '\n')
            fprintf(stdout, "\t\t");
    }
    fprintf(stdout, "\n");
}
