#include "../headers/application.h"

/*
 * Function: get_app
 * ----------------------------
 *   Fonction qui invoque la fonction nécessaire selon le protocole applicatif
 *
 *   packet: la partie du paquet correspondante à l'en-tête du protocole applicatif à traîter
 *   port: port applicatif à traîter
 *   resp: booléen pour savoir si c'est une requête du client ou une réponse du serveur (utile pour les protocoles de "transfert")
 *   level: niveau de verbosité
 *   len: taille des données (pour l'affichage des données)
 *
 *   returns: Vrai si le port correspond à une application supportée par l'analyseur, Faux sinon.
 */
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

/*
 * Function: treat_app
 * ----------------------------
 *   Fonction qui traîte la couche applicative en vérifiant si un des ports source ou destination match avec un port applicatif (supporté)
 *
 *   packet: la partie du paquet correspondante à l'en-tête du protocole applicatif à traîter
 *   sport: port source
 *   sport: port destination
 *   level: niveau de verbosité
 *   len: taille des données (pour l'affichage des données)
 *
 *   returns: void
 */
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

/*
 * Function: c_print
 * ----------------------------
 *   Fonction qui écrit un caractère
 *
 *   c: caractère à traîter
 *
 *   returns: le caractère qui a été écrit
 */
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

/*
 * Function: print
 * ----------------------------
 *   Fonction qui écrit des données (pour les protocoles applicatifs)
 *
 *   packet: la partie du paquet correspondante à l'en-tête du protocole applicatif traîté
 *   len: taille des données
 *
 *   returns: void
 */
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
