#include "../headers/transfer.h"

//Fonction qui invoque la fonction correpondant au protocole (de "transfert") applicatif du port passé en paramètre 
void treat_transfer (const unsigned char *packet, int type, int len, int level, int port) {
    switch (port) {
        case HTTP:
            fprintf(stdout, "\tHTTP [%d] =>", port);
            break;
        case HTTPS:
            fprintf(stdout, "\tHTTPS [%d] =>", port);
            break;
        case FTPD:
            fprintf(stdout, "\tFTP Data [%d] =>", port);
            break;
        case FTPC:
            fprintf(stdout, "\tFTP Control [%d] =>", port);
            break;
        case SMTP:
            fprintf(stdout, "\tSMTP [%d] =>", port);
            break;
        case SMTPS:
            fprintf(stdout, "\tSMTPS [%d] =>", port);
            break;
        default:
            return;
    }
    if (type == REQUEST)
        fprintf(stdout, " REQUEST\n");
    else
        fprintf(stdout, " RESPONSE\n");
    if (len <= 0 || level != V3)
        return;
    print(packet, len);
}
