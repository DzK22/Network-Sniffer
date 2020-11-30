#include "../headers/transfer.h"

//Fonction qui invoque la fonction correpondant au protocole (de "transfert") applicatif du port passé en paramètre
void treat_transfer (const unsigned char *packet, int type, int len, int level, int port) {
    switch (port) {
        case HTTP:
            if (level == V1) {
                fprintf(stdout, "|| HTTP\n");
                return;
            }
            fprintf(stdout, "\tHTTP [%d] =>", port);
            break;
        case HTTPS:
            if (level == V1) {
                fprintf(stdout, "|| HTTPS\n");
                return;
            }
            fprintf(stdout, "\tHTTPS [%d] =>", port);
            break;
        case FTPD:
            if (level == V1) {
                fprintf(stdout, "|| FTP Data\n");
                return;
            }
            fprintf(stdout, "\tFTP Data [%d] =>", port);
            break;
        case FTPC:
            if (level == V1) {
                fprintf(stdout, "|| FTP Control\n");
                return;
            }
            fprintf(stdout, "\tFTP Control [%d] =>", port);
            break;
        case SMTP:
            if (level == V1) {
                fprintf(stdout, "|| SMTP\n");
                return;
            }
            fprintf(stdout, "\tSMTP [%d] =>", port);
            break;
        case SMTPS:
            if (level == V1) {
                fprintf(stdout, "|| SMTPS\n");
                return;
            }
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
