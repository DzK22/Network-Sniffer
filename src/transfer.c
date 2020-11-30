#include "../headers/transfer.h"

//Fonction qui invoque la fonction correpondant au protocole (de "transfert") applicatif du port passé en paramètre
void treat_transfer (const unsigned char *packet, bool resp, int len, int level, int port) {
    switch (port) {
        case HTTP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| HTTP");
                    return;

                case V2:
                    fprintf(stdout, "$> HTTP:");
                    break;

                case V3:
                    fprintf(stdout, "\tHTTP [%d] =>", port);
                    break;
            }
            break;

        case HTTPS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| HTTPS");
                    return;

                case V2:
                    fprintf(stdout, "$> HTTPS:");
                    break;

                case V3:
                    fprintf(stdout, "\tHTTPS [%d] =>", port);
                    break;
            }
            break;

        case FTPD:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| FTP Data");
                    return;

                case V2:
                    fprintf(stdout, "$> FTP Data:");
                    break;

                case V3:
                    fprintf(stdout, "\tFTP Data [%d] =>", port);
                    break;
            }
            break;

        case FTPC:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| FTP Control");
                    return;

                case V2:
                    fprintf(stdout, "$> FTP Control:");
                    break;

                case V3:
                    fprintf(stdout, "\tFTP Control [%d] =>", port);
                    break;
            }
            break;

        case SMTP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| SMTP");
                    return;

                case V2:
                    fprintf(stdout, "$> SMTP:");
                    break;

                case V3:
                    fprintf(stdout, "\tSMTP [%d] =>", port);
                    break;
            }
            break;

        case SMTPS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| SMTPS");
                    return;

                case V2:
                    fprintf(stdout, "$> SMTPS:");
                    break;

                case V3:
                    fprintf(stdout, "\tSMTPS [%d] =>", port);
                    break;
            }
            break;

        case POP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| POP");
                    return;

                case V2:
                    fprintf(stdout, "$> POP:");
                    break;

                case V3:
                    fprintf(stdout, "\tPOP [%d] =>", port);
                    break;
            }
            break;

        case IMAP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| IMAP");
                    return;

                case V2:
                    fprintf(stdout, "$> IMAP:");
                    break;

                case V3:
                    fprintf(stdout, "\tIMAP [%d] =>", port);
                    break;
            }
            break;

        default:
            return;
    }

    if (!resp)
        fprintf(stdout, " REQUEST\n");
    else
        fprintf(stdout, " RESPONSE\n");

    if (len <= 0 || level != V3)
        return;

    print(packet, len);
}
